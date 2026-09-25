package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ==================== UYGULAMA YAŞAM DÖNGÜSÜ ====================

// Sürüm — derleme sırasında -ldflags "-X main.version=..." ile değiştirilir
var version = "5.0.0-dev"

// Global çekirdek nesneler
var (
	resolver *Resolver
	metrics  *ResolverMetrics
	blocker  *Blocklist
	cfg      Config
	app      *App
)

// App — çalışan bir Ceky Resolver örneği (uygulama veya servis modu)
type App struct {
	mode     string // "app" (pencereli) | "service" (arka plan)
	token    string // Paneldeki değişiklik isteklerini doğrulayan gizli anahtar
	sysAddrs []string
	dnsAddrs []string
	closers  []io.Closer
	web      *http.Server
	stop     chan struct{}
	stopOnce sync.Once

	opMu sync.Mutex // Sistem DNS işlemleri aynı anda yalnızca bir kez

	mu          sync.Mutex
	probe       NetProbe
	failStreak  int
	okStreak    int
	sysActive   bool   // Sistem DNS'i şu an Ceky'ye yönlü
	suspended   bool   // Güvenli mod: kök sunuculara ulaşılamadığı için geçici olarak eski DNS'e dönüldü
	reason      string // Kullanıcıya gösterilecek durum açıklaması
	currentDNS  []string
	installed   bool
	handoff     bool // Kalıcı kuruluma devrediliyor — DNS ayarı geri alınmasın
	lastLogTCP  bool
	blocklistOn bool // Liste güncelleme döngüsü başlatıldı mı
}

func newApp(mode string) *App {
	buf := make([]byte, 16)
	rand.Read(buf)
	return &App{mode: mode, token: hex.EncodeToString(buf), stop: make(chan struct{})}
}

func panelURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", cfg.DashboardPort)
}

// instanceRunning — bu bilgisayarda zaten çalışan bir Ceky Resolver var mı?
func instanceRunning(port int) bool {
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/app/ping", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return resp.StatusCode == 200 && strings.Contains(string(body), "ceky-resolver")
}

// systemAddrsFor — sistem DNS ayarına yazılacak adresler
func systemAddrsFor(bound []string) []string {
	var out []string
	for _, a := range bound {
		ip := net.ParseIP(a)
		switch {
		case ip == nil:
		case ip.IsUnspecified(): // 0.0.0.0 / :: → loopback üzerinden eriş
			if ip.To4() != nil {
				out = append(out, "127.0.0.1")
			} else {
				out = append(out, "127.0.0.1", "::1")
			}
		default:
			out = append(out, a)
		}
	}
	return out
}

// runApp — DNS sunucusunu, paneli ve koruma denetleyicisini başlat
func runApp(mode string, noBrowser bool, relaunchArgs []string) {
	if mode == "service" {
		os.MkdirAll(dataDir, 0755)
		redirectOutput(dataPath("ceky-resolver.log"))
	}
	cfg = peekConfig()

	// Aynı anda iki örnek çalışmasın (ör. servis kuruluyken çift tıklama)
	if cfg.DashboardOn && instanceRunning(cfg.DashboardPort) {
		if mode == "service" {
			fmt.Println("Başka bir Ceky Resolver örneği çalışıyor — çıkılıyor")
			os.Exit(1)
		}
		fmt.Println("✓ Ceky Resolver zaten çalışıyor — kontrol paneli açılıyor:", panelURL())
		openBrowser(panelURL())
		return
	}

	// Sistem DNS'ini değiştirebilmek (ve 53. portu açabilmek) için yönetici izni
	if mode == "app" && !isAdmin() {
		if err := relaunchElevated(relaunchArgs); err == nil {
			return // Yönetici olarak yeni pencerede açıldı
		}
		fmt.Println("⚠ Yönetici izni yok: DNS sunucusu çalışır ama sistem DNS ayarı değiştirilemez.")
	}

	os.MkdirAll(dataDir, 0755)
	cfg = loadConfig()

	app = newApp(mode)
	metrics = newResolverMetrics()
	cache := newDNSCache(cfg.CacheMaxEntries)
	cache.disabled = !cfg.CacheEnabled
	resolver = newResolver(cfg.RootServers, cache, metrics)
	resolver.verbose = cfg.Verbose
	resolver.forceTCP.Store(cfg.Transport == "tcp")
	queryLog = newQueryLog(cfg.QueryLogSize)
	consoleQueryLog = mode == "app" && !cfg.Verbose

	blocker = newBlocklist()
	blocker.sources = cfg.BlocklistURLs
	blocker.customFile = dataPath(cfg.BlocklistFile)
	blocker.allowFile = dataPath(cfg.AllowlistFile)
	blocker.cacheDir = dataPath("lists")
	blocker.refresh = time.Duration(max(cfg.BlocklistRefreshHours, 1)) * time.Hour
	blocker.client = newSelfResolvingClient()

	printBanner(mode)

	// DNS dinleyicileri (UDP + TCP, IPv4 + IPv6 loopback)
	bound, closers, err := startDNSListeners(dnsListenAddrs(cfg.BindAddr), cfg.DNSPort)
	if err != nil {
		printListenError(err)
		pauseIfOwnConsole()
		os.Exit(1)
	}
	app.closers = closers
	app.dnsAddrs = bound
	app.sysAddrs = systemAddrsFor(bound)

	// Şifreli DNS (isteğe bağlı)
	if cfg.DoTEnabled || cfg.DoHEnabled {
		certFile, keyFile := ensureTLSCerts(cfg)
		if cfg.DoTEnabled && certFile != "" {
			if c := startDoTServer(certFile, keyFile); c != nil {
				app.closers = append(app.closers, c)
			}
		}
		if cfg.DoHEnabled {
			if c := startDoHServer(dataPath(cfg.CertFile), dataPath(cfg.KeyFile)); c != nil {
				app.closers = append(app.closers, c)
			}
		}
	}

	// Kontrol paneli
	if cfg.DashboardOn {
		app.web = startDashboard(cfg.DashboardPort)
	}

	// Reklam engelleme
	blocker.enabled.Store(cfg.BlocklistEnabled)
	if cfg.BlocklistEnabled {
		app.startBlocklist()
	}

	go app.backgroundLoops()
	go app.controlLoop()

	fmt.Println("║")
	fmt.Println("║ 📡 Dinleyiciler:")
	for _, a := range bound {
		fmt.Printf("║   DNS — %s (UDP+TCP)\n", net.JoinHostPort(a, fmt.Sprint(cfg.DNSPort)))
	}
	if cfg.DashboardOn {
		fmt.Printf("║   Panel — %s\n", panelURL())
	}
	if mode == "app" {
		fmt.Println("║")
		fmt.Println("║ ✓ Hazır! Kontrol panelinden korumayı açıp kapatabilirsiniz.")
		fmt.Println("║ ⚠ Bu pencereyi kapatırsanız koruma kapanır ve eski DNS ayarlarınız geri yüklenir.")
		fmt.Println("║   Bilgisayar açıldığında otomatik çalışması için panelde \"Kalıcı Kur\" deyin.")
	}
	fmt.Println("╚═══════════════════════════════════════════")
	fmt.Println()

	if mode == "app" && !noBrowser && cfg.DashboardOn {
		openBrowser(panelURL())
	}

	// Kapanış sinyali bekle (Ctrl+C, pencere kapatma, systemd/launchd durdurma)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-app.stop:
	}
	app.shutdown()
}

func printBanner(mode string) {
	fmt.Println("╔════════════════════════════════════════════")
	fmt.Printf("║ Ceky Resolver v%s — Başlatıldı\n", version)
	fmt.Println("║ Bağımsız Rekürsif DNS Çözümleyici")
	fmt.Println("║ Google / Cloudflare / İSS DNS'i gerekmez")
	fmt.Println("║ + Reklam Engelleme · Şifreli DNS · Canlı Panel")
	fmt.Println("╠════════════════════════════════════════════")
	fmt.Printf("║ ⚙ Veri klasörü: %s (%s modu)\n", dataDir, map[string]string{"app": "uygulama", "service": "servis"}[mode])
}

func printListenError(err error) {
	fmt.Printf("\n╔══ HATA ══════════════════════════════════\n")
	fmt.Printf("║ DNS portu (%d) açılamadı: %v\n", cfg.DNSPort, err)
	fmt.Println("║")
	if cfg.DNSPort < 1024 && !isAdmin() {
		fmt.Println("║ Port 53 için YÖNETİCİ yetkisi gerekir.")
		if runtime.GOOS == "windows" {
			fmt.Println("║ Çözüm: ceky-resolver.exe'ye sağ tık → 'Yönetici olarak çalıştır'")
		} else {
			fmt.Println("║ Çözüm: sudo ceky-resolver")
		}
	} else {
		fmt.Println("║ Başka bir DNS programı bu portu kullanıyor olabilir")
		fmt.Println("║ (ör. dnsmasq, Pi-hole, AdGuard, Acrylic DNS, Docker, İnternet Bağlantısı Paylaşımı).")
		fmt.Println("║ O programı kapatın veya config.json'da \"dnsPort\" değerini değiştirin.")
	}
	fmt.Println("╚═══════════════════════════════════════════")
}

// pauseIfOwnConsole — çift tıklamayla açılan pencere hemen kapanmasın
func pauseIfOwnConsole() {
	if ownsConsole() {
		fmt.Println("\nKapatmak için Enter'a basın...")
		fmt.Scanln()
	}
}

func (a *App) startBlocklist() {
	a.mu.Lock()
	started := a.blocklistOn
	a.blocklistOn = true
	a.mu.Unlock()
	if !started {
		blocker.StartAutoRefresh(a.stop)
	}
}

// requestStop — uygulamayı kapat (panelden "Çıkış" veya servise devir)
func (a *App) requestStop() {
	a.stopOnce.Do(func() { close(a.stop) })
}

// shutdown — dinleyicileri kapat, gerekiyorsa sistem DNS'ini geri yükle
func (a *App) shutdown() {
	a.requestStop()
	fmt.Println("\n║ Kapatılıyor...")

	a.opMu.Lock()
	defer a.opMu.Unlock()

	if a.web != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		a.web.Shutdown(ctx)
		cancel()
	}
	closeAll(a.closers)

	a.mu.Lock()
	handoff := a.handoff
	a.mu.Unlock()
	if handoff {
		// Kalıcı kuruluma devir: servis aynı yedeği devralır, DNS geri alınmaz
		time.Sleep(time.Second) // Portlar serbest kalsın
		if err := startService(); err != nil {
			fmt.Printf("║ ⚠ Servis başlatılamadı: %v\n", err)
			disableSystemDNS()
		} else {
			fmt.Println("║ ✓ Kalıcı kurulum tamamlandı — Ceky Resolver artık arka planda çalışıyor.")
		}
	} else if backupExists() {
		if err := disableSystemDNS(); err != nil {
			fmt.Printf("║ ⚠ DNS ayarları geri yüklenemedi: %v\n", err)
			fmt.Println("║   Elle geri almak için: ceky-resolver restore")
		} else {
			fmt.Println("║ ✓ DNS ayarlarınız eski haline getirildi")
		}
	}
	fmt.Println("║ Güle güle!")
}

// ==================== ARKA PLAN DÖNGÜLERİ ====================

func (a *App) backgroundLoops() {
	cleanup := time.NewTicker(time.Duration(max(cfg.CacheCleanupSec, 10)) * time.Second)
	defer cleanup.Stop()

	var stats <-chan time.Time
	if a.mode == "app" && cfg.StatsInterval > 0 {
		t := time.NewTicker(time.Duration(cfg.StatsInterval) * time.Second)
		defer t.Stop()
		stats = t.C
	}

	for {
		select {
		case <-a.stop:
			return
		case <-cleanup.C:
			resolver.cache.Cleanup()
		case <-stats:
			metrics.PrintStats()
			size, hits, misses := resolver.cache.Stats()
			fmt.Printf("║ Önbellek:   %d kayıt, %d isabet, %d ıskalama\n", size, hits, misses)
			fmt.Printf("║ Engellenen: %d reklam/takipçi (%d kural)\n", blocker.BlockedCount(), blocker.Size())
			fmt.Println("╚═══════════════════════════════════════════")
		}
	}
}

// ==================== KORUMA DENETLEYİCİSİ ====================
//
// Her 15 saniyede bir kök sunuculara erişim test edilir:
//   - Erişim varsa ve koruma isteniyorsa sistem DNS'i Ceky'ye yönlendirilir.
//   - İSS UDP/53'e müdahale ediyorsa TCP'ye geçilir.
//   - Hiçbir yoldan erişilemiyorsa (ör. otel Wi-Fi giriş sayfası) güvenli mod
//     devreye girer ve internet kesilmesin diye eski DNS geçici olarak geri yüklenir.

func (a *App) controlLoop() {
	if backupExists() {
		// Önceki çalışmadan (veya servisten devralınan) aktif koruma
		a.mu.Lock()
		a.sysActive = true
		a.mu.Unlock()
		if b, err := loadBackup(); err == nil {
			setAutoLocalForwarders(b.Original)
		}
	}
	a.checkNetwork()
	a.reconcile()
	a.refreshSystemInfo()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for n := 1; ; n++ {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			a.checkNetwork()
			a.reconcile()
			if n%4 == 0 {
				a.refreshSystemInfo()
			}
			a.mu.Lock()
			active := a.sysActive
			a.mu.Unlock()
			if active && (runtime.GOOS == "linux" || n%4 == 0) {
				a.opMu.Lock()
				if err := reconcileSystemDNS(); err != nil && cfg.Verbose {
					fmt.Printf("║ ⚠ DNS ayarı denetimi: %v\n", err)
				}
				a.opMu.Unlock()
			}
		}
	}
}

func (a *App) checkNetwork() {
	p := resolver.Probe()

	a.mu.Lock()
	defer a.mu.Unlock()
	a.probe = p
	if p.Healthy() {
		a.okStreak++
		a.failStreak = 0
	} else {
		a.failStreak++
		a.okStreak = 0
	}

	switch cfg.Transport {
	case "udp":
		resolver.forceTCP.Store(false)
	case "tcp":
		resolver.forceTCP.Store(true)
	default:
		useTCP := p.UDP != "ok" && p.TCP == "ok"
		if p.UDP == "ok" || useTCP {
			resolver.forceTCP.Store(useTCP)
		}
		if useTCP && !a.lastLogTCP {
			fmt.Println("║ ⚠ UDP/53 trafiğine müdahale tespit edildi (muhtemelen İSS) — TCP ile devam ediliyor")
		}
		a.lastLogTCP = useTCP
	}
}

func (a *App) refreshSystemInfo() {
	installed := serviceInstalled()
	current := currentSystemDNS()
	a.mu.Lock()
	a.installed = installed
	a.currentDNS = current
	a.mu.Unlock()
}

func probeText(status string) string {
	switch status {
	case "ok":
		return "erişilebilir"
	case "intercepted":
		return "ağ araya giriyor"
	case "blocked":
		return "yanıt yok"
	}
	return "bilinmiyor"
}

func (a *App) setReason(r string) {
	if r != "" && r != a.reason {
		fmt.Println("║ ⓘ " + r)
	}
	a.reason = r
}

// reconcile — istenen durum ile gerçek durumu eşitle. Yavaş sistem işlemleri
// (PowerShell, networksetup) sırasında durum kilidi tutulmaz; panel donmaz.
func (a *App) reconcile() {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	select {
	case <-a.stop:
		return
	default:
	}

	a.mu.Lock()
	want := cfg.AutoEnable
	probe := a.probe
	active, suspended := a.sysActive, a.suspended
	okStreak, failStreak := a.okStreak, a.failStreak
	a.mu.Unlock()
	healthy := probe.Healthy()

	// Ayar dışarıdan geri alındıysa (ör. "ceky-resolver restore") kullanıcı kapatmak istemiştir
	if active && !backupExists() {
		a.mu.Lock()
		a.sysActive = false
		if want {
			cfg.AutoEnable = false
			a.setReason("Sistem DNS ayarı dışarıdan geri alındı — koruma kapatıldı")
		}
		snapshot := cfg
		a.mu.Unlock()
		saveConfig(snapshot)
		return
	}

	if !isAdmin() {
		a.mu.Lock()
		if want {
			a.setReason("Yönetici izni olmadığı için sistem DNS ayarı değiştirilemiyor")
		}
		a.mu.Unlock()
		return
	}

	switch {
	case want && !active && healthy && (!suspended || okStreak >= 2):
		err := enableSystemDNS(a.sysAddrs)
		a.mu.Lock()
		if err != nil {
			a.setReason("Koruma açılamadı: " + err.Error())
		} else {
			a.sysActive, a.suspended = true, false
			a.setReason("")
			fmt.Println("║ 🛡 Koruma AKTİF — tüm DNS sorguları doğrudan kök sunuculardan çözülüyor")
		}
		a.mu.Unlock()
		if err == nil {
			if b, err := loadBackup(); err == nil {
				setAutoLocalForwarders(b.Original)
			}
			go a.refreshSystemInfo()
		}

	case want && active && !healthy && cfg.FailSafe && failStreak >= 3:
		err := disableSystemDNS()
		a.mu.Lock()
		if err != nil {
			a.setReason("Güvenli moda geçilemedi: " + err.Error())
		} else {
			a.sysActive, a.suspended = false, true
			a.setReason("Kök sunuculara ulaşılamıyor — internetiniz kesilmesin diye eski DNS'e geçici olarak dönüldü. Bağlantı düzelince koruma otomatik açılır.")
		}
		a.mu.Unlock()
		go a.refreshSystemInfo()

	case want && !active && !healthy:
		a.mu.Lock()
		if !suspended {
			a.setReason(fmt.Sprintf("Kök sunuculara ulaşılamıyor (UDP: %s, TCP: %s) — bağlantı bekleniyor",
				probeText(probe.UDP), probeText(probe.TCP)))
		}
		a.mu.Unlock()

	case !want && active:
		err := disableSystemDNS()
		a.mu.Lock()
		if err != nil {
			a.setReason("Koruma kapatılamadı: " + err.Error())
		} else {
			a.sysActive, a.suspended = false, false
			a.setReason("")
			fmt.Println("║ Koruma kapatıldı — eski DNS ayarları geri yüklendi")
		}
		a.mu.Unlock()
		go a.refreshSystemInfo()

	case !want:
		a.mu.Lock()
		a.suspended = false
		a.setReason("")
		a.mu.Unlock()
	}
}

// setProtection — panelden koruma aç/kapat
func (a *App) setProtection(on bool) {
	a.mu.Lock()
	cfg.AutoEnable = on
	a.suspended = false
	snapshot := cfg
	a.mu.Unlock()
	saveConfig(snapshot)
	a.reconcile()
}

// setBlocklist — panelden reklam engelleme aç/kapat
func (a *App) setBlocklist(on bool) {
	a.mu.Lock()
	cfg.BlocklistEnabled = on
	snapshot := cfg
	a.mu.Unlock()
	saveConfig(snapshot)
	blocker.enabled.Store(on)
	if on {
		a.startBlocklist()
	}
}

// ==================== KALICI KURULUM ====================

// installFiles — programı sabit konuma kopyala, ayarları sistem klasörüne taşı, servisi kaydet
func installFiles() error {
	if !isAdmin() {
		return errNotAdmin
	}
	target := installedExePath()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if !sameFile(exe, target) {
		if err := copyFile(exe, target, 0755); err != nil {
			return fmt.Errorf("program kopyalanamadı (%s): %v", target, err)
		}
	}

	// Kullanıcının mevcut ayarları ve listeleri sistem klasörüne taşınır
	sysDir := systemDataDir()
	os.MkdirAll(sysDir, 0755)
	if !sameFile(dataDir, sysDir) {
		for _, name := range []string{configFile, cfg.BlocklistFile, cfg.AllowlistFile} {
			src := dataPath(name)
			dst := filepath.Join(sysDir, filepath.Base(name))
			if _, err := os.Stat(dst); err == nil {
				continue
			}
			if _, err := os.Stat(src); err == nil {
				copyFile(src, dst, 0644)
			}
		}
	}
	return registerService(target, sysDir)
}

func sameFile(a, b string) bool {
	ia, err1 := os.Stat(a)
	ib, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ia, ib)
}

func copyFile(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, data, perm)
}

// installFromPanel — çalışan uygulamayı kalıcı servise devret
func (a *App) installFromPanel() error {
	if a.mode != "app" {
		return fmt.Errorf("zaten kalıcı olarak kurulu")
	}
	if err := installFiles(); err != nil {
		return err
	}
	a.mu.Lock()
	a.handoff = true
	a.mu.Unlock()
	go func() {
		time.Sleep(500 * time.Millisecond) // Yanıt tarayıcıya ulaşsın
		a.requestStop()                    // shutdown() servisi başlatır
	}()
	return nil
}
