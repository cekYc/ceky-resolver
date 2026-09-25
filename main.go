package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// ==================== ANA FONKSİYON ====================

const usageText = `Ceky Resolver %s — Bağımsız rekürsif DNS çözümleyici

Kullanım:
  ceky-resolver                Uygulamayı başlat ve kontrol panelini aç
  ceky-resolver install        Kalıcı kur (bilgisayar açılınca arka planda başlar)
  ceky-resolver uninstall      Kalıcı kurulumu kaldır, DNS ayarlarını geri yükle
  ceky-resolver restore        ACİL DURUM: DNS ayarlarını hemen eski haline getir
  ceky-resolver status         Durumu göster
  ceky-resolver version        Sürümü göster

Seçenekler:
  -data <klasör>   Ayarların tutulacağı klasör
  -no-browser      Kontrol panelini tarayıcıda açma

Kontrol paneli: http://127.0.0.1:9090
`

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Printf(usageText, version) }
	dataFlag := fs.String("data", "", "veri klasörü")
	noBrowser := fs.Bool("no-browser", false, "kontrol panelini açma")
	pause := fs.Bool("pause", false, "bitince Enter bekle")
	fs.Parse(args)

	dataDir = resolveDataDir(*dataFlag)

	// Yönetici olarak yeniden başlatılırken aynı seçenekler korunur
	relaunch := []string{cmd}
	if *dataFlag != "" {
		relaunch = append(relaunch, "-data", dataDir)
	}
	if *noBrowser {
		relaunch = append(relaunch, "-no-browser")
	}

	switch cmd {
	case "run":
		runApp("app", *noBrowser, relaunch)
	case "service":
		runApp("service", true, nil)
	case "install":
		withAdmin(relaunch, *pause, cmdInstall)
	case "uninstall":
		withAdmin(relaunch, *pause, cmdUninstall)
	case "restore":
		withAdmin(relaunch, *pause, cmdRestore)
	case "status":
		cmdStatus()
		if *pause || ownsConsole() {
			pauseIfOwnConsole()
		}
	case "version":
		fmt.Println(version)
	case "help":
		fs.Usage()
	default:
		fmt.Printf("Bilinmeyen komut: %s\n\n", cmd)
		fs.Usage()
		os.Exit(2)
	}
}

// withAdmin — komutu yönetici izniyle çalıştır (gerekirse izin iste)
func withAdmin(relaunch []string, pause bool, fn func() error) {
	if !isAdmin() {
		// Windows'ta yeni pencere açılır; çıktı okunabilsin diye orada Enter beklenir
		args := relaunch
		if runtime.GOOS == "windows" {
			args = append(args, "-pause")
		}
		if err := relaunchElevated(args); err != nil {
			fmt.Println("✗ Bu komut için yönetici izni gerekiyor.")
			if runtime.GOOS == "windows" {
				fmt.Println("  Komut İstemi'ni 'Yönetici olarak çalıştır' ile açıp tekrar deneyin.")
			} else {
				fmt.Printf("  sudo %s\n", strings.Join(os.Args, " "))
			}
			pauseIfOwnConsole()
			os.Exit(1)
		}
		return
	}
	err := fn()
	if err != nil {
		fmt.Printf("✗ Hata: %v\n", err)
	}
	if pause || ownsConsole() {
		fmt.Println("\nKapatmak için Enter'a basın...")
		fmt.Scanln()
	}
	if err != nil {
		os.Exit(1)
	}
}

// ==================== KOMUTLAR ====================

func cmdInstall() error {
	cfg = peekConfig()
	fmt.Println("Ceky Resolver kalıcı olarak kuruluyor...")

	if serviceInstalled() {
		fmt.Println("  • Önceki kurulum durduruluyor")
		stopService()
		waitFor(func() bool { return !instanceRunning(cfg.DashboardPort) }, 5*time.Second)
	}
	if instanceRunning(cfg.DashboardPort) {
		return fmt.Errorf("Ceky Resolver şu an açık — önce onu kapatın veya kontrol panelindeki \"Kalıcı Kur\" düğmesini kullanın")
	}

	if err := installFiles(); err != nil {
		return err
	}
	fmt.Printf("  • Program: %s\n", installedExePath())
	fmt.Printf("  • Ayarlar: %s\n", systemDataDir())

	if err := startService(); err != nil {
		return err
	}
	if !waitFor(func() bool { return instanceRunning(cfg.DashboardPort) }, 15*time.Second) {
		fmt.Println("  ⚠ Servis henüz yanıt vermiyor; birkaç saniye içinde başlamış olmalı.")
	}

	fmt.Println()
	fmt.Println("✓ Kurulum tamamlandı! Ceky Resolver artık bilgisayar açılışında otomatik başlar.")
	fmt.Println("  Kontrol paneli:", panelURL())
	fmt.Println("  Kaldırmak için:  ceky-resolver uninstall")
	openBrowser(panelURL())
	return nil
}

func cmdUninstall() error {
	cfg = peekConfig()
	fmt.Println("Ceky Resolver kaldırılıyor...")

	if serviceInstalled() {
		stopService()
		waitFor(func() bool { return !instanceRunning(cfg.DashboardPort) }, 5*time.Second)
		if err := unregisterService(); err != nil {
			return err
		}
		fmt.Println("  ✓ Otomatik başlatma kaldırıldı")
	}
	if err := disableSystemDNS(); err != nil {
		return fmt.Errorf("DNS ayarları geri yüklenemedi: %v", err)
	}
	fmt.Println("  ✓ DNS ayarları eski haline getirildi")

	exe, _ := os.Executable()
	if target := installedExePath(); !sameFile(exe, target) {
		os.Remove(target)
	}
	fmt.Println()
	fmt.Println("✓ Kaldırma tamamlandı.")
	fmt.Printf("  Ayarlarınız silinmedi: %s\n", systemDataDir())
	return nil
}

// cmdRestore — acil durum: interneti hemen eski DNS ile çalışır hale getir
func cmdRestore() error {
	cfg = peekConfig()
	if serviceInstalled() {
		// Servis durdurulmazsa ayarı birkaç saniye içinde yeniden uygular
		stopService()
		if serviceStopRestoresDNS { // macOS/Linux: süreç kapanırken DNS'i kendisi geri yükler
			waitFor(func() bool { return !backupExists() }, 5*time.Second)
		}
	}
	if !backupExists() {
		fmt.Println("✓ DNS ayarları zaten orijinal halinde.")
	} else if err := disableSystemDNS(); err != nil {
		return err
	} else {
		fmt.Println("✓ DNS ayarları eski haline getirildi.")
	}
	if serviceInstalled() {
		fmt.Println("  Kalıcı kurulum durduruldu; bilgisayar yeniden başlayınca tekrar çalışır.")
		fmt.Println("  Tamamen kaldırmak için: ceky-resolver uninstall")
	}
	return nil
}

func cmdStatus() {
	cfg = peekConfig()
	yesNo := func(b bool, yes, no string) string {
		if b {
			return yes
		}
		return no
	}
	running := instanceRunning(cfg.DashboardPort)
	fmt.Printf("Ceky Resolver %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Println("────────────────────────────────────")
	fmt.Println("Çalışıyor:        ", yesNo(running, "evet — "+panelURL(), "hayır"))
	fmt.Println("Koruma (sistem):  ", yesNo(backupExists(), "AÇIK — sistem DNS'i Ceky'ye yönlü", "kapalı"))
	fmt.Println("Kalıcı kurulum:   ", yesNo(serviceInstalled(), "var", "yok"))
	if servers := currentSystemDNS(); len(servers) > 0 {
		fmt.Println("Sistem DNS'i:     ", strings.Join(servers, ", "))
	}
	fmt.Println("Veri klasörü:     ", dataDir)
	fmt.Println("Yönetici:         ", yesNo(isAdmin(), "evet", "hayır"))
}

func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return cond()
}
