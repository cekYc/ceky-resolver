package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== REKLAM ENGELLEYİCİ (AD-BLOCKER) ====================

// Blocklist — Reklam/takipçi domain'lerini tutan yapı.
// Go'nun map yapısı hash tabanlı olduğu için arama O(1) karmaşıklığındadır.
// Listeler kilidin dışında hazırlanıp tek hamlede değiştirilir; böylece
// indirme sırasında DNS sorguları asla beklemez.
type Blocklist struct {
	mu       sync.RWMutex
	domains  map[string]struct{}
	allow    map[string]struct{}
	count    int
	blocked  uint64
	enabled  atomic.Bool
	loading  atomic.Bool
	loadedAt time.Time

	sources    []string
	customFile string // Kullanıcının kendi engelleme listesi
	allowFile  string // Asla engellenmeyecek domain'ler
	cacheDir   string // İndirilen listelerin yerel kopyaları
	refresh    time.Duration
	client     *http.Client
}

// Bilinen reklam/takipçi listesi kaynakları (hosts formatı)
var defaultBlocklistURLs = []string{
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"https://adaway.org/hosts.txt",
}

// Yeni blocklist oluştur
func newBlocklist() *Blocklist {
	return &Blocklist{
		domains: make(map[string]struct{}),
		allow:   make(map[string]struct{}),
		sources: defaultBlocklistURLs,
		refresh: 24 * time.Hour,
		client:  http.DefaultClient,
	}
}

// Domain engelli mi kontrol et — O(1) hızında
func (b *Blocklist) IsBlocked(domain string) bool {
	if !b.enabled.Load() {
		return false
	}
	normalized := normalizeName(domain)

	b.mu.RLock()
	defer b.mu.RUnlock()

	// İzin listesi her zaman önceliklidir (alt domain'ler dahil)
	for n := normalized; n != ""; n = parentName(n) {
		if _, ok := b.allow[n]; ok {
			return false
		}
	}
	// Tam eşleşme + alt domain: ads.example.com → example.com engelliyse engelle
	for n := normalized; strings.Contains(n, "."); n = parentName(n) {
		if _, ok := b.domains[n]; ok {
			atomic.AddUint64(&b.blocked, 1)
			return true
		}
	}
	return false
}

// Engelleme sayısını döndür
func (b *Blocklist) BlockedCount() uint64 {
	return atomic.LoadUint64(&b.blocked)
}

// Toplam engelli domain sayısı
func (b *Blocklist) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// LoadedAt — listelerin son yüklenme zamanı
func (b *Blocklist) LoadedAt() time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.loadedAt
}

// Allowlist — izin verilen domain'ler (sıralı)
func (b *Blocklist) Allowlist() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.allow))
	for d := range b.allow {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Allow — domain'i izin listesine ekle / çıkar ve dosyaya kaydet
func (b *Blocklist) Allow(domain string, allowed bool) error {
	d := normalizeName(strings.TrimSpace(domain))
	if d == "" || strings.ContainsAny(d, " /\\:*") {
		return fmt.Errorf("geçersiz domain: %q", domain)
	}
	b.mu.Lock()
	if allowed {
		b.allow[d] = struct{}{}
	} else {
		delete(b.allow, d)
	}
	list := make([]string, 0, len(b.allow))
	for a := range b.allow {
		list = append(list, a)
	}
	b.mu.Unlock()

	if b.allowFile == "" {
		return nil
	}
	sort.Strings(list)
	content := "# Ceky Resolver izin listesi — bu domain'ler (ve alt domain'leri) asla engellenmez\n" +
		strings.Join(list, "\n") + "\n"
	return writeFileAtomic(b.allowFile, []byte(content), 0644)
}

// Hosts formatındaki satırı ayrıştır
// Formatlar:
//
//	0.0.0.0 ads.example.com
//	127.0.0.1 ads.example.com
//	ads.example.com
//	||ads.example.com^   (AdBlock biçimi)
func parseHostsLine(line string) string {
	line = strings.TrimSpace(line)

	// Boş satır veya yorum
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return ""
	}

	// Satır içi yorum temizle
	if idx := strings.Index(line, "#"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}

	// AdBlock biçimi: ||domain^
	if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
		return validListDomain(line[2 : len(line)-1])
	}

	fields := strings.Fields(line)

	switch len(fields) {
	case 1:
		// Sadece domain adı
		return validListDomain(fields[0])
	default:
		// IP + domain formatı (hosts)
		domain := strings.ToLower(fields[1])
		// localhost, broadcasthost gibi girdileri atla
		switch domain {
		case "localhost", "localhost.localdomain", "local", "broadcasthost",
			"ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
			"ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0":
			return ""
		}
		return validListDomain(domain)
	}
}

func validListDomain(d string) string {
	d = normalizeName(d)
	if len(d) <= 3 || !strings.Contains(d, ".") || strings.ContainsAny(d, "/*:|^ ") || net.ParseIP(d) != nil {
		return ""
	}
	return d
}

// loadListFile — dosyadaki domain'leri map'e ekle
func loadListFile(path string, into map[string]struct{}) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	// Büyük satırlar için buffer'ı artır
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if domain := parseHostsLine(scanner.Text()); domain != "" {
			into[domain] = struct{}{}
			count++
		}
	}
	return count, scanner.Err()
}

func (b *Blocklist) cachePath(url string) string {
	sum := sha1.Sum([]byte(url))
	return filepath.Join(b.cacheDir, hex.EncodeToString(sum[:8])+".txt")
}

// download — listeyi indir ve önbellek dosyasına atomik olarak yaz
func (b *Blocklist) download(url, path string) error {
	resp, err := b.client.Get(url)
	if err != nil {
		return fmt.Errorf("indirme hatası: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0644)
}

// Load — listeleri yükle. update=true ise süresi dolmuş listeler internetten
// yeniden indirilir; false ise yalnızca yerel kopyalar kullanılır (hızlı açılış).
func (b *Blocklist) Load(update bool) {
	if !b.loading.CompareAndSwap(false, true) {
		return
	}
	defer b.loading.Store(false)

	startTime := time.Now()
	domains := make(map[string]struct{}, 100000)
	allow := make(map[string]struct{})
	os.MkdirAll(b.cacheDir, 0755)

	// 1) Kullanıcının özel listesi
	if b.customFile != "" {
		if count, err := loadListFile(b.customFile, domains); err == nil && count > 0 {
			fmt.Printf("║   ✓ Özel liste: %d domain\n", count)
		}
	}

	// 2) Online kaynaklar (yerel kopya üzerinden)
	downloaded := 0
	for _, url := range b.sources {
		// URL'nin kısa adını al
		shortName := url
		if idx := strings.LastIndex(url, "/"); idx >= 0 {
			shortName = url[idx+1:]
		}
		path := b.cachePath(url)
		info, statErr := os.Stat(path)
		if update && (statErr != nil || time.Since(info.ModTime()) > b.refresh) {
			if err := b.download(url, path); err != nil {
				fmt.Printf("║   ⚠ %s indirilemedi: %v (eski kopya kullanılıyor)\n", shortName, err)
			} else {
				downloaded++
			}
		}
		if count, err := loadListFile(path, domains); err == nil {
			if update {
				fmt.Printf("║   ✓ %s: %d domain\n", shortName, count)
			}
		}
	}

	// 3) İzin listesi
	if b.allowFile != "" {
		loadListFile(b.allowFile, allow)
	}

	if !update && len(domains) == 0 && len(allow) == 0 {
		return // Henüz yerel kopya yok — indirme bekleniyor
	}
	if update && downloaded == 0 && len(domains) == b.Size() && b.Size() > 0 {
		return // Değişiklik yok
	}

	b.mu.Lock()
	b.domains = domains
	b.allow = allow
	b.count = len(domains) // Benzersiz domain sayısı
	b.loadedAt = time.Now()
	b.mu.Unlock()

	fmt.Printf("║ 🛡️  Reklam engelleme: %d benzersiz domain (%.1fs)\n", len(domains), time.Since(startTime).Seconds())
}

// StartAutoRefresh — açılışta yerel kopyaları yükle, ardından periyodik güncelle
func (b *Blocklist) StartAutoRefresh(stop <-chan struct{}) {
	b.Load(false)
	go func() {
		// Kök sunuculara erişim kontrolü tamamlansın diye kısa bekle
		select {
		case <-time.After(3 * time.Second):
		case <-stop:
			return
		}
		b.Load(true)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.Load(true)
			case <-stop:
				return
			}
		}
	}()
}

// ==================== KENDİ KENDİNE ÇÖZÜMLEYEN HTTP İSTEMCİSİ ====================

// newSelfResolvingClient — liste indirmeleri için bile aracı DNS kullanmayan istemci.
// Alan adları Ceky'nin kendi rekürsif çözümleyicisiyle çözülür.
func newSelfResolvingClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil || resolver == nil {
			return dialer.DialContext(ctx, network, addr)
		}
		var lastErr error
		for _, rr := range resolver.Resolve(host, typeA).Records {
			if rr.Type != typeA {
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(recordIP(rr), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		// Kendi çözümleyicimiz sonuç veremediyse işletim sistemine bırak
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Client{Timeout: 90 * time.Second, Transport: transport}
}

// writeFileAtomic — önce geçici dosyaya yaz, sonra yerine taşı
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ceky-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	os.Chmod(tmp.Name(), perm)
	return os.Rename(tmp.Name(), path)
}
