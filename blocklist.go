package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== REKLAM ENGELLEYİCİ (AD-BLOCKER) ====================

// Blocklist — Reklam/takipçi domain'lerini tutan yapı
// Go'nun map yapısı hash tabanlı olduğu için arama O(1) karmaşıklığındadır.
type Blocklist struct {
	mu       sync.RWMutex
	domains  map[string]bool
	count    int
	blocked  uint64
	sources  []string
	loadedAt time.Time
}

// Bilinen reklam/takipçi listesi kaynakları (hosts formatı)
var defaultBlocklistURLs = []string{
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"https://adaway.org/hosts.txt",
}

// Yerel blocklist dosya yolu
const localBlocklistFile = "blocklist.txt"

// Yeni blocklist oluştur
func newBlocklist() *Blocklist {
	return &Blocklist{
		domains: make(map[string]bool),
		sources: defaultBlocklistURLs,
	}
}

// Domain engelli mi kontrol et — O(1) hızında
func (b *Blocklist) IsBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Tam eşleşme
	normalized := strings.ToLower(strings.TrimSuffix(domain, "."))
	if b.domains[normalized] {
		atomic.AddUint64(&b.blocked, 1)
		return true
	}

	// Alt domain kontrolü: ads.example.com → example.com da engelliyse engelle
	parts := strings.Split(normalized, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if b.domains[parent] {
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

// Hosts formatındaki satırı ayrıştır
// Formatlar:
//
//	0.0.0.0 ads.example.com
//	127.0.0.1 ads.example.com
//	ads.example.com
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

	fields := strings.Fields(line)

	switch len(fields) {
	case 1:
		// Sadece domain adı
		return strings.ToLower(fields[0])
	case 2:
		// IP + domain formatı (hosts)
		domain := strings.ToLower(fields[1])
		// localhost, broadcasthost gibi girdileri atla
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "local" || domain == "broadcasthost" ||
			domain == "ip6-localhost" || domain == "ip6-loopback" ||
			domain == "ip6-localnet" || domain == "ip6-mcastprefix" ||
			domain == "ip6-allnodes" || domain == "ip6-allrouters" ||
			domain == "ip6-allhosts" {
			return ""
		}
		return domain
	default:
		if len(fields) > 2 {
			return strings.ToLower(fields[1])
		}
		return ""
	}
}

// URL'den blocklist indir ve yükle
func (b *Blocklist) loadFromURL(url string) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("indirme hatası: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	count := 0
	scanner := bufio.NewScanner(resp.Body)
	// Büyük satırlar için buffer'ı artır
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		domain := parseHostsLine(scanner.Text())
		if domain != "" && len(domain) > 3 {
			b.domains[domain] = true
			count++
		}
	}

	return count, scanner.Err()
}

// Yerel dosyadan blocklist yükle
func (b *Blocklist) loadFromFile(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := parseHostsLine(scanner.Text())
		if domain != "" && len(domain) > 3 {
			b.domains[domain] = true
			count++
		}
	}

	return count, scanner.Err()
}

// Tüm kaynakları yükle
func (b *Blocklist) Load() {
	b.mu.Lock()
	defer b.mu.Unlock()

	startTime := time.Now()
	totalLoaded := 0

	fmt.Println("║")
	fmt.Println("║ 🛡️  Reklam Engelleme Listesi Yükleniyor...")

	// 1) Yerel dosya varsa yükle
	if _, err := os.Stat(localBlocklistFile); err == nil {
		count, err := b.loadFromFile(localBlocklistFile)
		if err != nil {
			fmt.Printf("║   ⚠ Yerel liste hatası: %v\n", err)
		} else {
			fmt.Printf("║   ✓ Yerel liste: %d domain yüklendi\n", count)
			totalLoaded += count
		}
	}

	// 2) Online kaynakları indir
	for _, url := range b.sources {
		// URL'nin kısa adını al
		shortName := url
		if idx := strings.LastIndex(url, "/"); idx >= 0 {
			shortName = url[idx+1:]
		}

		fmt.Printf("║   ↓ İndiriliyor: %s...\n", shortName)
		count, err := b.loadFromURL(url)
		if err != nil {
			fmt.Printf("║   ⚠ Hata (%s): %v\n", shortName, err)
		} else {
			fmt.Printf("║   ✓ %s: %d domain yüklendi\n", shortName, count)
			totalLoaded += count
		}
	}

	b.count = len(b.domains) // Benzersiz domain sayısı
	b.loadedAt = time.Now()

	elapsed := time.Since(startTime)
	fmt.Printf("║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("║   🛡️  Toplam: %d benzersiz domain engellendi (%.1fs)\n", b.count, elapsed.Seconds())
	fmt.Println("║")
}

// Engelli domain'e 0.0.0.0 yanıtı oluştur
func buildBlockedResponse(requestBuf []byte) []byte {
	origHeader := parseHeader(requestBuf[:12])

	// Yanıt header'ı — 1 answer, RCODE=0 (başarılı ama 0.0.0.0)
	respHeader := make([]byte, 12)
	binary.BigEndian.PutUint16(respHeader[0:2], origHeader.ID)
	binary.BigEndian.PutUint16(respHeader[2:4], 0x8180) // QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(respHeader[4:6], origHeader.QDCount)
	binary.BigEndian.PutUint16(respHeader[6:8], 1) // 1 answer
	binary.BigEndian.PutUint16(respHeader[8:10], 0)
	binary.BigEndian.PutUint16(respHeader[10:12], 0)

	var response []byte
	response = append(response, respHeader...)

	// Soru bölümünü kopyala
	_, questionEnd := parseQuestion(requestBuf, 12)
	response = append(response, requestBuf[12:questionEnd]...)

	// Answer: 0.0.0.0 (A kaydı)
	response = append(response, 0xC0, 0x0C) // Name pointer
	answerTail := make([]byte, 10)
	binary.BigEndian.PutUint16(answerTail[0:2], 1)   // Type: A
	binary.BigEndian.PutUint16(answerTail[2:4], 1)   // Class: IN
	binary.BigEndian.PutUint32(answerTail[4:8], 300) // TTL: 5 dakika
	binary.BigEndian.PutUint16(answerTail[8:10], 4)  // RDLength: 4 byte
	response = append(response, answerTail...)
	response = append(response, 0, 0, 0, 0) // 0.0.0.0

	return response
}
