package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ==================== YAPILAR (STRUCTS) ====================

// DNSHeader — DNS paket başlığı (12 byte)
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion — DNS soru bölümü
type DNSQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

// DNSRecord — Ayrıştırılmış DNS kayıt yapısı (Answer, Authority, Additional)
type DNSRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// ==================== ÖNBELLEK (CACHE) ====================

// CacheEntry — Önbellekteki bir DNS kaydı
type CacheEntry struct {
	Records   []DNSRecord
	ExpiresAt time.Time
	CachedAt  time.Time
}

// DNSCache — Goroutine-safe DNS önbelleği
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
	hits    uint64
	misses  uint64
}

// Yeni cache oluştur
func newDNSCache() *DNSCache {
	return &DNSCache{
		entries: make(map[string]CacheEntry),
	}
}

// Cache anahtarı oluştur (domain + qtype)
func cacheKey(domain string, qtype uint16) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(domain), qtype)
}

// Cache'den oku — TTL süresi dolmuşsa nil döner
func (c *DNSCache) Get(domain string, qtype uint16) ([]DNSRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(domain, qtype)
	entry, exists := c.entries[key]
	if !exists {
		c.misses++
		return nil, false
	}

	// TTL süresi dolmuş mu?
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		c.misses++
		return nil, false
	}

	// TTL'i kalan süreye göre güncelle (client'a doğru TTL göstermek için)
	elapsed := uint32(time.Since(entry.CachedAt).Seconds())
	updatedRecords := make([]DNSRecord, len(entry.Records))
	copy(updatedRecords, entry.Records)
	for i := range updatedRecords {
		if updatedRecords[i].TTL > elapsed {
			updatedRecords[i].TTL -= elapsed
		} else {
			updatedRecords[i].TTL = 1
		}
	}

	c.hits++
	return updatedRecords, true
}

// Cache'e yaz — TTL'e göre son kullanma tarihi hesapla
func (c *DNSCache) Set(domain string, qtype uint16, records []DNSRecord) {
	if len(records) == 0 {
		return
	}

	// En düşük TTL'i bul
	minTTL := records[0].TTL
	for _, r := range records {
		if r.TTL < minTTL {
			minTTL = r.TTL
		}
	}
	if minTTL == 0 {
		minTTL = 60 // minimum 60 saniye
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[cacheKey(domain, qtype)] = CacheEntry{
		Records:   records,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
	}
}

// Cache istatistikleri
func (c *DNSCache) Stats() (size int, hits, misses uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries), c.hits, c.misses
}

// Süresi dolmuş kayıtları temizle
func (c *DNSCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleaned := 0
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			cleaned++
		}
	}
	return cleaned
}

// ==================== PERFORMANS METRİKLERİ ====================

// QueryMetric — Tek bir sorgunun ölçüm verisi
type QueryMetric struct {
	ServerIP   string
	ServerType string // "root", "tld", "auth"
	Domain     string
	Duration   time.Duration
	Protocol   string // "udp", "tcp"
}

// ResolverMetrics — Tüm ölçümleri toplayan yapı
type ResolverMetrics struct {
	mu             sync.Mutex
	totalQueries   uint64
	cachedQueries  uint64
	totalResolveMs float64
	queryMetrics   []QueryMetric
	serverAvg      map[string]struct {
		totalMs float64
		count   int
	}
}

func newResolverMetrics() *ResolverMetrics {
	return &ResolverMetrics{
		serverAvg: make(map[string]struct {
			totalMs float64
			count   int
		}),
	}
}

// Sorgu metriği kaydet
func (m *ResolverMetrics) RecordQuery(metric QueryMetric) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.queryMetrics = append(m.queryMetrics, metric)

	// Sunucu türüne göre ortalama hesapla
	key := metric.ServerType
	entry := m.serverAvg[key]
	entry.totalMs += float64(metric.Duration.Milliseconds())
	entry.count++
	m.serverAvg[key] = entry
}

// Toplam sorgu sayısını artır
func (m *ResolverMetrics) IncrementTotal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalQueries++
}

// Cached sorgu sayısını artır
func (m *ResolverMetrics) IncrementCached() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedQueries++
}

// Toplam çözümleme süresi ekle
func (m *ResolverMetrics) AddResolveTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalResolveMs += float64(d.Milliseconds())
}

// İstatistik raporu yazdır
func (m *ResolverMetrics) PrintStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println()
	fmt.Println("╔══ Resolver Monitor ════════════════════════")
	fmt.Printf("║ Toplam Sorgu:     %d\n", m.totalQueries)
	fmt.Printf("║ Önbellekten:      %d\n", m.cachedQueries)

	if m.totalQueries > 0 {
		avgMs := m.totalResolveMs / float64(m.totalQueries)
		fmt.Printf("║ Ort. Çözümleme:   %.1f ms\n", avgMs)
	}

	fmt.Println("║")
	fmt.Println("║ Sunucu Türü       Ort. Yanıt    Sorgu")
	fmt.Println("║ ─────────────────────────────────────")

	for _, stype := range []string{"root", "tld", "auth"} {
		if entry, ok := m.serverAvg[stype]; ok && entry.count > 0 {
			avg := entry.totalMs / float64(entry.count)
			label := map[string]string{"root": "Kök", "tld": "TLD", "auth": "Yetkili"}[stype]
			fmt.Printf("║ %-17s %6.1f ms     %d\n", label, avg, entry.count)
		}
	}
	fmt.Println("╚═══════════════════════════════════════════")
}

// Global cache, metrik ve blocker nesneleri
var (
	dnsCache *DNSCache
	metrics  *ResolverMetrics
	blocker  *Blocklist
	cfg      Config
)

// ==================== KÖK SUNUCULAR ====================

// 13 kök DNS sunucusunun IP adresleri
var rootServers = []string{
	"198.41.0.4",     // a.root-servers.net
	"199.9.14.201",   // b.root-servers.net
	"192.33.4.12",    // c.root-servers.net
	"199.7.91.13",    // d.root-servers.net
	"192.203.230.10", // e.root-servers.net
	"192.5.5.241",    // f.root-servers.net
	"192.112.36.4",   // g.root-servers.net
	"198.97.190.53",  // h.root-servers.net
	"192.36.148.17",  // i.root-servers.net
	"192.58.128.30",  // j.root-servers.net
	"193.0.14.129",   // k.root-servers.net
	"199.7.83.42",    // l.root-servers.net
	"202.12.27.33",   // m.root-servers.net
}

// ==================== AYRIŞTIRMA (PARSING) ====================

// Byte dizisini alıp DNSHeader struct'ına dönüştüren fonksiyon
func parseHeader(buf []byte) DNSHeader {
	return DNSHeader{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   binary.BigEndian.Uint16(buf[2:4]),
		QDCount: binary.BigEndian.Uint16(buf[4:6]),
		ANCount: binary.BigEndian.Uint16(buf[6:8]),
		NSCount: binary.BigEndian.Uint16(buf[8:10]),
		ARCount: binary.BigEndian.Uint16(buf[10:12]),
	}
}

// DNS soru kısmını ayrıştır
func parseQuestion(buf []byte, offset int) (DNSQuestion, int) {
	name, newOffset := parseDomainName(buf, offset)
	qtype := binary.BigEndian.Uint16(buf[newOffset : newOffset+2])
	qclass := binary.BigEndian.Uint16(buf[newOffset+2 : newOffset+4])
	newOffset += 4

	return DNSQuestion{
		Name:   name,
		QType:  qtype,
		QClass: qclass,
	}, newOffset
}

// Domain adını wire formatından ayrıştır (compression pointer desteği ile)
func parseDomainName(buf []byte, offset int) (string, int) {
	var labels []string
	jumped := false
	originalOffset := offset

	for {
		if offset >= len(buf) {
			break
		}
		length := int(buf[offset])

		// Null terminator — alan adı bitti
		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			break
		}

		// Compression pointer (ilk 2 bit = 11)
		if length&0xC0 == 0xC0 {
			if !jumped {
				originalOffset = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(buf[offset:offset+2])) & 0x3FFF
			offset = pointer
			jumped = true
			continue
		}

		// Normal etiket
		offset++
		if offset+length > len(buf) {
			break
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}

	return strings.Join(labels, "."), originalOffset
}

// DNS kayıtlarını ayrıştır (Answer, Authority veya Additional bölümü)
func parseRecords(buf []byte, offset int, count uint16) ([]DNSRecord, int) {
	records := make([]DNSRecord, 0, count)

	for i := 0; i < int(count); i++ {
		if offset >= len(buf) {
			break
		}

		name, newOffset := parseDomainName(buf, offset)
		offset = newOffset

		if offset+10 > len(buf) {
			break
		}

		rtype := binary.BigEndian.Uint16(buf[offset : offset+2])
		class := binary.BigEndian.Uint16(buf[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(buf[offset+4 : offset+8])
		rdlength := binary.BigEndian.Uint16(buf[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlength) > len(buf) {
			break
		}

		rdata := make([]byte, rdlength)
		copy(rdata, buf[offset:offset+int(rdlength)])

		records = append(records, DNSRecord{
			Name:     name,
			Type:     rtype,
			Class:    class,
			TTL:      ttl,
			RDLength: rdlength,
			RData:    rdata,
		})
		offset += int(rdlength)
	}

	return records, offset
}

// ==================== PATİKA OLUŞTURMA ====================

// Domain adını DNS wire formatına dönüştür
func domainToBytes(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0)
	return buf
}

// Yeni bir DNS sorgu paketi oluştur (EDNS0 destekli)
func buildQuery(domain string, qtype uint16) []byte {
	// Header
	header := make([]byte, 12)
	id := uint16(rand.Intn(65535))
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0000) // Flags: standart sorgu, recursion istenmiyor
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCount: 1 soru
	binary.BigEndian.PutUint16(header[10:12], 1)    // ARCount: 1 (EDNS0 OPT kaydı)

	// Soru bölümü
	question := domainToBytes(domain)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype) // QType
	binary.BigEndian.PutUint16(tail[2:4], 1)     // QClass: IN

	// EDNS0 OPT kaydı (RFC 6891)
	// Kök sunucular EDNS0 olmadan büyük yanıtları keser (TC=1)
	opt := make([]byte, 11)
	opt[0] = 0                                 // Name: root (boş)
	binary.BigEndian.PutUint16(opt[1:3], 41)   // Type: OPT (41)
	binary.BigEndian.PutUint16(opt[3:5], 4096) // UDP payload size: 4096
	// opt[5:9] = 0 (extended RCODE, version, DO=0, Z=0)
	binary.BigEndian.PutUint16(opt[9:11], 0) // RDLENGTH: 0

	var buf []byte
	buf = append(buf, header...)
	buf = append(buf, question...)
	buf = append(buf, tail...)
	buf = append(buf, opt...)
	return buf
}

// Belirli bir DNS sunucusuna UDP ile sorgu gönder
func queryServerUDP(serverIP string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", serverIP+":53", 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("UDP bağlantı hatası (%s): %v", serverIP, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("UDP gönderme hatası: %v", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("UDP okuma hatası: %v", err)
	}

	return response[:n], nil
}

// Belirli bir DNS sunucusuna TCP ile sorgu gönder (DNS over TCP: 2-byte uzunluk prefix)
func queryServerTCP(serverIP string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", serverIP+":53", 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP bağlantı hatası (%s): %v", serverIP, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// TCP DNS: önce 2-byte mesaj uzunluğunu gönder
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	_, err = conn.Write(append(lenBuf, query...))
	if err != nil {
		return nil, fmt.Errorf("TCP gönderme hatası: %v", err)
	}

	// Yanıt uzunluğunu oku (2 byte)
	_, err = conn.Read(lenBuf)
	if err != nil {
		return nil, fmt.Errorf("TCP uzunluk okuma hatası: %v", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))

	// Yanıt gövdesini oku
	response := make([]byte, respLen)
	totalRead := 0
	for totalRead < respLen {
		n, err := conn.Read(response[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("TCP okuma hatası: %v", err)
		}
		totalRead += n
	}

	return response, nil
}

// DNS sunucusuna sorgu gönder — önce UDP dene, REFUSED veya TC ise TCP'ye geç
func queryServer(serverIP string, domain string, qtype uint16, serverType string) (DNSHeader, []DNSRecord, []DNSRecord, []DNSRecord, []byte, error) {
	query := buildQuery(domain, qtype)
	start := time.Now()
	protocol := "udp"

	// Önce UDP dene
	response, err := queryServerUDP(serverIP, query)
	if err != nil {
		// UDP başarısız oldu, TCP dene
		fmt.Printf("    [UDP başarısız, TCP deneniyor: %s]\n", serverIP)
		protocol = "tcp"
		response, err = queryServerTCP(serverIP, query)
		if err != nil {
			return DNSHeader{}, nil, nil, nil, nil, err
		}
	}

	if len(response) < 12 {
		return DNSHeader{}, nil, nil, nil, nil, fmt.Errorf("yanıt çok kısa: %d byte", len(response))
	}

	// Header'ı ayrıştır
	respHeader := parseHeader(response[:12])

	// REFUSED (RCODE=5) veya Truncated (TC=1) → TCP'ye geç
	rcode := respHeader.Flags & 0x000F
	tc := respHeader.Flags & 0x0200
	if rcode == 5 || tc != 0 {
		if rcode == 5 {
			fmt.Printf("    [UDP REFUSED, TCP deneniyor: %s]\n", serverIP)
		} else {
			fmt.Printf("    [Yanıt kesilmiş (TC=1), TCP deneniyor: %s]\n", serverIP)
		}
		protocol = "tcp"
		response, err = queryServerTCP(serverIP, query)
		if err != nil {
			return DNSHeader{}, nil, nil, nil, nil, err
		}
		if len(response) < 12 {
			return DNSHeader{}, nil, nil, nil, nil, fmt.Errorf("TCP yanıt çok kısa: %d byte", len(response))
		}
		respHeader = parseHeader(response[:12])
	}

	// Soru bölümünü atla
	offset := 12
	for i := 0; i < int(respHeader.QDCount); i++ {
		_, offset = parseQuestion(response, offset)
	}

	// Answer, Authority ve Additional bölümlerini ayrıştır
	answers, offset := parseRecords(response, offset, respHeader.ANCount)
	authorities, offset := parseRecords(response, offset, respHeader.NSCount)
	additionals, _ := parseRecords(response, offset, respHeader.ARCount)

	duration := time.Since(start)
	fmt.Printf("    [Yanıt: %d byte, AN=%d, NS=%d, AR=%d — %s %dms]\n",
		len(response), len(answers), len(authorities), len(additionals),
		protocol, duration.Milliseconds())

	// Metrik kaydet
	metrics.RecordQuery(QueryMetric{
		ServerIP:   serverIP,
		ServerType: serverType,
		Domain:     domain,
		Duration:   duration,
		Protocol:   protocol,
	})

	return respHeader, answers, authorities, additionals, response, nil
}

// ==================== REKÜRSİF ÇÖZÜMLEME ====================

// Bir NS kaydından IP adresi bul (Additional bölümündeki A kayıtlarından)
func findNSIP(nsName string, additionals []DNSRecord) string {
	for _, rec := range additionals {
		if rec.Type == 1 && strings.EqualFold(rec.Name, nsName) && len(rec.RData) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rec.RData[0], rec.RData[1], rec.RData[2], rec.RData[3])
		}
	}
	return ""
}

// NS kaydının RData'sından domain adını çıkar
func extractNSName(rdata []byte, fullResponse []byte) string {
	// NS kayıtlarında RData, compression pointer içerebilen bir domain adıdır
	// Ancak RData offsetini bilmemiz lazım — basit yaklaşım olarak
	// fullResponse üzerinden çözmek gerekir. Burada basitleştirilmiş versiyon:
	name, _ := parseDomainName(fullResponse, findRDataOffset(fullResponse, rdata))
	return name
}

// RData'nın fullResponse içindeki offset'ini bul
func findRDataOffset(fullResponse []byte, rdata []byte) int {
	for i := 0; i <= len(fullResponse)-len(rdata); i++ {
		match := true
		for j := 0; j < len(rdata); j++ {
			if fullResponse[i+j] != rdata[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return 0
}

// resolve — Kök sunuculardan başlayarak domain adını çözümle
func resolve(domain string, qtype uint16, depth int) ([]DNSRecord, error) {
	if depth > 10 {
		return nil, fmt.Errorf("maksimum derinlik aşıldı (döngü olabilir)")
	}

	// Önbellekte var mı?
	if cached, ok := dnsCache.Get(domain, qtype); ok {
		fmt.Printf("  [Adım %d] ⚡ ÖNBELLEKTEN: %s (tip: %d)\n", depth, domain, qtype)
		return cached, nil
	}

	// Kök sunuculardan birini seç
	nameserver := rootServers[rand.Intn(len(rootServers))]

	fmt.Printf("  [Adım %d] Kök sunucudan başlıyoruz: %s\n", depth, nameserver)

	for i := 0; i < 20; i++ { // Sonsuz döngüye karşı güvenlik
		// Sunucu türünü belirle
		var serverType string
		if i == 0 {
			serverType = "root"
		} else if i == 1 {
			serverType = "tld"
		} else {
			serverType = "auth"
		}

		fmt.Printf("  [Adım %d.%d] %s sunucusuna sorgu: %s (tip: %d)\n", depth, i, nameserver, domain, qtype)

		header, answers, authorities, additionals, rawResponse, err := queryServer(nameserver, domain, qtype, serverType)
		if err != nil {
			return nil, fmt.Errorf("sorgu hatası (%s): %v", nameserver, err)
		}

		// RCODE kontrolü
		rcode := header.Flags & 0x000F
		if rcode == 3 { // NXDOMAIN
			return nil, fmt.Errorf("alan adı bulunamadı (NXDOMAIN): %s", domain)
		}

		// 1) Yanıtta cevap (Answer) varsa → buldum!
		if len(answers) > 0 {
			// CNAME ise, CNAME'in gösterdiği adresi çözümle
			for _, ans := range answers {
				if ans.Type == 5 { // CNAME
					cname, _ := parseDomainName(rawResponse, findRDataOffset(rawResponse, ans.RData))
					fmt.Printf("  [Adım %d.%d] CNAME bulundu: %s → %s\n", depth, i, domain, cname)
					return resolve(cname, qtype, depth+1)
				}
			}
			fmt.Printf("  [Adım %d.%d] ✓ Cevap bulundu! (%d kayıt)\n", depth, i, len(answers))
			// Önbelleğe kaydet
			dnsCache.Set(domain, qtype, answers)
			return answers, nil
		}

		// 2) Authority bölümünde NS kaydı varsa → bir sonraki sunucuya yönlen
		if len(authorities) > 0 {
			found := false
			for _, auth := range authorities {
				if auth.Type != 2 { // NS kaydı değilse atla
					continue
				}

				nsName, _ := parseDomainName(rawResponse, findRDataOffset(rawResponse, auth.RData))
				fmt.Printf("  [Adım %d.%d] NS referansı: %s → %s\n", depth, i, auth.Name, nsName)

				// Additional bölümünde bu NS'in IP'si var mı?
				nsIP := findNSIP(nsName, additionals)

				if nsIP == "" {
					// IP yok, NS adını kendi çözümlememiz gerekiyor (glue record eksik)
					fmt.Printf("  [Adım %d.%d] NS IP'si bilinmiyor, %s çözümleniyor...\n", depth, i, nsName)
					nsRecords, err := resolve(nsName, 1, depth+1) // A kaydı iste
					if err != nil || len(nsRecords) == 0 {
						continue // Bu NS işe yaramadı, sonrakini dene
					}
					if len(nsRecords[0].RData) == 4 {
						nsIP = fmt.Sprintf("%d.%d.%d.%d",
							nsRecords[0].RData[0], nsRecords[0].RData[1],
							nsRecords[0].RData[2], nsRecords[0].RData[3])
					}
				}

				if nsIP != "" {
					nameserver = nsIP
					found = true
					break
				}
			}

			if !found {
				return nil, fmt.Errorf("NS kaydı bulundu ama IP çözümlenemedi: %s", domain)
			}
			continue // Yeni nameserver ile tekrar dene
		}

		// 3) Ne cevap ne de authority yok
		return nil, fmt.Errorf("çözümleme sonuçsuz kaldı: %s", domain)
	}

	return nil, fmt.Errorf("çözümleme tamamlanamadı (çok fazla adım): %s", domain)
}

// ==================== YANIT PAKETİ OLUŞTURMA ====================

// İstemciye gönderilecek DNS yanıt paketini oluştur
func buildResponse(requestBuf []byte, requestLen int, answers []DNSRecord) []byte {
	// Orijinal header'ı al
	origHeader := parseHeader(requestBuf[:12])

	// Yanıt header'ı oluştur
	respHeader := make([]byte, 12)
	binary.BigEndian.PutUint16(respHeader[0:2], origHeader.ID)        // Aynı ID
	binary.BigEndian.PutUint16(respHeader[2:4], 0x8180)               // QR=1 (yanıt), RD=1, RA=1
	binary.BigEndian.PutUint16(respHeader[4:6], origHeader.QDCount)   // Soru sayısı
	binary.BigEndian.PutUint16(respHeader[6:8], uint16(len(answers))) // Cevap sayısı
	binary.BigEndian.PutUint16(respHeader[8:10], 0)                   // Authority sayısı
	binary.BigEndian.PutUint16(respHeader[10:12], 0)                  // Additional sayısı

	var response []byte
	response = append(response, respHeader...)

	// Soru bölümünü orijinalden kopyala
	_, questionEnd := parseQuestion(requestBuf, 12)
	response = append(response, requestBuf[12:questionEnd]...)

	// Cevap kayıtlarını ekle
	for _, ans := range answers {
		// İsim — soru bölümüne pointer (0xC00C = offset 12)
		response = append(response, 0xC0, 0x0C)
		// Type
		typeBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(typeBuf, ans.Type)
		response = append(response, typeBuf...)
		// Class
		classBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(classBuf, ans.Class)
		response = append(response, classBuf...)
		// TTL
		ttlBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(ttlBuf, ans.TTL)
		response = append(response, ttlBuf...)
		// RDLength
		rdlenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(rdlenBuf, uint16(len(ans.RData)))
		response = append(response, rdlenBuf...)
		// RData
		response = append(response, ans.RData...)
	}

	return response
}

// NXDOMAIN yanıtı oluştur
func buildNXDOMAIN(requestBuf []byte) []byte {
	origHeader := parseHeader(requestBuf[:12])

	respHeader := make([]byte, 12)
	binary.BigEndian.PutUint16(respHeader[0:2], origHeader.ID)
	binary.BigEndian.PutUint16(respHeader[2:4], 0x8183) // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
	binary.BigEndian.PutUint16(respHeader[4:6], origHeader.QDCount)
	binary.BigEndian.PutUint16(respHeader[6:8], 0)
	binary.BigEndian.PutUint16(respHeader[8:10], 0)
	binary.BigEndian.PutUint16(respHeader[10:12], 0)

	var response []byte
	response = append(response, respHeader...)

	_, questionEnd := parseQuestion(requestBuf, 12)
	response = append(response, requestBuf[12:questionEnd]...)

	return response
}

// ==================== ANA FONKSİYON ====================

func main() {
	rand.Seed(time.Now().UnixNano())

	// Yapılandırmayı yükle
	cfg = loadConfig()

	// Core bileşenleri başlat
	dnsCache = newDNSCache()
	metrics = newResolverMetrics()
	blocker = newBlocklist()
	queryLog = newQueryLog(cfg.QueryLogSize)

	// Başlık
	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║       Ceky Resolver v4.0 — Başlatıldı      ║")
	fmt.Println("║   Gerçek Rekursif DNS Çözümleyici        ║")
	fmt.Println("║   + Reklam Engelleme (Pi-hole)          ║")
	fmt.Println("║   + Yüksek Performans (Goroutine)       ║")
	fmt.Println("║   + Şifreli DNS (DoH/DoT)               ║")
	fmt.Println("║   + Canlı Web Dashboard                 ║")
	fmt.Println("╚════════════════════════════════════════════╝")
	fmt.Printf("║ ⚙ Yapılandırma: %s\n", configFile)
	fmt.Printf("║   DNS Port: %d | Bind: %s\n", cfg.DNSPort, cfg.BindAddr)

	// Reklam engelleme
	if cfg.BlocklistEnabled {
		blocker.sources = cfg.BlocklistURLs
		go blocker.Load()
	} else {
		fmt.Println("║ ⚠ Reklam engelleme devre dışı")
	}

	// Web Dashboard
	if cfg.DashboardOn {
		startDashboard(cfg.DashboardPort)
	}

	// Periyodik cache temizliği
	if cfg.CacheEnabled {
		go func() {
			interval := time.Duration(cfg.CacheCleanupSec) * time.Second
			for {
				time.Sleep(interval)
				cleaned := dnsCache.Cleanup()
				if cleaned > 0 {
					fmt.Printf("\n[Önbellek] %d süresi dolmuş kayıt temizlendi\n", cleaned)
				}
			}
		}()
	}

	// Periyodik istatistik raporu
	if cfg.StatsInterval > 0 {
		go func() {
			interval := time.Duration(cfg.StatsInterval) * time.Second
			for {
				time.Sleep(interval)
				metrics.PrintStats()
				size, hits, misses := dnsCache.Stats()
				fmt.Printf("║ Önbellek:   %d kayıt, %d isabet, %d ıskalama\n", size, hits, misses)
				if hits+misses > 0 {
					fmt.Printf("║ İsabet:     %.1f%%\n", float64(hits)/float64(hits+misses)*100)
				}
				fmt.Printf("║ Engellenen: %d reklam/takipçı (%d kural)\n", blocker.BlockedCount(), blocker.Size())
				fmt.Println("╚═══════════════════════════════════════════")
			}
		}()
	}

	// TLS sertifikasını kontrol et / oluştur
	certFile, keyFile := ensureTLSCerts(cfg)

	// DoT ve DoH sunucularını başlat
	if certFile != "" && keyFile != "" {
		startDoTServer(certFile, keyFile)
		startDoHServer(certFile, keyFile)
	} else {
		fmt.Println("║ ⚠ DoT devre dışı (sertifika yok)")
		startDoHServer(cfg.CertFile, cfg.KeyFile) // HTTP fallback
	}

	// UDP dinleyiciyi başlat
	addr := net.UDPAddr{Port: cfg.DNSPort, IP: net.ParseIP(cfg.BindAddr)}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Printf("\n╔══ HATA ══════════════════════════════════\n")
		fmt.Printf("║ Port %d açılamadı: %v\n", cfg.DNSPort, err)
		if cfg.DNSPort == 53 {
			fmt.Println("║")
			fmt.Println("║ Port 53 için YÖNETİCİ yetkisi gerekir!")
			fmt.Println("║ Çözüm: PowerShell'i Yönetici olarak aç:")
			fmt.Println("║   Start-Process powershell -Verb RunAs")
			fmt.Println("║")
			fmt.Println("║ Veya config.json'da port'u değiştir:")
			fmt.Println("║   \"dnsPort\": 5353")
		}
		fmt.Println("╚═══════════════════════════════════════════")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("║")
	fmt.Println("║ 📡 Dinleyiciler:")
	fmt.Printf("║   UDP — %s:%d (DNS)\n", cfg.BindAddr, cfg.DNSPort)
	if certFile != "" {
		fmt.Printf("║   DoT — %s:%d (DNS-over-TLS)\n", cfg.BindAddr, cfg.DoTPort)
	}
	fmt.Printf("║   DoH — %s:%d (/dns-query)\n", cfg.BindAddr, cfg.DoHPort)
	if cfg.DashboardOn {
		fmt.Printf("║   Web — http://%s:%d (Dashboard)\n", cfg.BindAddr, cfg.DashboardPort)
	}
	fmt.Println("║")
	if cfg.DNSPort == 53 {
		fmt.Println("║ ✓ Sistem DNS'i olarak kullanılabilir!")
		fmt.Println("║   Ağ Ayarları → DNS → 127.0.0.1")
	} else {
		fmt.Printf("║ 💡 Sistem DNS'i olarak kullanmak için port'u 53 yapın\n")
		fmt.Printf("║    veya: setup.ps1 scriptini Yönetici olarak çalıştırın\n")
	}
	fmt.Println("║")
	fmt.Println("║ Bekleniyor...")
	fmt.Println()

	// Ana döngü — Her istek ayrı goroutine'de işlenir
	for {
		bufPtr := getBuffer()
		buf := *bufPtr

		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Okuma hatası:", err)
			putBuffer(bufPtr)
			continue
		}

		if n < 12 {
			putBuffer(bufPtr)
			continue
		}

		packetData := make([]byte, n)
		copy(packetData, buf[:n])
		putBuffer(bufPtr)

		go handleRequest(RequestContext{
			Data:   packetData,
			Size:   n,
			Source: source,
			Conn:   conn,
		})
	}
}
