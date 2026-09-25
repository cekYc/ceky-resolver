package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ==================== SORGU KAYIT SİSTEMİ (QUERY LOG) ====================

// QueryLogEntry — Tek bir DNS sorgusunun tüm detayları
type QueryLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Domain     string    `json:"domain"`
	QType      uint16    `json:"qtype"`
	QTypeName  string    `json:"qtypeName"`
	ResponseMs float64   `json:"responseMs"`
	Status     string    `json:"status"` // "resolved", "blocked", "cached", "nxdomain", "error", "local"
	AnswerIP   string    `json:"answerIp"`
	Source     string    `json:"source"` // "udp", "dot", "doh"
	ClientIP   string    `json:"clientIp"`
}

// TimeSeriesPoint — Zaman serisi veri noktası (grafik için)
type TimeSeriesPoint struct {
	Timestamp int64   `json:"t"` // Unix epoch saniye
	Queries   int     `json:"q"` // O saniyelik toplam sorgu
	Blocked   int     `json:"b"` // O saniyelik engellenen
	Cached    int     `json:"c"` // O saniyelik önbellekten
	AvgMs     float64 `json:"m"` // O saniyelik ort. yanıt ms
}

// TopDomain — En çok sorgulanan/engellenen domain
type TopDomain struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// QueryLog — Dairesel buffer ile son N sorguyu tutan yapı
type QueryLog struct {
	mu         sync.RWMutex
	entries    []QueryLogEntry
	maxSize    int
	writeIdx   int
	totalCount int

	// Zaman serisi — son 5 dakikalık saniye bazlı veri (300 nokta)
	timeSeries    []TimeSeriesPoint
	tsMaxSize     int
	tsWriteIdx    int
	currentSecond int64
	currentPoint  TimeSeriesPoint

	// Domain sayaçları
	domainCounts  map[string]int
	blockedCounts map[string]int

	// Başlangıç zamanı
	startedAt time.Time
}

// Yeni QueryLog oluştur
func newQueryLog(maxEntries int) *QueryLog {
	return &QueryLog{
		entries:       make([]QueryLogEntry, maxEntries),
		maxSize:       maxEntries,
		timeSeries:    make([]TimeSeriesPoint, 300), // 5 dakikalık grafik
		tsMaxSize:     300,
		domainCounts:  make(map[string]int),
		blockedCounts: make(map[string]int),
		startedAt:     time.Now(),
	}
}

// Sorgu kaydı ekle
func (ql *QueryLog) Add(entry QueryLogEntry) {
	ql.mu.Lock()
	defer ql.mu.Unlock()

	// Dairesel buffer'a yaz
	ql.entries[ql.writeIdx] = entry
	ql.writeIdx = (ql.writeIdx + 1) % ql.maxSize
	ql.totalCount++

	// Domain sayacı (bellek sınırlı: çok büyürse tek seferlik domain'ler atılır)
	if len(ql.domainCounts) > maxTrackedDomains {
		pruneCounts(ql.domainCounts)
	}
	if len(ql.blockedCounts) > maxTrackedDomains {
		pruneCounts(ql.blockedCounts)
	}
	ql.domainCounts[entry.Domain]++
	if entry.Status == "blocked" {
		ql.blockedCounts[entry.Domain]++
	}

	// Zaman serisi güncelle
	now := time.Now().Unix()
	if ql.currentSecond == now {
		// Aynı saniye içinde — güncelle
		ql.currentPoint.Queries++
		if entry.Status == "blocked" {
			ql.currentPoint.Blocked++
		}
		if entry.Status == "cached" {
			ql.currentPoint.Cached++
		}
		// Ort. ms (kayan ortalama)
		n := float64(ql.currentPoint.Queries)
		ql.currentPoint.AvgMs = ql.currentPoint.AvgMs*(n-1)/n + entry.ResponseMs/n
	} else {
		// Yeni saniye başladı — öncekini kaydet
		if ql.currentSecond > 0 {
			ql.timeSeries[ql.tsWriteIdx] = ql.currentPoint
			ql.tsWriteIdx = (ql.tsWriteIdx + 1) % ql.tsMaxSize
		}
		ql.currentSecond = now
		ql.currentPoint = TimeSeriesPoint{
			Timestamp: now,
			Queries:   1,
			AvgMs:     entry.ResponseMs,
		}
		if entry.Status == "blocked" {
			ql.currentPoint.Blocked = 1
		}
		if entry.Status == "cached" {
			ql.currentPoint.Cached = 1
		}
	}
}

const maxTrackedDomains = 20000

func pruneCounts(m map[string]int) {
	for k, v := range m {
		if v <= 1 {
			delete(m, k)
		}
	}
	if len(m) > maxTrackedDomains { // Hâlâ büyükse sıfırla
		clear(m)
	}
}

// Son N sorguyu döndür (en yeniden en eskiye)
func (ql *QueryLog) Recent(n int) []QueryLogEntry {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	count := ql.totalCount
	if count > ql.maxSize {
		count = ql.maxSize
	}
	if n > count {
		n = count
	}

	result := make([]QueryLogEntry, 0, n)
	idx := (ql.writeIdx - 1 + ql.maxSize) % ql.maxSize
	for i := 0; i < n; i++ {
		entry := ql.entries[idx]
		if entry.Timestamp.IsZero() {
			break
		}
		result = append(result, entry)
		idx = (idx - 1 + ql.maxSize) % ql.maxSize
	}
	return result
}

// Zaman serisi verilerini döndür (grafik için)
func (ql *QueryLog) TimeSeries() []TimeSeriesPoint {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	// Aktif noktayı da dahil et
	var result []TimeSeriesPoint
	now := time.Now().Unix()
	cutoff := now - int64(ql.tsMaxSize)

	// Tüm noktaları tara, geçerli olanları al
	for i := 0; i < ql.tsMaxSize; i++ {
		pt := ql.timeSeries[i]
		if pt.Timestamp > cutoff && pt.Timestamp > 0 {
			result = append(result, pt)
		}
	}

	// Aktif saniyeyi de ekle
	if ql.currentSecond > cutoff && ql.currentSecond > 0 {
		result = append(result, ql.currentPoint)
	}

	// Zamana göre sırala
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp < result[j].Timestamp })

	return result
}

// En çok sorgulanan domain'ler
func (ql *QueryLog) TopDomains(n int) []TopDomain {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	return topN(ql.domainCounts, n)
}

// En çok engellenen domain'ler
func (ql *QueryLog) TopBlocked(n int) []TopDomain {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	return topN(ql.blockedCounts, n)
}

// Map'ten en yüksek N tanesini al
func topN(m map[string]int, n int) []TopDomain {
	type kv struct {
		key   string
		value int
	}
	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	// Selection sort (küçük N için yeterli)
	for i := 0; i < len(sorted) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].value > sorted[maxIdx].value {
				maxIdx = j
			}
		}
		sorted[i], sorted[maxIdx] = sorted[maxIdx], sorted[i]
	}

	limit := n
	if limit > len(sorted) {
		limit = len(sorted)
	}
	result := make([]TopDomain, limit)
	for i := 0; i < limit; i++ {
		result[i] = TopDomain{Domain: sorted[i].key, Count: sorted[i].value}
	}
	return result
}

// Uptime döndür
func (ql *QueryLog) Uptime() time.Duration {
	return time.Since(ql.startedAt)
}

// QType numaraları → isimler
var qtypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	41:  "OPT",
	64:  "SVCB",
	65:  "HTTPS",
	255: "ANY",
}

// QType numarasını isme çevir
func qtypeName(qtype uint16) string {
	if name, ok := qtypeNames[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}
