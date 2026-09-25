package main

import (
	"fmt"
	"sync"
	"time"
)

// ==================== PERFORMANS METRİKLERİ ====================

// QueryMetric — Tek bir yukarı akış sorgusunun ölçüm verisi
type QueryMetric struct {
	ServerIP   string
	ServerType string // "root", "tld", "auth"
	Domain     string
	Duration   time.Duration
	Protocol   string // "udp", "tcp"
}

type serverAvgEntry struct {
	totalMs float64
	count   int
}

// ResolverMetrics — Tüm ölçümleri toplayan yapı (sabit bellek kullanımı)
type ResolverMetrics struct {
	mu             sync.Mutex
	totalQueries   uint64
	cachedQueries  uint64
	totalResolveMs float64
	serverAvg      map[string]serverAvgEntry
}

func newResolverMetrics() *ResolverMetrics {
	return &ResolverMetrics{serverAvg: make(map[string]serverAvgEntry)}
}

// Sorgu metriği kaydet — sunucu türüne göre ortalama hesapla
func (m *ResolverMetrics) RecordQuery(metric QueryMetric) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.serverAvg[metric.ServerType]
	entry.totalMs += float64(metric.Duration.Microseconds()) / 1000
	entry.count++
	m.serverAvg[metric.ServerType] = entry
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
	m.totalResolveMs += float64(d.Microseconds()) / 1000
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
