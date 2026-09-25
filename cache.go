package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ==================== ÖNBELLEK (CACHE) ====================

const (
	minCacheTTL   = 10    // saniye — çok kısa TTL'ler bu değere yükseltilir
	maxCacheTTL   = 86400 // saniye — 1 gün
	minNegTTL     = 30    // NXDOMAIN / NODATA için alt sınır
	maxNegTTL     = 3600  // NXDOMAIN / NODATA için üst sınır
	servFailTTL   = 5     // Hatalar kısa süre önbellekte tutulur (fırtınayı önler)
	staleWindow   = 24 * time.Hour
	staleReplyTTL = 30 // Bayat yanıtlarda istemciye bildirilen TTL
)

// CacheEntry — Önbellekteki bir çözümleme sonucu
type CacheEntry struct {
	Answer    Answer
	ExpiresAt time.Time
	CachedAt  time.Time
}

// DNSCache — Goroutine-safe DNS önbelleği (olumlu + olumsuz yanıtlar).
// Süresi dolan kayıtlar bir gün boyunca "bayat" olarak saklanır; yukarı akış
// sunuculara ulaşılamazsa bunlar sunulur (RFC 8767 — internet kesilmesin diye).
type DNSCache struct {
	mu         sync.Mutex
	entries    map[string]CacheEntry
	maxEntries int
	disabled   bool // cacheEnabled=false — hiçbir şey saklanmaz
	hits       uint64
	misses     uint64
}

// Yeni cache oluştur (maxEntries <= 0 → sınırsız)
func newDNSCache(maxEntries int) *DNSCache {
	return &DNSCache{
		entries:    make(map[string]CacheEntry),
		maxEntries: maxEntries,
	}
}

// Cache anahtarı oluştur (domain + qtype)
func cacheKey(domain string, qtype uint16) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(domain), qtype)
}

// TTL'leri geçen süre kadar azalt (istemciye doğru TTL göstermek için)
func agedRecords(records []DNSRecord, elapsed uint32, floor uint32) []DNSRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]DNSRecord, len(records))
	copy(out, records)
	for i := range out {
		if out[i].TTL > elapsed+floor {
			out[i].TTL -= elapsed
		} else {
			out[i].TTL = floor
		}
	}
	return out
}

// Cache'den oku — yalnızca süresi dolmamış kayıtlar
func (c *DNSCache) Get(domain string, qtype uint16) (Answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[cacheKey(domain, qtype)]
	if !ok || c.disabled || time.Now().After(entry.ExpiresAt) {
		c.misses++
		return Answer{}, false
	}
	c.hits++

	elapsed := uint32(time.Since(entry.CachedAt).Seconds())
	ans := entry.Answer
	ans.Records = agedRecords(ans.Records, elapsed, 1)
	ans.Authority = agedRecords(ans.Authority, elapsed, 1)
	ans.Cached = true
	return ans, true
}

// GetStale — süresi dolmuş (ama bayatlık penceresi içindeki) olumlu yanıt
func (c *DNSCache) GetStale(domain string, qtype uint16) (Answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[cacheKey(domain, qtype)]
	if !ok || entry.Answer.Rcode != rcodeSuccess || len(entry.Answer.Records) == 0 ||
		time.Since(entry.ExpiresAt) > staleWindow {
		return Answer{}, false
	}
	ans := entry.Answer
	ans.Records = agedRecords(ans.Records, ^uint32(0)/2, staleReplyTTL)
	ans.Authority = nil
	ans.Cached = true
	return ans, true
}

// answerTTL — bir sonucun önbellekte kalacağı süre
func answerTTL(ans Answer) uint32 {
	switch {
	case ans.Rcode == rcodeServFail:
		return servFailTTL
	case len(ans.Records) > 0 && ans.Rcode == rcodeSuccess:
		ttl := ans.Records[0].TTL
		for _, r := range ans.Records {
			ttl = min(ttl, r.TTL)
		}
		return min(max(ttl, minCacheTTL), maxCacheTTL)
	default: // NXDOMAIN / NODATA — SOA'dan (RFC 2308)
		ttl := uint32(minNegTTL)
		for _, r := range ans.Authority {
			if r.Type == typeSOA {
				ttl = soaMinimum(r)
			}
		}
		return min(max(ttl, minNegTTL), maxNegTTL)
	}
}

// Cache'e yaz — TTL'e göre son kullanma tarihi hesapla
func (c *DNSCache) Set(domain string, qtype uint16, ans Answer) {
	if c.disabled {
		return
	}
	ttl := answerTTL(ans)
	now := time.Now()
	ans.Cached = false

	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(domain, qtype)
	if ans.Rcode == rcodeServFail {
		// Hata, eldeki (bayat da olsa) iyi yanıtın üzerine yazılmasın
		if old, ok := c.entries[key]; ok && old.Answer.Rcode == rcodeSuccess {
			return
		}
	}
	if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		c.evictLocked(now)
	}
	c.entries[key] = CacheEntry{
		Answer:    ans,
		CachedAt:  now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
	}
}

// evictLocked — önbellek dolunca önce süresi dolanları, yetmezse rastgele %10'u at
func (c *DNSCache) evictLocked(now time.Time) {
	for key, e := range c.entries {
		if now.After(e.ExpiresAt) {
			delete(c.entries, key)
		}
	}
	if len(c.entries) < c.maxEntries {
		return
	}
	drop := c.maxEntries/10 + 1
	for key := range c.entries { // map sırası rastgeledir
		delete(c.entries, key)
		if drop--; drop == 0 {
			break
		}
	}
}

// Flush — tüm önbelleği temizle
func (c *DNSCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]CacheEntry)
}

// Cache istatistikleri
func (c *DNSCache) Stats() (size int, hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.hits, c.misses
}

// Bayatlık penceresini de aşmış kayıtları temizle
func (c *DNSCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleaned := 0
	cutoff := time.Now().Add(-staleWindow)
	for key, entry := range c.entries {
		if entry.ExpiresAt.Before(cutoff) {
			delete(c.entries, key)
			cleaned++
		}
	}
	return cleaned
}

// ==================== DELEGASYON ÖNBELLEĞİ ====================

// zoneCache — "com → a.gtld-servers.net IP'leri" gibi bölge kesimlerini tutar.
// Böylece her sorguda kök sunucudan başlamak gerekmez.
type zoneCache struct {
	mu sync.RWMutex
	m  map[string]zoneEntry
}

type zoneEntry struct {
	servers []string
	expires time.Time
}

func newZoneCache() *zoneCache {
	return &zoneCache{m: make(map[string]zoneEntry)}
}

// closest — isme en yakın bilinen bölge kesimini bul ("" = kök, sunucu listesi boş)
func (z *zoneCache) closest(name string) (string, []string) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	now := time.Now()
	for n := name; n != ""; n = parentName(n) {
		if e, ok := z.m[n]; ok && now.Before(e.expires) {
			return n, append([]string(nil), e.servers...)
		}
	}
	return "", nil
}

func (z *zoneCache) put(zone string, servers []string, ttl uint32) {
	if zone == "" || len(servers) == 0 {
		return
	}
	ttl = min(max(ttl, 60), maxCacheTTL)
	z.mu.Lock()
	defer z.mu.Unlock()
	if len(z.m) > 20000 { // Kaba üst sınır
		z.m = make(map[string]zoneEntry)
	}
	z.m[zone] = zoneEntry{servers: servers, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
}

func (z *zoneCache) remove(zone string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.m, zone)
}

func (z *zoneCache) flush() {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.m = make(map[string]zoneEntry)
}

// ==================== TEKİL UÇUŞ (SINGLEFLIGHT) ====================

// flightGroup — aynı anda gelen özdeş sorguları tek çözümlemede birleştirir
type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	ans Answer
}

func (g *flightGroup) do(key string, fn func() Answer) Answer {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*flightCall)
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.ans
	}
	c := &flightCall{ans: Answer{Rcode: rcodeServFail}} // fn paniklerse bekleyenler SERVFAIL alır
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		c.wg.Done()
	}()
	c.ans = fn()
	return c.ans
}
