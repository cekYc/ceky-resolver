package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// ==================== CANLI WEB DASHBOARD ====================

//go:embed web/index.html
var dashboardHTML string

// Global query log
var queryLog *QueryLog

// SSE bağlantı sayacı
var sseClients int64

// DashboardStats — JSON API yanıt yapısı
type DashboardStats struct {
	// Genel
	Uptime       string  `json:"uptime"`
	UptimeSec    float64 `json:"uptimeSec"`
	TotalQueries uint64  `json:"totalQueries"`
	CachedHits   uint64  `json:"cachedHits"`
	CacheMisses  uint64  `json:"cacheMisses"`
	CacheSize    int     `json:"cacheSize"`
	CacheHitRate float64 `json:"cacheHitRate"`

	// Reklam engelleme
	BlockedCount uint64  `json:"blockedCount"`
	BlockRules   int     `json:"blockRules"`
	BlockRate    float64 `json:"blockRate"`

	// Performans
	AvgResponseMs float64 `json:"avgResponseMs"`

	// Sunucu performansı
	ServerStats map[string]ServerStat `json:"serverStats"`

	// SSE
	LiveClients int64 `json:"liveClients"`
}

type ServerStat struct {
	AvgMs float64 `json:"avgMs"`
	Count int     `json:"count"`
}

// AppState — kontrol panelinin gösterdiği uygulama durumu
type AppState struct {
	Version    string `json:"version"`
	OS         string `json:"os"`
	Mode       string `json:"mode"`
	Admin      bool   `json:"admin"`
	Protection struct {
		Wanted    bool   `json:"wanted"`
		Active    bool   `json:"active"`
		Suspended bool   `json:"suspended"`
		Reason    string `json:"reason"`
	} `json:"protection"`
	Network struct {
		UDP       string    `json:"udp"`
		TCP       string    `json:"tcp"`
		Transport string    `json:"transport"`
		Checked   time.Time `json:"checked"`
	} `json:"network"`
	Listen           []string `json:"listen"`
	SystemDNS        []string `json:"systemDns"`
	ServiceInstalled bool     `json:"serviceInstalled"`
	Blocklist        struct {
		Enabled   bool      `json:"enabled"`
		Rules     int       `json:"rules"`
		Loading   bool      `json:"loading"`
		UpdatedAt time.Time `json:"updatedAt"`
		Allowlist []string  `json:"allowlist"`
	} `json:"blocklist"`
	DataDir string `json:"dataDir"`
}

// Dashboard HTTP sunucusunu başlat (yalnızca bu bilgisayardan erişilebilir)
func startDashboard(port int) *http.Server {
	mux := http.NewServeMux()

	// Ana sayfa — embedded HTML
	mux.HandleFunc("/", handleDashboardPage)

	// JSON API (salt okunur)
	mux.HandleFunc("/api/stats", handleAPIStats)
	mux.HandleFunc("/api/queries", handleAPIQueries)
	mux.HandleFunc("/api/timeseries", handleAPITimeSeries)
	mux.HandleFunc("/api/top-domains", handleAPITopDomains)
	mux.HandleFunc("/api/top-blocked", handleAPITopBlocked)
	mux.HandleFunc("/api/app/ping", handleAPIPing)
	mux.HandleFunc("/api/app/state", handleAPIState)

	// SSE — gerçek zamanlı akış
	mux.HandleFunc("/api/stream", handleSSEStream)

	// Uygulama kontrolleri (POST + token)
	mux.HandleFunc("/api/app/protection", handleAPIProtection)
	mux.HandleFunc("/api/app/blocklist", handleAPIBlocklist)
	mux.HandleFunc("/api/app/allow", handleAPIAllow)
	mux.HandleFunc("/api/app/flush", handleAPIFlush)
	mux.HandleFunc("/api/app/test", handleAPITest)
	mux.HandleFunc("/api/app/install", handleAPIInstall)
	mux.HandleFunc("/api/app/quit", handleAPIQuit)

	server := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      securePanel(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE için sınırsız
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("║ ⚠ Dashboard hatası: %v\n", err)
		}
	}()
	return server
}

// ==================== GÜVENLİK ====================

// allowedHost — DNS rebinding saldırılarına karşı yalnızca yerel Host başlıkları
func allowedHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch strings.Trim(host, "[]") {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// securePanel — başka sitelerin panele istek atıp ayarları değiştirmesini (CSRF)
// ve sorgu geçmişini okumasını engeller
func securePanel(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if app == nil || r.Header.Get("X-Ceky-Token") != app.token {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// readJSON — POST gövdesini oku (en fazla 4 KB)
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST gerekli")
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if len(body) > 0 && v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			writeError(w, http.StatusBadRequest, "geçersiz istek")
			return false
		}
	}
	return true
}

// ==================== API HANDLER'LAR ====================

func collectStats() DashboardStats {
	metrics.mu.Lock()
	totalQ := metrics.totalQueries
	avgMs := float64(0)
	if totalQ > 0 {
		avgMs = metrics.totalResolveMs / float64(totalQ)
	}
	serverStats := make(map[string]ServerStat)
	for k, v := range metrics.serverAvg {
		if v.count > 0 {
			serverStats[k] = ServerStat{
				AvgMs: v.totalMs / float64(v.count),
				Count: v.count,
			}
		}
	}
	metrics.mu.Unlock()

	cacheSize, cacheHits, cacheMisses := resolver.cache.Stats()
	hitRate := float64(0)
	if cacheHits+cacheMisses > 0 {
		hitRate = float64(cacheHits) / float64(cacheHits+cacheMisses) * 100
	}

	blockedCount := blocker.BlockedCount()
	blockRules := blocker.Size()
	blockRate := float64(0)
	if totalQ > 0 {
		blockRate = float64(blockedCount) / float64(totalQ) * 100
	}

	uptime := queryLog.Uptime()

	return DashboardStats{
		Uptime:        formatUptime(uptime),
		UptimeSec:     uptime.Seconds(),
		TotalQueries:  totalQ,
		CachedHits:    cacheHits,
		CacheMisses:   cacheMisses,
		CacheSize:     cacheSize,
		CacheHitRate:  hitRate,
		BlockedCount:  blockedCount,
		BlockRules:    blockRules,
		BlockRate:     blockRate,
		AvgResponseMs: avgMs,
		ServerStats:   serverStats,
		LiveClients:   atomic.LoadInt64(&sseClients),
	}
}

func collectState() AppState {
	var s AppState
	s.Version = version
	s.OS = runtime.GOOS
	s.Admin = isAdmin()
	s.DataDir = dataDir
	s.Blocklist.Rules = blocker.Size()
	s.Blocklist.Loading = blocker.loading.Load()
	s.Blocklist.UpdatedAt = blocker.LoadedAt()
	s.Blocklist.Allowlist = blocker.Allowlist()
	s.Network.Transport = "udp"
	if resolver.forceTCP.Load() {
		s.Network.Transport = "tcp"
	}

	app.mu.Lock()
	defer app.mu.Unlock()
	s.Mode = app.mode
	s.Protection.Wanted = cfg.AutoEnable
	s.Protection.Active = app.sysActive
	s.Protection.Suspended = app.suspended
	s.Protection.Reason = app.reason
	s.Network.UDP = app.probe.UDP
	s.Network.TCP = app.probe.TCP
	s.Network.Checked = app.probe.Checked
	s.Listen = app.dnsAddrs
	s.SystemDNS = app.currentDNS
	s.ServiceInstalled = app.installed
	s.Blocklist.Enabled = cfg.BlocklistEnabled
	return s
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, collectStats())
}

func handleAPIQueries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, queryLog.Recent(50))
}

func handleAPITimeSeries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, queryLog.TimeSeries())
}

func handleAPITopDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, queryLog.TopDomains(10))
}

func handleAPITopBlocked(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, queryLog.TopBlocked(10))
}

// handleAPIPing — "zaten çalışıyor mu?" kontrolü için
func handleAPIPing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"app": "ceky-resolver", "version": version})
}

func handleAPIState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, collectState())
}

func handleAPIProtection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	app.setProtection(req.Enabled)
	writeJSON(w, collectState())
}

func handleAPIBlocklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	app.setBlocklist(req.Enabled)
	writeJSON(w, collectState())
}

func handleAPIAllow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain  string `json:"domain"`
		Allowed bool   `json:"allowed"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := blocker.Allow(req.Domain, req.Allowed); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resolver.cache.Flush() // Engelli yanıtlar istemci önbelleğinden de kısa sürede düşer (TTL 60)
	writeJSON(w, collectState())
}

func handleAPIFlush(w http.ResponseWriter, r *http.Request) {
	if !readJSON(w, r, nil) {
		return
	}
	resolver.FlushCache()
	flushOSCache()
	writeJSON(w, map[string]bool{"ok": true})
}

// handleAPITest — bir alan adını önbelleksiz, kökten itibaren adım adım çöz
func handleAPITest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	domain := normalizeName(strings.TrimSpace(req.Domain))
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	if i := strings.IndexAny(domain, "/:"); i >= 0 {
		domain = domain[:i]
	}
	if domain == "" {
		domain = "example.com"
	}
	if len(domain) > 253 || strings.ContainsAny(domain, " \\*") {
		writeError(w, http.StatusBadRequest, "geçersiz alan adı")
		return
	}

	start := time.Now()
	steps, ans := resolver.Trace(domain, typeA)
	var answers []string
	for _, rr := range ans.Records {
		switch {
		case recordIP(rr) != "":
			answers = append(answers, recordIP(rr))
		case rr.Type == typeCNAME:
			answers = append(answers, "→ "+rdataName(rr.RData))
		}
	}
	rcodes := map[int]string{rcodeSuccess: "NOERROR", rcodeServFail: "SERVFAIL", rcodeNXDomain: "NXDOMAIN"}
	writeJSON(w, map[string]any{
		"domain":  domain,
		"rcode":   rcodes[ans.Rcode],
		"answers": answers,
		"steps":   steps,
		"ms":      float64(time.Since(start).Microseconds()) / 1000,
	})
}

func handleAPIInstall(w http.ResponseWriter, r *http.Request) {
	if !readJSON(w, r, nil) {
		return
	}
	if err := app.installFromPanel(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func handleAPIQuit(w http.ResponseWriter, r *http.Request) {
	if !readJSON(w, r, nil) {
		return
	}
	if app.mode != "app" {
		writeError(w, http.StatusBadRequest, "servis modunda çıkış yok — 'ceky-resolver uninstall' kullanın")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	go func() {
		time.Sleep(300 * time.Millisecond)
		app.requestStop()
	}()
}

// ==================== SSE STREAM ====================

func handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	atomic.AddInt64(&sseClients, 1)
	defer atomic.AddInt64(&sseClients, -1)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	for tick := 0; ; tick++ {
		if tick%2 == 0 {
			state, _ := json.Marshal(collectState())
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", state)
		}

		stats := collectStats()
		data, _ := json.Marshal(stats)
		fmt.Fprintf(w, "event: stats\ndata: %s\n\n", data)

		// Son 50 sorgu
		recent := queryLog.Recent(50)
		rData, _ := json.Marshal(recent)
		fmt.Fprintf(w, "event: queries\ndata: %s\n\n", rData)

		flusher.Flush()

		select {
		case <-ctx.Done():
			return
		case <-app.stop:
			return
		case <-ticker.C:
		}
	}
}

// ==================== YARDIMCI ====================

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dg %ds %dd %dsn", days, hours, mins, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%ds %dd %dsn", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dd %dsn", mins, secs)
	}
	return fmt.Sprintf("%dsn", secs)
}

// ==================== EMBEDDED HTML DASHBOARD ====================

func handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
	page := strings.Replace(dashboardHTML, "{{CEKY_TOKEN}}", app.token, 1)
	page = strings.Replace(page, "{{CEKY_VERSION}}", version, -1)
	w.Write([]byte(page))
}
