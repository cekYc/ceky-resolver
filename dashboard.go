package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// ==================== CANLI WEB DASHBOARD ====================

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

// Dashboard HTTP sunucusunu başlat
func startDashboard(port int) {
	mux := http.NewServeMux()

	// Ana sayfa — embedded HTML
	mux.HandleFunc("/", handleDashboardPage)

	// JSON API
	mux.HandleFunc("/api/stats", handleAPIStats)
	mux.HandleFunc("/api/queries", handleAPIQueries)
	mux.HandleFunc("/api/timeseries", handleAPITimeSeries)
	mux.HandleFunc("/api/top-domains", handleAPITopDomains)
	mux.HandleFunc("/api/top-blocked", handleAPITopBlocked)

	// SSE — gerçek zamanlı akış
	mux.HandleFunc("/api/stream", handleSSEStream)

	server := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE için sınırsız
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("║ ⚠ Dashboard hatası: %v\n", err)
		}
	}()
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

	cacheSize, cacheHits, cacheMisses := dnsCache.Stats()
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

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(collectStats())
}

func handleAPIQueries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	entries := queryLog.Recent(50)
	json.NewEncoder(w).Encode(entries)
}

func handleAPITimeSeries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	ts := queryLog.TimeSeries()
	json.NewEncoder(w).Encode(ts)
}

func handleAPITopDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(queryLog.TopDomains(10))
}

func handleAPITopBlocked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(queryLog.TopBlocked(10))
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	atomic.AddInt64(&sseClients, 1)
	defer atomic.AddInt64(&sseClients, -1)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := collectStats()
			data, _ := json.Marshal(stats)
			fmt.Fprintf(w, "event: stats\ndata: %s\n\n", data)

			// Son 5 sorgu
			recent := queryLog.Recent(5)
			rData, _ := json.Marshal(recent)
			fmt.Fprintf(w, "event: queries\ndata: %s\n\n", rData)

			flusher.Flush()
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
	w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ceky Resolver — Canlı Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0e17;--card:#111827;--card2:#1a2332;--border:#1e2d3d;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --accent:#3b82f6;--accent2:#6366f1;--green:#10b981;--red:#ef4444;
  --orange:#f59e0b;--cyan:#06b6d4;--pink:#ec4899;
  --glow:0 0 20px rgba(59,130,246,0.15);
}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);overflow-x:hidden;min-height:100vh}

/* Header */
.header{background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;backdrop-filter:blur(10px)}
.header-left{display:flex;align-items:center;gap:12px}
.logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:bold;color:#fff;box-shadow:0 0 20px rgba(99,102,241,0.3)}
.header h1{font-size:20px;font-weight:700;background:linear-gradient(135deg,#fff,var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .version{font-size:11px;color:var(--text3);background:var(--card);padding:2px 8px;border-radius:4px;border:1px solid var(--border)}
.header-right{display:flex;align-items:center;gap:16px}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;display:inline-block}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(16,185,129,0.5)}50%{opacity:.7;box-shadow:0 0 0 8px rgba(16,185,129,0)}}
.uptime{font-size:12px;color:var(--text2);font-family:'Cascadia Code','Fira Code',monospace}

/* Grid */
.container{max-width:1400px;margin:0 auto;padding:20px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.main-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px}
.bottom-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}

/* Cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden;transition:border-color .3s,box-shadow .3s}
.card:hover{border-color:rgba(59,130,246,0.3);box-shadow:var(--glow)}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0;transition:opacity .3s}
.card:hover::before{opacity:1}
.card-title{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:12px;display:flex;align-items:center;gap:6px}
.card-title .icon{font-size:14px}

/* Stat Cards */
.stat-card{text-align:center}
.stat-value{font-size:36px;font-weight:800;line-height:1;margin-bottom:4px;font-family:'Cascadia Code','Fira Code',monospace}
.stat-sub{font-size:12px;color:var(--text2)}
.stat-value.blue{color:var(--accent)}
.stat-value.green{color:var(--green)}
.stat-value.red{color:var(--red)}
.stat-value.orange{color:var(--orange)}
.stat-value.cyan{color:var(--cyan)}
.stat-value.pink{color:var(--pink)}

/* Chart */
.chart-container{position:relative;height:200px;margin-top:8px}
#qpsChart{width:100%;height:100%;display:block}

/* Query Table */
.query-table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px}
.query-table th{text-align:left;padding:8px 10px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:1px;font-size:10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--card)}
.query-table td{padding:6px 10px;border-bottom:1px solid rgba(30,45,61,0.5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
.query-table tr{transition:background .15s}
.query-table tr:hover td{background:rgba(59,130,246,0.05)}
.query-scroll{max-height:340px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.query-scroll::-webkit-scrollbar{width:4px}
.query-scroll::-webkit-scrollbar-track{background:transparent}
.query-scroll::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

/* Status badges */
.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.badge-resolved{background:rgba(16,185,129,0.15);color:var(--green)}
.badge-blocked{background:rgba(239,68,68,0.15);color:var(--red)}
.badge-cached{background:rgba(6,182,212,0.15);color:var(--cyan)}
.badge-nxdomain{background:rgba(245,158,11,0.15);color:var(--orange)}
.badge-error{background:rgba(239,68,68,0.1);color:#f87171}

/* Progress bars */
.progress-bar{height:6px;background:var(--card2);border-radius:3px;overflow:hidden;margin-top:8px}
.progress-fill{height:100%;border-radius:3px;transition:width .8s cubic-bezier(0.4,0,0.2,1)}
.progress-fill.green{background:linear-gradient(90deg,var(--green),#34d399)}
.progress-fill.red{background:linear-gradient(90deg,var(--red),#f87171)}
.progress-fill.blue{background:linear-gradient(90deg,var(--accent),#60a5fa)}

/* Top domains list */
.domain-list{list-style:none}
.domain-item{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid rgba(30,45,61,0.3);font-size:12px}
.domain-item:last-child{border:none}
.domain-name{color:var(--text);font-family:'Cascadia Code','Fira Code',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px}
.domain-count{color:var(--text2);font-weight:600;font-size:11px;background:var(--card2);padding:2px 8px;border-radius:4px;min-width:36px;text-align:center}

/* Gauge */
.gauge-container{display:flex;justify-content:center;margin:10px 0}
.gauge{position:relative;width:120px;height:60px;overflow:hidden}
.gauge-bg{position:absolute;width:120px;height:120px;border-radius:50%;border:10px solid var(--card2);border-bottom-color:transparent;border-left-color:transparent;transform:rotate(225deg)}
.gauge-fill{position:absolute;width:120px;height:120px;border-radius:50%;border:10px solid transparent;border-top-color:var(--green);border-right-color:var(--green);transform:rotate(225deg);transition:transform .8s cubic-bezier(0.4,0,0.2,1)}
.gauge-value{position:absolute;bottom:0;left:50%;transform:translateX(-50%);font-size:20px;font-weight:800;font-family:'Cascadia Code','Fira Code',monospace}

/* Server stats */
.server-stat{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(30,45,61,0.3)}
.server-stat:last-child{border:none}
.server-label{font-size:12px;color:var(--text2)}
.server-value{font-family:'Cascadia Code','Fira Code',monospace;font-size:13px;font-weight:600}
.server-value.fast{color:var(--green)}
.server-value.medium{color:var(--orange)}
.server-value.slow{color:var(--red)}

/* Animations */
@keyframes slideIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
@keyframes countUp{from{opacity:0;transform:scale(0.8)}to{opacity:1;transform:scale(1)}}
.card{animation:slideIn .4s ease-out}
.fade-in{animation:slideIn .3s ease-out}

/* Responsive */
@media(max-width:1200px){.main-grid{grid-template-columns:1fr}.bottom-grid{grid-template-columns:1fr 1fr}}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}.bottom-grid{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- HEADER -->
<header class="header">
  <div class="header-left">
    <div class="logo">C</div>
    <h1>Ceky Resolver</h1>
    <span class="version">v3.0</span>
  </div>
  <div class="header-right">
    <span class="live-dot"></span>
    <span class="uptime" id="uptime">00:00:00</span>
  </div>
</header>

<div class="container">

<!-- STAT CARDS -->
<div class="stats-grid">
  <div class="card stat-card">
    <div class="card-title"><span class="icon">📊</span> Toplam Sorgu</div>
    <div class="stat-value blue" id="totalQueries">0</div>
    <div class="stat-sub" id="qps">0 sorgu/sn</div>
  </div>
  <div class="card stat-card">
    <div class="card-title"><span class="icon">⚡</span> Ort. Yanit</div>
    <div class="stat-value cyan" id="avgMs">0</div>
    <div class="stat-sub">milisaniye</div>
  </div>
  <div class="card stat-card">
    <div class="card-title"><span class="icon">🛡️</span> Engellenen</div>
    <div class="stat-value red" id="blockedCount">0</div>
    <div class="stat-sub" id="blockRate">%0 engelleme orani</div>
  </div>
  <div class="card stat-card">
    <div class="card-title"><span class="icon">💾</span> Onbellek Isabet</div>
    <div class="stat-value green" id="cacheHitRate">0%</div>
    <div class="stat-sub" id="cacheSub">0 kayit</div>
  </div>
</div>

<!-- MAIN GRID: Chart + Queries -->
<div class="main-grid">
  <!-- Chart -->
  <div class="card">
    <div class="card-title"><span class="icon">📈</span> Sorgu Trafigi (Canli)</div>
    <div class="chart-container">
      <canvas id="qpsChart"></canvas>
    </div>
  </div>
  <!-- Server Performance -->
  <div class="card">
    <div class="card-title"><span class="icon">🌐</span> Sunucu Performansi</div>
    <div id="serverStats">
      <div class="server-stat"><span class="server-label">Kok Sunucu</span><span class="server-value" id="rootMs">—</span></div>
      <div class="server-stat"><span class="server-label">TLD Sunucu</span><span class="server-value" id="tldMs">—</span></div>
      <div class="server-stat"><span class="server-label">Yetkili Sunucu</span><span class="server-value" id="authMs">—</span></div>
    </div>

    <div style="margin-top:20px">
      <div class="card-title"><span class="icon">📊</span> Onbellek Durumu</div>
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
        <span style="color:var(--text2)">Isabet Orani</span>
        <span style="color:var(--green);font-weight:600" id="hitRateLabel">0%</span>
      </div>
      <div class="progress-bar"><div class="progress-fill green" id="hitRateBar" style="width:0%"></div></div>

      <div style="display:flex;justify-content:space-between;font-size:12px;margin-top:12px;margin-bottom:4px">
        <span style="color:var(--text2)">Engelleme Orani</span>
        <span style="color:var(--red);font-weight:600" id="blockRateLabel">0%</span>
      </div>
      <div class="progress-bar"><div class="progress-fill red" id="blockRateBar" style="width:0%"></div></div>

      <div style="margin-top:16px;display:flex;gap:16px;font-size:11px;color:var(--text3)">
        <div>🧩 Kural: <span style="color:var(--text)" id="blockRules">0</span></div>
        <div>📦 Onbellek: <span style="color:var(--text)" id="cacheEntries">0</span></div>
        <div>👥 Canli: <span style="color:var(--text)" id="liveClients">0</span></div>
      </div>
    </div>
  </div>
</div>

<!-- BOTTOM GRID -->
<div class="bottom-grid">
  <!-- Recent Queries -->
  <div class="card" style="grid-column:span 2">
    <div class="card-title"><span class="icon">📋</span> Son Sorgular (Canli)</div>
    <div class="query-scroll">
      <table class="query-table">
        <thead><tr><th>Zaman</th><th>Domain</th><th>Tip</th><th>Durum</th><th>Yanit</th><th>Sure</th></tr></thead>
        <tbody id="queryBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Top Domains -->
  <div class="card">
    <div class="card-title"><span class="icon">🏆</span> En Cok Sorgulanan</div>
    <ul class="domain-list" id="topDomains"></ul>

    <div class="card-title" style="margin-top:20px"><span class="icon">🚫</span> En Cok Engellenen</div>
    <ul class="domain-list" id="topBlocked"></ul>
  </div>
</div>

</div>

<script>
// ==================== DASHBOARD JS ====================

// Animasyonlu sayaç
function animateValue(el, newVal, decimals = 0) {
  const current = parseFloat(el.textContent.replace(/[^0-9.]/g,'')) || 0;
  if (Math.abs(current - newVal) < 0.01) return;
  const steps = 20;
  const increment = (newVal - current) / steps;
  let step = 0;
  function tick() {
    step++;
    const val = current + increment * step;
    if (decimals > 0) {
      el.textContent = val.toFixed(decimals);
    } else {
      el.textContent = Math.round(val).toLocaleString('tr-TR');
    }
    if (step < steps) requestAnimationFrame(tick);
    else {
      if (decimals > 0) el.textContent = newVal.toFixed(decimals);
      else el.textContent = newVal.toLocaleString('tr-TR');
    }
  }
  tick();
}

// QPS chart state
const chartData = { points: [], maxPoints: 60 };

function drawChart() {
  const canvas = document.getElementById('qpsChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width = rect.width + 'px';
  canvas.style.height = rect.height + 'px';
  ctx.scale(dpr, dpr);

  const W = rect.width, H = rect.height;
  const pad = { top: 10, right: 10, bottom: 24, left: 40 };
  const cW = W - pad.left - pad.right;
  const cH = H - pad.top - pad.bottom;

  // Clear
  ctx.clearRect(0, 0, W, H);

  const pts = chartData.points;
  if (pts.length < 2) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px "Segoe UI"';
    ctx.textAlign = 'center';
    ctx.fillText('Veri bekleniyor...', W/2, H/2);
    return;
  }

  // Max value
  let maxQ = 1;
  for (const p of pts) { if (p.q > maxQ) maxQ = p.q; }
  maxQ = Math.ceil(maxQ * 1.2) || 1;

  // Grid lines
  ctx.strokeStyle = 'rgba(30,45,61,0.6)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (cH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(pad.left + cW, y);
    ctx.stroke();
    ctx.fillStyle = '#64748b';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxQ - (maxQ/4)*i), pad.left - 6, y + 3);
  }

  // Helper: value to Y
  const toY = v => pad.top + cH - (v / maxQ) * cH;
  const toX = i => pad.left + (i / (pts.length - 1)) * cW;

  // Blocked area (red)
  ctx.beginPath();
  ctx.moveTo(toX(0), toY(0));
  for (let i = 0; i < pts.length; i++) ctx.lineTo(toX(i), toY(pts[i].b));
  ctx.lineTo(toX(pts.length-1), toY(0));
  ctx.closePath();
  const redGrad = ctx.createLinearGradient(0, pad.top, 0, pad.top+cH);
  redGrad.addColorStop(0, 'rgba(239,68,68,0.3)');
  redGrad.addColorStop(1, 'rgba(239,68,68,0.02)');
  ctx.fillStyle = redGrad;
  ctx.fill();

  // Total area (blue)
  ctx.beginPath();
  ctx.moveTo(toX(0), toY(0));
  for (let i = 0; i < pts.length; i++) ctx.lineTo(toX(i), toY(pts[i].q));
  ctx.lineTo(toX(pts.length-1), toY(0));
  ctx.closePath();
  const blueGrad = ctx.createLinearGradient(0, pad.top, 0, pad.top+cH);
  blueGrad.addColorStop(0, 'rgba(59,130,246,0.25)');
  blueGrad.addColorStop(1, 'rgba(59,130,246,0.02)');
  ctx.fillStyle = blueGrad;
  ctx.fill();

  // Total line (blue)
  ctx.beginPath();
  ctx.strokeStyle = '#3b82f6';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  for (let i = 0; i < pts.length; i++) {
    if (i===0) ctx.moveTo(toX(i), toY(pts[i].q));
    else ctx.lineTo(toX(i), toY(pts[i].q));
  }
  ctx.stroke();

  // Blocked line (red)
  ctx.beginPath();
  ctx.strokeStyle = '#ef4444';
  ctx.lineWidth = 1.5;
  for (let i = 0; i < pts.length; i++) {
    if (i===0) ctx.moveTo(toX(i), toY(pts[i].b));
    else ctx.lineTo(toX(i), toY(pts[i].b));
  }
  ctx.stroke();

  // Cached line (cyan, dashed)
  ctx.beginPath();
  ctx.strokeStyle = '#06b6d4';
  ctx.lineWidth = 1;
  ctx.setLineDash([4,4]);
  for (let i = 0; i < pts.length; i++) {
    if (i===0) ctx.moveTo(toX(i), toY(pts[i].c));
    else ctx.lineTo(toX(i), toY(pts[i].c));
  }
  ctx.stroke();
  ctx.setLineDash([]);

  // Dots on last point
  if (pts.length > 0) {
    const last = pts[pts.length-1];
    const lx = toX(pts.length-1);
    // Blue dot
    ctx.beginPath();
    ctx.fillStyle = '#3b82f6';
    ctx.arc(lx, toY(last.q), 4, 0, Math.PI*2);
    ctx.fill();
    ctx.strokeStyle = '#0a0e17';
    ctx.lineWidth = 2;
    ctx.stroke();
  }

  // Legend
  const legendY = H - 6;
  ctx.font = '10px "Segoe UI"';
  ctx.textAlign = 'left';

  ctx.fillStyle = '#3b82f6';
  ctx.fillRect(pad.left, legendY - 6, 12, 3);
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('Toplam', pad.left + 16, legendY);

  ctx.fillStyle = '#ef4444';
  ctx.fillRect(pad.left + 76, legendY - 6, 12, 3);
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('Engellenen', pad.left + 92, legendY);

  ctx.fillStyle = '#06b6d4';
  ctx.fillRect(pad.left + 172, legendY - 6, 12, 3);
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('Onbellek', pad.left + 188, legendY);
}

// Status badge HTML
function statusBadge(status) {
  const map = {
    resolved: ['badge-resolved','COZUMLENDI'],
    blocked: ['badge-blocked','ENGELLENDI'],
    cached: ['badge-cached','ONBELLEK'],
    nxdomain: ['badge-nxdomain','NXDOMAIN'],
    error: ['badge-error','HATA']
  };
  const [cls, label] = map[status] || ['badge-resolved', status];
  return '<span class="badge '+cls+'">'+label+'</span>';
}

// Format time
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString('tr-TR', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

// Update query table
function updateQueryTable(queries) {
  const body = document.getElementById('queryBody');
  if (!queries || queries.length === 0) return;

  let html = '';
  for (const q of queries) {
    const ms = q.responseMs < 1 ? '<1' : q.responseMs.toFixed(0);
    html += '<tr class="fade-in">' +
      '<td style="color:var(--text3);font-family:monospace;font-size:11px">'+fmtTime(q.timestamp)+'</td>' +
      '<td style="font-family:monospace">'+escHtml(q.domain)+'</td>' +
      '<td style="color:var(--text3)">'+escHtml(q.qtypeName || 'A')+'</td>' +
      '<td>'+statusBadge(q.status)+'</td>' +
      '<td style="font-family:monospace;color:var(--text2)">'+(q.answerIp||'—')+'</td>' +
      '<td style="font-family:monospace;color:'+(q.responseMs<10?'var(--green)':q.responseMs<100?'var(--orange)':'var(--red)')+'">'+ms+' ms</td>' +
      '</tr>';
  }
  body.innerHTML = html;
}

// Update domain lists
function updateDomainList(elementId, domains) {
  const el = document.getElementById(elementId);
  if (!domains || domains.length === 0) {
    el.innerHTML = '<li class="domain-item" style="color:var(--text3);font-size:12px;justify-content:center">Henuz veri yok</li>';
    return;
  }
  let html = '';
  for (const d of domains) {
    html += '<li class="domain-item">' +
      '<span class="domain-name">'+escHtml(d.domain)+'</span>' +
      '<span class="domain-count">'+d.count+'</span></li>';
  }
  el.innerHTML = html;
}

// Escape HTML
function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Server stat color
function msColor(ms) {
  if (ms < 50) return 'fast';
  if (ms < 200) return 'medium';
  return 'slow';
}

// Prev query count for QPS calc
let prevTotal = 0;
let prevTime = Date.now();

// ==================== SSE CONNECTION ====================

function connectSSE() {
  const es = new EventSource('/api/stream');

  es.addEventListener('stats', e => {
    const s = JSON.parse(e.data);

    // Stat cards
    animateValue(document.getElementById('totalQueries'), s.totalQueries);
    animateValue(document.getElementById('avgMs'), s.avgResponseMs, 1);
    animateValue(document.getElementById('blockedCount'), s.blockedCount);
    document.getElementById('cacheHitRate').textContent = s.cacheHitRate.toFixed(1) + '%';
    document.getElementById('blockRate').textContent = '%' + s.blockRate.toFixed(1) + ' engelleme orani';
    document.getElementById('cacheSub').textContent = s.cacheSize + ' kayit / ' + s.cachedHits + ' isabet';
    document.getElementById('uptime').textContent = s.uptime;

    // QPS
    const now = Date.now();
    const elapsed = (now - prevTime) / 1000;
    if (elapsed > 0) {
      const qps = ((s.totalQueries - prevTotal) / elapsed).toFixed(1);
      document.getElementById('qps').textContent = qps + ' sorgu/sn';

      // Chart point
      chartData.points.push({
        q: s.totalQueries - prevTotal,
        b: Math.round(s.blockedCount * elapsed / (s.uptimeSec || 1)),
        c: Math.round(s.cachedHits * elapsed / (s.uptimeSec || 1)),
        t: now
      });
      if (chartData.points.length > chartData.maxPoints) chartData.points.shift();
    }
    prevTotal = s.totalQueries;
    prevTime = now;

    // Progress bars
    document.getElementById('hitRateBar').style.width = s.cacheHitRate + '%';
    document.getElementById('hitRateLabel').textContent = s.cacheHitRate.toFixed(1) + '%';
    document.getElementById('blockRateBar').style.width = Math.min(s.blockRate, 100) + '%';
    document.getElementById('blockRateLabel').textContent = s.blockRate.toFixed(1) + '%';
    document.getElementById('blockRules').textContent = s.blockRules.toLocaleString('tr-TR');
    document.getElementById('cacheEntries').textContent = s.cacheSize;
    document.getElementById('liveClients').textContent = s.liveClients;

    // Server stats
    const types = {root:'rootMs', tld:'tldMs', auth:'authMs'};
    for (const [key, elId] of Object.entries(types)) {
      const el = document.getElementById(elId);
      if (s.serverStats && s.serverStats[key]) {
        const ms = s.serverStats[key].avgMs;
        el.textContent = ms.toFixed(1) + ' ms (' + s.serverStats[key].count + ')';
        el.className = 'server-value ' + msColor(ms);
      }
    }

    drawChart();
  });

  es.addEventListener('queries', e => {
    const queries = JSON.parse(e.data);
    updateQueryTable(queries);
  });

  es.onerror = () => {
    es.close();
    setTimeout(connectSSE, 3000);
  };
}

// Initial data load
async function loadInitial() {
  try {
    const [topD, topB, queries] = await Promise.all([
      fetch('/api/top-domains').then(r=>r.json()),
      fetch('/api/top-blocked').then(r=>r.json()),
      fetch('/api/queries').then(r=>r.json())
    ]);
    updateDomainList('topDomains', topD);
    updateDomainList('topBlocked', topB);
    updateQueryTable(queries);
  } catch(e) {}
}

// Top domain'leri periyodik güncelle
setInterval(async () => {
  try {
    const [topD, topB] = await Promise.all([
      fetch('/api/top-domains').then(r=>r.json()),
      fetch('/api/top-blocked').then(r=>r.json())
    ]);
    updateDomainList('topDomains', topD);
    updateDomainList('topBlocked', topB);
  } catch(e) {}
}, 5000);

// Resize chart
window.addEventListener('resize', drawChart);

// Start
loadInitial();
connectSSE();
drawChart();
</script>
</body>
</html>`
