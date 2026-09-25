package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== KÖK SUNUCULAR ====================

// 13 kök DNS sunucusunun IPv4 adresleri (IANA root hints)
var rootServers = []string{
	"198.41.0.4",     // a.root-servers.net
	"170.247.170.2",  // b.root-servers.net (Kasım 2023'te değişti)
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

// ==================== REKÜRSİF ÇÖZÜMLEYİCİ ====================

// Answer — bir çözümlemenin sonucu
type Answer struct {
	Rcode     int
	Records   []DNSRecord // Answer bölümü (CNAME zinciri dahil)
	Authority []DNSRecord // NXDOMAIN / NODATA için SOA
	Cached    bool
}

// Resolver — kök sunuculardan başlayan, hiçbir aracı DNS'e bağlı olmayan çözümleyici
type Resolver struct {
	roots      []string
	port       string
	udpTimeout time.Duration
	tcpTimeout time.Duration
	cache      *DNSCache
	zones      *zoneCache
	metrics    *ResolverMetrics
	flight     flightGroup
	forceTCP   atomic.Bool // İSS UDP/53'e müdahale ediyorsa TCP kullanılır
	verbose    bool
	trace      func(TraceStep)
}

const (
	maxDepth        = 12 // İç içe çözümleme (CNAME + NS) sınırı
	maxTriesPerZone = 4
)

// Yanıt sınıfları
const (
	kindAnswer = iota
	kindReferral
	kindNXDomain
	kindNoData
	kindLame
)

func newResolver(roots []string, cache *DNSCache, m *ResolverMetrics) *Resolver {
	if len(roots) == 0 {
		roots = rootServers
	}
	return &Resolver{
		roots:      roots,
		port:       "53",
		udpTimeout: 1500 * time.Millisecond,
		tcpTimeout: 3 * time.Second,
		cache:      cache,
		zones:      newZoneCache(),
		metrics:    m,
	}
}

func (r *Resolver) logf(format string, args ...any) {
	if r.verbose {
		fmt.Printf("  "+format+"\n", args...)
	}
}

// Resolve — alan adını kök sunuculardan başlayarak çözümle
func (r *Resolver) Resolve(name string, qtype uint16) Answer {
	return r.resolve(normalizeName(name), qtype, 0)
}

// FlushCache — önbelleği ve delegasyon bilgisini sıfırla
func (r *Resolver) FlushCache() {
	r.cache.Flush()
	r.zones.flush()
}

func (r *Resolver) resolve(name string, qtype uint16, depth int) Answer {
	if ans, ok := r.cache.Get(name, qtype); ok {
		r.logf("⚡ ÖNBELLEKTEN: %s (tip: %s)", name, qtypeName(qtype))
		return ans
	}
	work := func() Answer {
		ans := r.resolveUncached(name, qtype, depth)
		if ans.Rcode == rcodeServFail {
			if stale, ok := r.cache.GetStale(name, qtype); ok {
				r.logf("⚠ Sunuculara ulaşılamadı, bayat yanıt sunuluyor: %s", name)
				return stale
			}
		}
		r.cache.Set(name, qtype, ans)
		return ans
	}
	// Tekil uçuş yalnızca en üst seviyede: iç içe çağrılarda kilitlenme olmasın
	if depth == 0 {
		return r.flight.do(cacheKey(name, qtype), work)
	}
	return work()
}

func (r *Resolver) resolveUncached(name string, qtype uint16, depth int) Answer {
	if depth > maxDepth {
		return Answer{Rcode: rcodeServFail}
	}
	res := r.lookup(name, qtype, depth)
	if res.Rcode != rcodeSuccess && res.Rcode != rcodeNXDomain {
		return Answer{Rcode: rcodeServFail}
	}

	target, complete, chain := followChain(name, qtype, res.Records)
	switch {
	case complete:
		return Answer{Rcode: rcodeSuccess, Records: chain}
	case res.Rcode == rcodeNXDomain:
		return Answer{Rcode: rcodeNXDomain, Records: chain, Authority: res.Authority}
	case target == name: // CNAME yok, kayıt da yok → NODATA
		return Answer{Rcode: rcodeSuccess, Authority: res.Authority}
	}

	// CNAME hedefi başka bir bölgede — onu da kökten (veya önbellekten) çöz
	r.logf("CNAME: %s → %s", name, target)
	sub := r.resolve(target, qtype, depth+1)
	if sub.Rcode == rcodeServFail {
		return Answer{Rcode: rcodeServFail}
	}
	return Answer{Rcode: sub.Rcode, Records: append(chain, sub.Records...), Authority: sub.Authority}
}

// followChain — yanıttaki kayıtlarda isimden başlayarak CNAME zincirini takip et.
// Yalnızca zincire ait kayıtlar alınır; alakasız (zehirli) kayıtlar atılır.
func followChain(name string, qtype uint16, records []DNSRecord) (string, bool, []DNSRecord) {
	cur := name
	var chain []DNSRecord
	for hop := 0; hop < 16; hop++ {
		matched := false
		for _, rr := range records {
			if normalizeName(rr.Name) == cur && (rr.Type == qtype || qtype == typeANY) {
				chain = append(chain, rr)
				matched = true
			}
		}
		if matched {
			return cur, true, chain
		}
		next := ""
		for _, rr := range records {
			if normalizeName(rr.Name) == cur && rr.Type == typeCNAME {
				chain = append(chain, rr)
				next = rdataName(rr.RData)
				break
			}
		}
		if next == "" || next == cur {
			return cur, false, chain
		}
		cur = next
	}
	return cur, false, chain
}

// lookup — tek bir ismi, bilinen en yakın bölge kesiminden başlayarak iteratif çöz
func (r *Resolver) lookup(name string, qtype uint16, depth int) Answer {
	zone, servers := r.zones.closest(name)
	if len(servers) == 0 {
		zone, servers = "", r.roots
	}
	restarted := false

	for step := 0; step < 24; step++ {
		msg, kind, err := r.queryZone(zone, servers, name, qtype, depth)
		if err != nil {
			if zone != "" && !restarted {
				// Önbellekteki sunucular yanıt vermiyor — kökten yeniden başla
				r.zones.remove(zone)
				zone, servers, restarted = "", r.roots, true
				continue
			}
			r.logf("✗ %s çözümlenemedi: %v", name, err)
			return Answer{Rcode: rcodeServFail}
		}

		switch kind {
		case kindAnswer:
			return Answer{Rcode: rcodeSuccess, Records: inZone(msg.Answers, zone)}
		case kindNXDomain:
			return Answer{Rcode: rcodeNXDomain, Records: inZone(msg.Answers, zone), Authority: soaRecords(msg)}
		case kindNoData:
			return Answer{Rcode: rcodeSuccess, Authority: soaRecords(msg)}
		}

		// Yönlendirme (referral) — bir alt bölgenin sunucularına geç
		cut, nsNames, ttl := referral(msg, zone, name)
		addrs := glueAddrs(msg, nsNames, zone)
		if len(addrs) == 0 {
			// Glue kaydı yok: NS isimlerini ayrıca çözmemiz gerekiyor
			addrs = r.resolveNSAddrs(nsNames, depth)
		}
		if len(addrs) == 0 {
			r.logf("✗ %s bölgesinin sunucu adresleri bulunamadı", cut)
			return Answer{Rcode: rcodeServFail}
		}
		r.zones.put(cut, addrs, ttl)
		zone, servers = cut, addrs
	}
	return Answer{Rcode: rcodeServFail}
}

// queryZone — bölgenin sunucularını rastgele sırayla dener, ilk geçerli yanıtı döndürür
func (r *Resolver) queryZone(zone string, servers []string, name string, qtype uint16, depth int) (*DNSMessage, int, error) {
	order := append([]string(nil), servers...)
	rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })

	var lastErr error
	for i, ip := range order {
		if i >= maxTriesPerZone {
			break
		}
		msg, info, err := r.queryServer(ip, zone, name, qtype)
		if err != nil {
			lastErr = err
			r.traceStep(depth, zone, ip, name, qtype, info, "hata: "+err.Error())
			continue
		}
		kind := classify(msg, zone, name)
		r.traceStep(depth, zone, ip, name, qtype, info, describe(msg, kind, zone, name))
		if kind == kindLame {
			lastErr = fmt.Errorf("%s geçersiz yanıt verdi (rcode %d)", ip, msg.Header.Rcode())
			continue
		}
		return msg, kind, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("sunucu yok")
	}
	return nil, 0, lastErr
}

// classify — sunucu yanıtını sınıflandır.
// Kesin yanıtlar (cevap, NXDOMAIN, NODATA) yalnızca AA (yetkili) bayrağı taşıyorsa
// kabul edilir. Araya giren bir cihaz (ör. İSS'nin DNS yönlendirmesi) kendi
// önbelleğinden cevap verdiğinde bu bayrak olmaz — böyle yanıtlar reddedilir.
func classify(msg *DNSMessage, zone, name string) int {
	authoritative := msg.Header.Flags&flagAA != 0
	switch msg.Header.Rcode() {
	case rcodeSuccess:
	case rcodeNXDomain:
		if authoritative {
			return kindNXDomain
		}
		return kindLame
	default: // SERVFAIL, REFUSED, ... → başka sunucu dene
		return kindLame
	}
	if len(msg.Answers) > 0 {
		if !authoritative {
			return kindLame
		}
		for _, rr := range msg.Answers {
			if normalizeName(rr.Name) == name {
				return kindAnswer
			}
		}
		return kindLame // Sorulmayan isimler için cevap — güvenilmez
	}
	if authoritative {
		return kindNoData
	}
	if cut, _, _ := referral(msg, zone, name); cut != "" {
		return kindReferral
	}
	return kindLame // Yukarı/yana yönlendirme veya yetkisiz boş yanıt
}

// referral — Authority bölümündeki geçerli (daha derin) bölge kesimi ve NS isimleri
func referral(msg *DNSMessage, zone, name string) (string, []string, uint32) {
	cut := ""
	var ns []string
	ttl := uint32(maxCacheTTL)
	for _, rr := range msg.Authority {
		if rr.Type != typeNS {
			continue
		}
		owner := normalizeName(rr.Name)
		// Kesim, mevcut bölgeden daha derin ve sorulan ismin atası olmalı
		if owner == zone || !isSubdomain(owner, zone) || !isSubdomain(name, owner) {
			continue
		}
		if cut == "" {
			cut = owner
		} else if owner != cut {
			continue
		}
		ns = append(ns, rdataName(rr.RData))
		ttl = min(ttl, rr.TTL)
	}
	return cut, ns, ttl
}

// glueAddrs — Additional bölümündeki NS IP'leri (yalnızca sunucunun yetki alanındakiler)
func glueAddrs(msg *DNSMessage, nsNames []string, zone string) []string {
	want := make(map[string]bool, len(nsNames))
	for _, n := range nsNames {
		want[n] = true
	}
	var addrs []string
	seen := make(map[string]bool)
	for _, rr := range msg.Additional {
		owner := normalizeName(rr.Name)
		if rr.Type != typeA || !want[owner] || !isSubdomain(owner, zone) {
			continue
		}
		if ip := recordIP(rr); ip != "" && !seen[ip] {
			seen[ip] = true
			addrs = append(addrs, ip)
		}
	}
	return addrs
}

// resolveNSAddrs — glue olmayan NS isimlerinin IP'lerini çöz
func (r *Resolver) resolveNSAddrs(nsNames []string, depth int) []string {
	names := append([]string(nil), nsNames...)
	rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })

	var addrs []string
	for i, ns := range names {
		if i >= 3 || len(addrs) >= 2 {
			break
		}
		r.logf("NS IP'si bilinmiyor, %s çözümleniyor...", ns)
		ans := r.resolve(ns, typeA, depth+1)
		for _, rr := range ans.Records {
			if ip := recordIP(rr); ip != "" && rr.Type == typeA {
				addrs = append(addrs, ip)
			}
		}
	}
	return addrs
}

// inZone — yalnızca sunucunun yetki alanındaki kayıtları tut (bailiwick kontrolü)
func inZone(records []DNSRecord, zone string) []DNSRecord {
	var out []DNSRecord
	for _, rr := range records {
		if isSubdomain(rr.Name, zone) {
			out = append(out, rr)
		}
	}
	return out
}

func soaRecords(msg *DNSMessage) []DNSRecord {
	var out []DNSRecord
	for _, rr := range msg.Authority {
		if rr.Type == typeSOA {
			out = append(out, rr)
		}
	}
	return out
}

func serverTypeOf(zone string) string {
	switch {
	case zone == "":
		return "root"
	case parentName(zone) == "":
		return "tld"
	}
	return "auth"
}

// ==================== AĞ G/Ç ====================

type exchangeInfo struct {
	proto string
	dur   time.Duration
}

// queryServer — tek bir sunucuya sorgu gönder, yanıtı doğrula
func (r *Resolver) queryServer(ip, zone, name string, qtype uint16) (*DNSMessage, exchangeInfo, error) {
	query := buildQuery(name, qtype)
	id := binary.BigEndian.Uint16(query)
	start := time.Now()
	info := exchangeInfo{proto: "udp"}

	var raw []byte
	var err error
	if r.forceTCP.Load() {
		info.proto = "tcp"
		raw, err = r.exchangeTCP(ip, query)
	} else {
		raw, err = r.exchangeUDP(ip, query)
		if err == nil && len(raw) >= 4 && binary.BigEndian.Uint16(raw[2:4])&flagTC != 0 {
			// Yanıt kesilmiş (TC=1) — TCP ile tekrar sor
			info.proto = "tcp"
			raw, err = r.exchangeTCP(ip, query)
		}
	}
	info.dur = time.Since(start)
	if err != nil {
		return nil, info, err
	}

	msg, err := parseMessage(raw)
	if err != nil {
		return nil, info, fmt.Errorf("%s: %v", ip, err)
	}
	if msg.Header.ID != id || msg.Header.Flags&flagQR == 0 || len(msg.Questions) != 1 ||
		normalizeName(msg.Questions[0].Name) != name || msg.Questions[0].QType != qtype {
		return nil, info, fmt.Errorf("%s: yanıt soruyla eşleşmiyor", ip)
	}

	if r.metrics != nil {
		r.metrics.RecordQuery(QueryMetric{
			ServerIP:   ip,
			ServerType: serverTypeOf(zone),
			Domain:     name,
			Duration:   info.dur,
			Protocol:   info.proto,
		})
	}
	r.logf("[%s] %s → %s %s: AN=%d NS=%d AR=%d (%s %dms)", serverTypeOf(zone), ip, name, qtypeName(qtype),
		len(msg.Answers), len(msg.Authority), len(msg.Additional), info.proto, info.dur.Milliseconds())
	return msg, info, nil
}

// UDP ile sorgu gönder. Yanlış ID'li paketler (sahte yanıt girişimi) yok sayılır.
func (r *Resolver) exchangeUDP(ip string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, r.port), r.udpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(r.udpTimeout))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: zaman aşımı/UDP hatası", ip)
		}
		if n >= 12 && buf[0] == query[0] && buf[1] == query[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// TCP ile sorgu gönder (DNS over TCP: 2-byte uzunluk öneki)
func (r *Resolver) exchangeTCP(ip string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, r.port), r.tcpTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: TCP bağlantı hatası", ip)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(r.tcpTimeout))

	msg := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(msg, query...)); err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("%s: TCP okuma hatası", ip)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("%s: TCP okuma hatası", ip)
	}
	return resp, nil
}

// ==================== İZLEME (TRACE) ====================

// TraceStep — bağlantı testinde gösterilen tek bir sunucu sorgusu
type TraceStep struct {
	Depth  int     `json:"depth"`
	Zone   string  `json:"zone"`
	Kind   string  `json:"kind"`
	Server string  `json:"server"`
	Name   string  `json:"name"`
	QType  string  `json:"qtype"`
	Proto  string  `json:"proto"`
	Ms     float64 `json:"ms"`
	Result string  `json:"result"`
}

func (r *Resolver) traceStep(depth int, zone, server, name string, qtype uint16, info exchangeInfo, result string) {
	if r.trace == nil {
		return
	}
	r.trace(TraceStep{
		Depth: depth, Zone: zone, Kind: serverTypeOf(zone), Server: server, Name: name,
		QType: qtypeName(qtype), Proto: info.proto, Ms: float64(info.dur.Microseconds()) / 1000, Result: result,
	})
}

// describe — yanıtın insan okunur özeti
func describe(msg *DNSMessage, kind int, zone, name string) string {
	switch kind {
	case kindAnswer:
		for _, rr := range msg.Answers {
			if ip := recordIP(rr); ip != "" {
				return "cevap: " + ip
			}
			if rr.Type == typeCNAME {
				return "takma ad → " + rdataName(rr.RData)
			}
		}
		return fmt.Sprintf("cevap (%d kayıt)", len(msg.Answers))
	case kindReferral:
		cut, ns, _ := referral(msg, zone, name)
		return fmt.Sprintf("yönlendirme → %s (%d sunucu)", cut, len(ns))
	case kindNXDomain:
		return "alan adı yok (NXDOMAIN)"
	case kindNoData:
		return "bu türde kayıt yok (NODATA)"
	}
	if rc := msg.Header.Rcode(); (rc == rcodeSuccess || rc == rcodeNXDomain) && msg.Header.Flags&flagAA == 0 &&
		(len(msg.Answers) > 0 || rc == rcodeNXDomain || msg.Header.Flags&flagRA != 0) {
		return "yetkisiz yanıt reddedildi — ağ araya giriyor olabilir"
	}
	return fmt.Sprintf("geçersiz yanıt (rcode %d)", msg.Header.Rcode())
}

// Trace — önbellek kullanmadan kökten itibaren çözümle ve her adımı kaydet
func (r *Resolver) Trace(name string, qtype uint16) ([]TraceStep, Answer) {
	var mu sync.Mutex
	var steps []TraceStep
	tr := newResolver(r.roots, newDNSCache(0), nil)
	tr.port, tr.udpTimeout, tr.tcpTimeout = r.port, r.udpTimeout, r.tcpTimeout
	tr.forceTCP.Store(r.forceTCP.Load())
	tr.trace = func(s TraceStep) {
		mu.Lock()
		steps = append(steps, s)
		mu.Unlock()
	}
	ans := tr.Resolve(name, qtype)
	return steps, ans
}

// ==================== AĞ MÜDAHALESİ TESPİTİ ====================

// NetProbe — kök sunuculara erişimin durumu
//
//	"ok"          — kök sunucular gerçek yanıt veriyor
//	"intercepted" — biri (genelde İSS) araya girip kendi yanıtını veriyor
//	"blocked"     — hiç yanıt yok
type NetProbe struct {
	UDP     string    `json:"udp"`
	TCP     string    `json:"tcp"`
	Checked time.Time `json:"checked"`
}

// Healthy — kök sunuculara en az bir yoldan gerçekten ulaşılabiliyor mu?
func (p NetProbe) Healthy() bool { return p.UDP == "ok" || p.TCP == "ok" }

// Probe — UDP (gerekirse TCP) üzerinden kök sunuculara ulaşılabilirliği test et
func (r *Resolver) Probe() NetProbe {
	p := NetProbe{UDP: r.probeTransport(false), TCP: "unknown", Checked: time.Now()}
	if p.UDP != "ok" {
		p.TCP = r.probeTransport(true)
	}
	return p
}

// probeTransport — 3 rastgele kök sunucuya aynı anda "com NS" sorar. Gerçek bir
// kök sunucu özyineleme yapmaz (RA=0) ve cevap değil yönlendirme döndürür; aksi
// durum aradaki bir cihazın DNS trafiğini ele geçirdiğini gösterir.
func (r *Resolver) probeTransport(tcp bool) string {
	roots := append([]string(nil), r.roots...)
	rand.Shuffle(len(roots), func(i, j int) { roots[i], roots[j] = roots[j], roots[i] })
	roots = roots[:min(len(roots), 3)]

	results := make(chan string, len(roots))
	for _, ip := range roots {
		go func(ip string) {
			query := buildQuery("com", typeNS)
			var raw []byte
			var err error
			if tcp {
				raw, err = r.exchangeTCP(ip, query)
			} else {
				raw, err = r.exchangeUDP(ip, query)
			}
			if err != nil {
				results <- "blocked"
				return
			}
			msg, err := parseMessage(raw)
			if err == nil && isGenuineRootReferral(msg, binary.BigEndian.Uint16(query)) {
				results <- "ok"
				return
			}
			results <- "intercepted"
		}(ip)
	}

	status := "blocked"
	for range roots {
		switch <-results {
		case "ok":
			return "ok"
		case "intercepted":
			status = "intercepted"
		}
	}
	return status
}

func isGenuineRootReferral(msg *DNSMessage, id uint16) bool {
	h := msg.Header
	if h.ID != id || h.Rcode() != rcodeSuccess || h.Flags&(flagRA|flagAA) != 0 || len(msg.Answers) != 0 {
		return false
	}
	for _, rr := range msg.Authority {
		if rr.Type == typeNS && normalizeName(rr.Name) == "com" {
			return true
		}
	}
	return false
}
