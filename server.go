package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ==================== GOROUTINE MİMARİSİ ====================

// RequestContext — Gelen bir UDP DNS isteğinin tüm bağlamı
type RequestContext struct {
	Data   []byte       // Paket verisi (kopyalanmış)
	Size   int          // Paket boyutu
	Source *net.UDPAddr // İstemci adresi
	Conn   *net.UDPConn // UDP bağlantısı (yanıt için)
}

// BufferPool — Bellek ayırmayı azaltan buffer havuzu
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 4096)
		return &buf
	},
}

// getBuffer — Havuzdan buffer al
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// putBuffer — Buffer'ı havuza geri koy
func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// Aynı anda işlenen sorgu sınırı (taşkın saldırılarına karşı)
var (
	udpSlots = make(chan struct{}, 1024)
	tcpSlots = make(chan struct{}, 256)
)

// Konsola her sorgu için tek satır yazılsın mı? (uygulama modunda açık)
var consoleQueryLog bool

// CGNAT (100.64.0.0/10) — bazı mobil/ev ağlarında yerel adres olarak kullanılır
var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// clientAllowed — açık çözümleyici (open resolver) olup kötüye kullanılmamak için
// varsayılan olarak yalnızca yerel ağdan gelen sorgular kabul edilir
func clientAllowed(ip net.IP) bool {
	if cfg.AllowPublicClients {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnatNet.Contains(ip)
}

// serveUDP — UDP ana döngüsü: her istek ayrı goroutine'de işlenir
func serveUDP(conn *net.UDPConn) {
	for {
		bufPtr := getBuffer()
		buf := *bufPtr

		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			putBuffer(bufPtr)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 12 || !clientAllowed(source.IP) {
			putBuffer(bufPtr)
			continue
		}

		packetData := make([]byte, n)
		copy(packetData, buf[:n])
		putBuffer(bufPtr)

		select {
		case udpSlots <- struct{}{}:
		default:
			continue // Aşırı yük — paketi düşür, istemci tekrar dener
		}
		go func() {
			defer func() { <-udpSlots }()
			handleRequest(RequestContext{Data: packetData, Size: n, Source: source, Conn: conn})
		}()
	}
}

// handleRequest — Tek bir UDP DNS isteğini goroutine içinde işle
func handleRequest(ctx RequestContext) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("║ ⚠ Goroutine panik: %v\n", r)
		}
	}()

	response := handleDNSMessage(ctx.Data[:ctx.Size], "udp", ctx.Source.IP.String(), true)
	if response != nil {
		ctx.Conn.WriteToUDP(response, ctx.Source)
	}
}

// ==================== ORTAK SORGU İŞLEYİCİ ====================

// handleDNSMessage — UDP / TCP / DoT / DoH için ortak işleyici. Yanıt paketini döndürür
// (nil = yanıt verme). overUDP ise yanıt, istemcinin kabul ettiği boyuta göre kırpılır.
func handleDNSMessage(raw []byte, proto, client string, overUDP bool) []byte {
	start := time.Now()

	req, err := parseMessage(raw)
	if err != nil {
		if len(raw) >= 12 && raw[2]&0x80 == 0 {
			return buildErrorReply(raw, rcodeFormErr)
		}
		return nil
	}
	if req.Header.Flags&flagQR != 0 {
		return nil // Yanıt paketlerine yanıt verilmez
	}

	limit := 0
	if overUDP {
		limit = min(max(ednsSize(req), 512), 4096)
	}
	if req.Header.Flags&flagOpcode != 0 {
		return buildReply(req, rcodeNotImp, nil, nil, limit)
	}
	if len(req.Questions) != 1 {
		return buildReply(req, rcodeFormErr, nil, nil, limit)
	}
	q := req.Questions[0]
	if q.QClass != classIN {
		return buildReply(req, rcodeNotImp, nil, nil, limit)
	}

	metrics.IncrementTotal()
	ans, status := answerQuery(q)
	duration := time.Since(start)

	if status != "blocked" {
		metrics.AddResolveTime(duration)
	}
	if status == "cached" {
		metrics.IncrementCached()
	}

	entry := QueryLogEntry{
		Timestamp:  start,
		Domain:     normalizeName(q.Name),
		QType:      q.QType,
		QTypeName:  qtypeName(q.QType),
		ResponseMs: float64(duration.Microseconds()) / 1000,
		Status:     status,
		Source:     proto,
		ClientIP:   client,
	}
	for _, rr := range ans.Records {
		if ip := recordIP(rr); ip != "" {
			entry.AnswerIP = ip
			break
		}
	}
	if queryLog != nil {
		queryLog.Add(entry)
	}
	logQuery(entry)

	return buildReply(req, ans.Rcode, ans.Records, ans.Authority, limit)
}

// answerQuery — sırasıyla: yerel yanıt → reklam engeli → rekürsif çözümleme
func answerQuery(q DNSQuestion) (Answer, string) {
	name := normalizeName(q.Name)

	if ans, ok := localAnswer(name, q.QType); ok {
		return ans, "local"
	}

	// 🛡️ Reklam Engelleme Kontrolü
	if blocker != nil && blocker.IsBlocked(name) {
		return Answer{Rcode: rcodeSuccess, Records: blockedRecords(q)}, "blocked"
	}

	// Gerçek rekursif çözümleme
	ans := resolver.Resolve(name, q.QType)
	switch {
	case ans.Rcode == rcodeServFail:
		return ans, "error"
	case ans.Rcode == rcodeNXDomain:
		return ans, "nxdomain"
	case ans.Cached:
		return ans, "cached"
	}
	return ans, "resolved"
}

var statusIcons = map[string]string{
	"resolved": "✓", "cached": "⚡", "blocked": "🛡", "nxdomain": "∅", "error": "✗", "local": "⌂",
}

func logQuery(e QueryLogEntry) {
	if !consoleQueryLog {
		return
	}
	answer := e.AnswerIP
	if e.Status == "error" {
		answer = "(çözümlenemedi)"
	}
	fmt.Printf("%s %s %-5s %s %s %.0fms\n", e.Timestamp.Format("15:04:05"), statusIcons[e.Status],
		e.QTypeName, e.Domain, answer, e.ResponseMs)
}

// ==================== DİNLEYİCİLER ====================

// dnsListenAddrs — bindAddr'a göre dinlenecek adresler. Varsayılanda IPv6 loopback
// da dinlenir; böylece sistemin IPv6 DNS'i de İSS yerine Ceky'ye yönlendirilebilir.
func dnsListenAddrs(bind string) []string {
	switch bind {
	case "", "127.0.0.1", "localhost":
		return []string{"127.0.0.1", "::1"}
	}
	return []string{bind}
}

// startDNSListeners — UDP+TCP dinleyicilerini aç. İlk adres zorunludur,
// diğerleri (ör. ::1) açılamazsa sessizce atlanır.
func startDNSListeners(addrs []string, port int) ([]string, []io.Closer, error) {
	var bound []string
	var closers []io.Closer
	for i, host := range addrs {
		addr := net.JoinHostPort(host, fmt.Sprint(port))
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			if i == 0 {
				return nil, closers, err
			}
			continue
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			if i == 0 {
				closeAll(closers)
				return nil, nil, err
			}
			continue
		}
		closers = append(closers, conn)
		go serveUDP(conn)

		// TCP — büyük yanıtlar (TC=1) için istemciler TCP'ye geçer
		if ln, err := net.Listen("tcp", addr); err == nil {
			closers = append(closers, ln)
			go serveStream(ln, "tcp")
		} else {
			fmt.Printf("║ ⚠ TCP %s açılamadı: %v\n", addr, err)
		}
		bound = append(bound, host)
	}
	return bound, closers, nil
}

func closeAll(closers []io.Closer) {
	for _, c := range closers {
		c.Close()
	}
}

// serveStream — TCP ve DoT bağlantılarını kabul et
func serveStream(ln net.Listener, proto string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if ip := net.ParseIP(host); ip == nil || !clientAllowed(ip) {
			conn.Close()
			continue
		}
		select {
		case tcpSlots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-tcpSlots }()
			handleStreamConn(conn, proto, host)
		}()
	}
}

// handleStreamConn — DNS over TCP / TLS: 2-byte uzunluk önekli mesajlar
func handleStreamConn(conn net.Conn, proto, client string) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("║ ⚠ Goroutine panik: %v\n", r)
		}
	}()

	reader := bufio.NewReader(conn)
	lenBuf := make([]byte, 2)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(reader, lenBuf); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf))
		if msgLen < 12 {
			return
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(reader, msg); err != nil {
			return
		}

		response := handleDNSMessage(msg, proto, client, false)
		if response == nil {
			return
		}
		out := binary.BigEndian.AppendUint16(make([]byte, 0, len(response)+2), uint16(len(response)))
		if _, err := conn.Write(append(out, response...)); err != nil {
			return
		}
	}
}

// ==================== DNS-over-TLS (DoT) — RFC 7858 ====================

func startDoTServer(certFile, keyFile string) io.Closer {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("║ ⚠ DoT: Sertifika yüklenemedi: %v\n", err)
		return nil
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", net.JoinHostPort(cfg.BindAddr, fmt.Sprint(cfg.DoTPort)), tlsConfig)
	if err != nil {
		fmt.Printf("║ ⚠ DoT dinleyici hatası: %v\n", err)
		return nil
	}

	fmt.Printf("║ 🔒 DNS-over-TLS (DoT) aktif — port %d\n", cfg.DoTPort)
	go serveStream(listener, "dot")
	return listener
}

// ==================== DNS-over-HTTPS (DoH) — RFC 8484 ====================

func startDoHServer(certFile, keyFile string) io.Closer {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", handleDoHRequest)

	server := &http.Server{
		Addr:         net.JoinHostPort(cfg.BindAddr, fmt.Sprint(cfg.DoHPort)),
		Handler:      mux,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		// TLS olmadan HTTP (geliştirme/test amaçlı)
		fmt.Printf("║ 🌐 DNS-over-HTTP (test) aktif — http://%s/dns-query\n", server.Addr)
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("║ ⚠ DoH HTTP hatası: %v\n", err)
			}
		}()
		return server
	}

	fmt.Printf("║ 🔒 DNS-over-HTTPS (DoH) aktif — https://%s/dns-query\n", server.Addr)
	go func() {
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			fmt.Printf("║ ⚠ DoH HTTPS hatası: %v\n", err)
		}
	}()
	return server
}

func handleDoHRequest(w http.ResponseWriter, r *http.Request) {
	var dnsMsg []byte
	var err error

	switch r.Method {
	case http.MethodPost:
		// POST: Gövde doğrudan DNS wire format
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Content-Type must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		dnsMsg, err = io.ReadAll(io.LimitReader(r.Body, 65535))
	case http.MethodGet:
		// GET: ?dns= parametresi (base64url, dolgusuz)
		dnsMsg, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(dnsMsg) < 12 {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(client); ip == nil || !clientAllowed(ip) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	response := handleDNSMessage(dnsMsg, "doh", client, false)
	if response == nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	// Önbellek süresi = en kısa TTL
	maxAge := uint32(0)
	if msg, err := parseMessage(response); err == nil && msg.Header.Rcode() == rcodeSuccess && len(msg.Answers) > 0 {
		maxAge = msg.Answers[0].TTL
		for _, rr := range msg.Answers {
			maxAge = min(maxAge, rr.TTL)
		}
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", maxAge))
	w.Write(response)
}
