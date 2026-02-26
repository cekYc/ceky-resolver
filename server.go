package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ==================== GOROUTINE MİMARİSİ ====================

// RequestContext — Gelen bir DNS isteğinin tüm bağlamı
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

// handleRequest — Tek bir DNS isteğini goroutine içinde işle
func handleRequest(ctx RequestContext) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("║ ⚠ Goroutine panik: %v\n", r)
		}
	}()

	if ctx.Size < 12 {
		return
	}

	// Header ve soru kısmını ayrıştır
	header := parseHeader(ctx.Data[:12])
	question, _ := parseQuestion(ctx.Data[:ctx.Size], 12)

	fmt.Printf("\n╔══ Yeni İstek ══════════════════════════════\n")
	fmt.Printf("║ Kaynak:  %s\n", ctx.Source)
	fmt.Printf("║ ID:      0x%04x\n", header.ID)
	fmt.Printf("║ Sorgu:   %s (tip: %d)\n", question.Name, question.QType)

	// 🛡️ Reklam Engelleme Kontrolü
	if blocker != nil && blocker.IsBlocked(question.Name) {
		fmt.Printf("║ 🛡️ ENGELLENDİ: %s (reklam/takipçi)\n", question.Name)
		response := buildBlockedResponse(ctx.Data[:ctx.Size])
		ctx.Conn.WriteToUDP(response, ctx.Source)
		fmt.Printf("╚══ Engellendi → 0.0.0.0 (%d byte) ════════\n", len(response))
		metrics.IncrementTotal()
		if queryLog != nil {
			queryLog.Add(QueryLogEntry{
				Timestamp: time.Now(), Domain: question.Name, QType: question.QType,
				QTypeName: qtypeName(question.QType), ResponseMs: 0,
				Status: "blocked", AnswerIP: "0.0.0.0", Source: "udp", ClientIP: ctx.Source.String(),
			})
		}
		return
	}

	fmt.Printf("╠══ Çözümleme Başlıyor ═════════════════════\n")

	// Metrik sayacı
	metrics.IncrementTotal()
	resolveStart := time.Now()

	// Gerçek rekursif çözümleme
	answers, err := resolve(question.Name, question.QType, 0)

	resolveDuration := time.Since(resolveStart)
	metrics.AddResolveTime(resolveDuration)

	var response []byte
	logEntry := QueryLogEntry{
		Timestamp: time.Now(), Domain: question.Name, QType: question.QType,
		QTypeName: qtypeName(question.QType), ResponseMs: float64(resolveDuration.Milliseconds()),
		Source: "udp", ClientIP: ctx.Source.String(),
	}

	if err != nil {
		fmt.Printf("║ ✗ Hata: %v\n", err)
		response = buildNXDOMAIN(ctx.Data[:ctx.Size])
		logEntry.Status = "nxdomain"
	} else {
		response = buildResponse(ctx.Data[:ctx.Size], ctx.Size, answers)
		for _, ans := range answers {
			if ans.Type == 1 && len(ans.RData) == 4 {
				logEntry.AnswerIP = fmt.Sprintf("%d.%d.%d.%d", ans.RData[0], ans.RData[1], ans.RData[2], ans.RData[3])
				fmt.Printf("║ ✓ %s → %s (TTL: %d)\n", question.Name, logEntry.AnswerIP, ans.TTL)
			}
		}
		if resolveDuration < 5*time.Millisecond {
			metrics.IncrementCached()
			logEntry.Status = "cached"
		} else {
			logEntry.Status = "resolved"
		}
	}

	if queryLog != nil {
		queryLog.Add(logEntry)
	}

	_, err = ctx.Conn.WriteToUDP(response, ctx.Source)
	if err != nil {
		fmt.Println("Yanıt gönderme hatası:", err)
		return
	}
	fmt.Printf("╚══ Yanıt gönderildi (%d byte, %dms) ═══════\n", len(response), resolveDuration.Milliseconds())
}

// ==================== DNS-over-TLS (DoT) — RFC 7858 ====================
// Port 8853 üzerinden TLS şifreli DNS hizmeti

func startDoTServer(certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("║ ⚠ DoT: Sertifika yüklenemedi: %v\n", err)
		fmt.Println("║   DoT devre dışı. Self-signed sertifika oluşturmak için:")
		fmt.Println("║   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes")
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.DoTPort), tlsConfig)
	if err != nil {
		fmt.Printf("║ ⚠ DoT dinleyici hatası: %v\n", err)
		return
	}

	fmt.Printf("║ 🔒 DNS-over-TLS (DoT) aktif — port %d\n", cfg.DoTPort)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleDoTConnection(conn)
		}
	}()
}

func handleDoTConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)

	for {
		// DNS over TCP: 2-byte uzunluk prefix
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(reader, lenBuf)
		if err != nil {
			return
		}

		msgLen := int(binary.BigEndian.Uint16(lenBuf))
		if msgLen < 12 || msgLen > 4096 {
			return
		}

		msg := make([]byte, msgLen)
		_, err = io.ReadFull(reader, msg)
		if err != nil {
			return
		}

		// Header ve soru ayrıştır
		header := parseHeader(msg[:12])
		question, _ := parseQuestion(msg[:msgLen], 12)

		fmt.Printf("\n╔══ DoT İstek ═══════════════════════════════\n")
		fmt.Printf("║ 🔒 Kaynak: %s (şifreli)\n", conn.RemoteAddr())
		fmt.Printf("║ ID:      0x%04x\n", header.ID)
		fmt.Printf("║ Sorgu:   %s (tip: %d)\n", question.Name, question.QType)

		// Reklam engelleme
		if blocker != nil && blocker.IsBlocked(question.Name) {
			fmt.Printf("║ 🛡️ ENGELLENDİ: %s\n", question.Name)
			response := buildBlockedResponse(msg)
			sendDoTResponse(conn, response)
			metrics.IncrementTotal()
			if queryLog != nil {
				queryLog.Add(QueryLogEntry{
					Timestamp: time.Now(), Domain: question.Name, QType: question.QType,
					QTypeName: qtypeName(question.QType), ResponseMs: 0,
					Status: "blocked", AnswerIP: "0.0.0.0", Source: "dot", ClientIP: conn.RemoteAddr().String(),
				})
			}
			continue
		}

		fmt.Printf("╠══ Çözümleme Başlıyor ═════════════════════\n")
		metrics.IncrementTotal()
		resolveStart := time.Now()

		answers, err := resolve(question.Name, question.QType, 0)
		resolveDuration := time.Since(resolveStart)
		metrics.AddResolveTime(resolveDuration)

		var response []byte
		dotLogEntry := QueryLogEntry{
			Timestamp: time.Now(), Domain: question.Name, QType: question.QType,
			QTypeName: qtypeName(question.QType), ResponseMs: float64(resolveDuration.Milliseconds()),
			Source: "dot", ClientIP: conn.RemoteAddr().String(),
		}

		if err != nil {
			response = buildNXDOMAIN(msg)
			dotLogEntry.Status = "nxdomain"
		} else {
			response = buildResponse(msg, msgLen, answers)
			if resolveDuration < 5*time.Millisecond {
				metrics.IncrementCached()
				dotLogEntry.Status = "cached"
			} else {
				dotLogEntry.Status = "resolved"
			}
			for _, ans := range answers {
				if ans.Type == 1 && len(ans.RData) == 4 {
					dotLogEntry.AnswerIP = fmt.Sprintf("%d.%d.%d.%d", ans.RData[0], ans.RData[1], ans.RData[2], ans.RData[3])
				}
			}
		}

		if queryLog != nil {
			queryLog.Add(dotLogEntry)
		}

		sendDoTResponse(conn, response)
		fmt.Printf("╚══ DoT Yanıt (%d byte, %dms) ═══════════════\n",
			len(response), resolveDuration.Milliseconds())
	}
}

func sendDoTResponse(conn net.Conn, response []byte) {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(response)))
	conn.Write(append(lenBuf, response...))
}

// ==================== DNS-over-HTTPS (DoH) — RFC 8484 ====================
// Port 8443 üzerinden HTTPS şifreli DNS hizmeti

func startDoHServer(certFile, keyFile string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", handleDoHRequest)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.DoHPort),
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Sertifika kontrolü
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("║ ⚠ DoH: Sertifika yüklenemedi, HTTP modunda başlatılıyor (port %d)\n", cfg.DoHPort)
		// TLS olmadan HTTP (geliştirme/test amaçlı)
		httpServer := &http.Server{
			Addr:         fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.DoHPort),
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		fmt.Printf("║ 🌐 DNS-over-HTTP (test) aktif — http://%s:%d/dns-query\n", cfg.BindAddr, cfg.DoHPort)
		go func() {
			if err := httpServer.ListenAndServe(); err != nil {
				fmt.Printf("║ ⚠ DoH HTTP hatası: %v\n", err)
			}
		}()
		return
	}

	fmt.Printf("║ 🔒 DNS-over-HTTPS (DoH) aktif — https://%s:%d/dns-query\n", cfg.BindAddr, cfg.DoHPort)
	go func() {
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			fmt.Printf("║ ⚠ DoH HTTPS hatası: %v\n", err)
		}
	}()
}

func handleDoHRequest(w http.ResponseWriter, r *http.Request) {
	var dnsMsg []byte

	switch r.Method {
	case http.MethodPost:
		// POST: Gövde doğrudan DNS wire format
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Content-Type must be application/dns-message", http.StatusBadRequest)
			return
		}
		var err error
		dnsMsg, err = io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "Read error", http.StatusBadRequest)
			return
		}

	case http.MethodGet:
		// GET: ?dns= parametresi (base64url encoded) — basitleştirilmiş
		http.Error(w, "GET method: use POST with application/dns-message", http.StatusMethodNotAllowed)
		return

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(dnsMsg) < 12 {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	// Ayrıştır
	header := parseHeader(dnsMsg[:12])
	question, _ := parseQuestion(dnsMsg, 12)

	fmt.Printf("\n╔══ DoH İstek ═══════════════════════════════\n")
	fmt.Printf("║ 🌐 Kaynak: %s (HTTPS)\n", r.RemoteAddr)
	fmt.Printf("║ ID:      0x%04x\n", header.ID)
	fmt.Printf("║ Sorgu:   %s (tip: %d)\n", question.Name, question.QType)

	// Reklam engelleme
	if blocker != nil && blocker.IsBlocked(question.Name) {
		fmt.Printf("║ 🛡️ ENGELLENDİ: %s\n", question.Name)
		response := buildBlockedResponse(dnsMsg)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(response)
		metrics.IncrementTotal()
		if queryLog != nil {
			queryLog.Add(QueryLogEntry{
				Timestamp: time.Now(), Domain: question.Name, QType: question.QType,
				QTypeName: qtypeName(question.QType), ResponseMs: 0,
				Status: "blocked", AnswerIP: "0.0.0.0", Source: "doh", ClientIP: r.RemoteAddr,
			})
		}
		return
	}

	fmt.Printf("╠══ Çözümleme Başlıyor ═════════════════════\n")
	metrics.IncrementTotal()
	resolveStart := time.Now()

	answers, err := resolve(question.Name, question.QType, 0)
	resolveDuration := time.Since(resolveStart)
	metrics.AddResolveTime(resolveDuration)

	var response []byte
	logEntry := QueryLogEntry{
		Timestamp: time.Now(), Domain: question.Name, QType: question.QType,
		QTypeName: qtypeName(question.QType), ResponseMs: float64(resolveDuration.Milliseconds()),
		Source: "doh", ClientIP: r.RemoteAddr,
	}

	if err != nil {
		response = buildNXDOMAIN(dnsMsg)
		logEntry.Status = "nxdomain"
	} else {
		response = buildResponse(dnsMsg, len(dnsMsg), answers)
		if resolveDuration < 5*time.Millisecond {
			metrics.IncrementCached()
			logEntry.Status = "cached"
		} else {
			logEntry.Status = "resolved"
		}
		for _, ans := range answers {
			if ans.Type == 1 && len(ans.RData) == 4 {
				logEntry.AnswerIP = fmt.Sprintf("%d.%d.%d.%d", ans.RData[0], ans.RData[1], ans.RData[2], ans.RData[3])
			}
		}
	}

	if queryLog != nil {
		queryLog.Add(logEntry)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", 300))
	w.Write(response)

	fmt.Printf("╚══ DoH Yanıt (%d byte, %dms) ═══════════════\n",
		len(response), resolveDuration.Milliseconds())
}
