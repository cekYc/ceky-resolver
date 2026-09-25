package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func ask(t *testing.T, name string, qtype uint16, edns, overUDP bool) *DNSMessage {
	t.Helper()
	raw := handleDNSMessage(makeQuery(name, qtype, edns), "udp", "127.0.0.1", overUDP)
	msg, err := parseMessage(raw)
	if err != nil {
		t.Fatalf("%s: yanıt ayrıştırılamadı: %v", name, err)
	}
	return msg
}

func TestHandlerResolves(t *testing.T) {
	port, _ := testHierarchy(t)
	setupGlobals(t, testResolver(port))

	msg := ask(t, "alias.example.test", typeA, true, true)
	if msg.Header.Rcode() != rcodeSuccess || len(msg.Answers) != 2 {
		t.Fatalf("CNAME + A bekleniyordu: rcode=%d n=%d", msg.Header.Rcode(), len(msg.Answers))
	}
	if normalizeName(msg.Answers[1].Name) != "www.example.test" {
		t.Fatalf("A kaydının sahibi CNAME hedefi olmalı, gelen %q", msg.Answers[1].Name)
	}

	if msg := ask(t, "yok.example.test", typeA, false, true); msg.Header.Rcode() != rcodeNXDomain {
		t.Fatalf("NXDOMAIN bekleniyordu, gelen %d", msg.Header.Rcode())
	}
	if msg := ask(t, "www.example.test", typeAAAA, false, true); msg.Header.Rcode() != rcodeSuccess || len(msg.Answers) != 0 {
		t.Fatal("AAAA için NODATA (NOERROR, boş) bekleniyordu")
	}

	if e := queryLog.Recent(1); len(e) != 1 || e[0].Domain != "www.example.test" {
		t.Fatalf("sorgu kaydı eksik: %+v", e)
	}
}

func TestHandlerTruncatesLargeUDPReplies(t *testing.T) {
	port, _ := testHierarchy(t)
	setupGlobals(t, testResolver(port))

	if msg := ask(t, "big.example.test", typeTXT, false, true); msg.Header.Flags&flagTC == 0 {
		t.Fatal("EDNS'siz UDP istemcisine büyük yanıt TC=1 ile gitmeli")
	}
	if msg := ask(t, "big.example.test", typeTXT, false, false); len(msg.Answers) != 40 {
		t.Fatalf("TCP üzerinden tam yanıt gitmeli, gelen %d", len(msg.Answers))
	}
}

func TestHandlerBlocksAds(t *testing.T) {
	setupGlobals(t, testResolver("1"))
	blocker.domains["ads.example.test"] = struct{}{}
	blocker.enabled.Store(true)

	msg := ask(t, "x.ads.example.test", typeA, false, true)
	if len(msg.Answers) != 1 || recordIP(msg.Answers[0]) != "0.0.0.0" {
		t.Fatalf("A için 0.0.0.0 bekleniyordu: %+v", msg.Answers)
	}
	msg = ask(t, "ads.example.test", typeAAAA, false, true)
	if len(msg.Answers) != 1 || recordIP(msg.Answers[0]) != "::" {
		t.Fatalf("AAAA için :: bekleniyordu: %+v", msg.Answers)
	}
	msg = ask(t, "ads.example.test", typeHTTPS, false, true)
	if msg.Header.Rcode() != rcodeSuccess || len(msg.Answers) != 0 {
		t.Fatal("diğer türler için boş NOERROR bekleniyordu")
	}

	blocker.allow["x.ads.example.test"] = struct{}{}
	if blocker.IsBlocked("x.ads.example.test") || !blocker.IsBlocked("y.ads.example.test") {
		t.Fatal("izin listesi yalnızca kendisini ve alt alanlarını kapsamalı")
	}
}

func TestHandlerLocalNames(t *testing.T) {
	setupGlobals(t, testResolver("1", "127.0.0.99"))

	if msg := ask(t, "localhost", typeA, false, true); len(msg.Answers) != 1 || recordIP(msg.Answers[0]) != "127.0.0.1" {
		t.Fatal("localhost → 127.0.0.1 olmalı")
	}
	// Firefox'un Cloudflare DoH'a geçmesini engelleyen kanarya
	if msg := ask(t, "use-application-dns.net", typeA, false, true); msg.Header.Rcode() != rcodeNXDomain {
		t.Fatal("use-application-dns.net NXDOMAIN olmalı")
	}
	// Özel IP'lerin ters kayıtları ve .lan internete sızmamalı
	for _, name := range []string{"1.1.168.192.in-addr.arpa", "5.0.20.172.in-addr.arpa", "yazici.lan", "nas.home.arpa"} {
		if msg := ask(t, name, typePTR, false, true); msg.Header.Rcode() != rcodeNXDomain {
			t.Errorf("%s yerelde NXDOMAIN olmalı, gelen %d", name, msg.Header.Rcode())
		}
	}
}

func TestHandlerLocalForwarding(t *testing.T) {
	port, _ := startMockServers(t, map[string]func(DNSQuestion) *mockReply{
		"127.0.0.6": func(q DNSQuestion) *mockReply { // Modem DNS'i
			if normalizeName(q.Name) == "nas.lan" {
				return &mockReply{ra: true, answers: []DNSRecord{rrA(q.Name, "192.168.1.20")}}
			}
			return &mockReply{rcode: rcodeNXDomain, ra: true}
		},
	})
	setupGlobals(t, testResolver(port, "127.0.0.99"))
	cfg.LocalForwarders = []string{"127.0.0.6"}

	msg := ask(t, "nas.lan", typeA, false, true)
	if len(msg.Answers) != 1 || recordIP(msg.Answers[0]) != "192.168.1.20" {
		t.Fatalf("yerel isim modeme sorulmalı: rcode=%d %+v", msg.Header.Rcode(), msg.Answers)
	}
}

func TestHandlerRejectsBadPackets(t *testing.T) {
	setupGlobals(t, testResolver("1"))

	garbage := []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}
	resp := handleDNSMessage(garbage, "udp", "127.0.0.1", true)
	if resp == nil || resp[3]&0x0F != rcodeFormErr || binary.BigEndian.Uint16(resp) != 0x1234 {
		t.Fatalf("bozuk pakete FORMERR bekleniyordu: %x", resp)
	}

	reply := makeQuery("example.test", typeA, false)
	reply[2] |= 0x80 // QR=1 — bu bir yanıt
	if handleDNSMessage(reply, "udp", "127.0.0.1", true) != nil {
		t.Fatal("yanıt paketlerine yanıt verilmemeli")
	}
}

func TestClientACL(t *testing.T) {
	cfg = defaultConfig()
	for _, ip := range []string{"127.0.0.1", "::1", "192.168.1.5", "10.0.0.2", "100.64.3.4", "fe80::1"} {
		if !clientAllowed(net.ParseIP(ip)) {
			t.Errorf("%s yerel sayılmalı", ip)
		}
	}
	if clientAllowed(net.ParseIP("8.8.8.8")) {
		t.Error("internetten gelen sorgular varsayılanda reddedilmeli (açık çözümleyici olmamak için)")
	}
}

func TestListenersEndToEnd(t *testing.T) {
	port, _ := testHierarchy(t)
	setupGlobals(t, testResolver(port))

	// Boş bir port bul
	l, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	dnsPort := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()

	bound, closers, err := startDNSListeners([]string{"127.0.0.1"}, dnsPort)
	if err != nil {
		t.Skipf("dinleyici açılamadı: %v", err)
	}
	defer closeAll(closers)
	if len(bound) != 1 {
		t.Fatalf("beklenen 1 adres, gelen %v", bound)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)

	// UDP
	conn, _ := net.Dial("udp", addr)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(makeQuery("www.example.test", typeA, true))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if msg, _ := parseMessage(buf[:n]); msg == nil || len(msg.Answers) != 1 {
		t.Fatal("UDP üzerinden yanıt alınamadı")
	}

	// TCP (aynı bağlantıda iki sorgu)
	tc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	for _, name := range []string{"www.example.test", "big.example.test"} {
		q := makeQuery(name, map[string]uint16{"www.example.test": typeA, "big.example.test": typeTXT}[name], false)
		tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(tc, lenBuf); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf))
		io.ReadFull(tc, resp)
		if msg, _ := parseMessage(resp); msg == nil || len(msg.Answers) == 0 {
			t.Fatalf("TCP yanıtı boş: %s", name)
		}
	}
}
