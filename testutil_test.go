package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ==================== TEST YARDIMCILARI: SAHTE DNS HİYERARŞİSİ ====================
//
// 127.0.0.x adreslerinde çalışan küçük yetkili sunucular:
//   127.0.0.2  kök (.)
//   127.0.0.3  "test" TLD'si
//   127.0.0.4  example.test, noglue.test, lame.test (sağlam)
//   127.0.0.5  lame.test (REFUSED döndüren bozuk sunucu)
//   127.0.0.9  "kötü" sunucu — her şeye 6.6.6.6 der (hiç sorulmamalı)

type mockReply struct {
	rcode      int
	aa         bool
	ra         bool
	answers    []DNSRecord
	authority  []DNSRecord
	additional []DNSRecord
	tcOverUDP  bool
}

type mockServer struct {
	ip      string
	handler func(q DNSQuestion) *mockReply
	queries atomic.Int32
	udp     *net.UDPConn
	tcp     net.Listener
}

func rrA(name, ip string) DNSRecord {
	return DNSRecord{Name: name, Type: typeA, Class: classIN, TTL: 300, RData: net.ParseIP(ip).To4()}
}

func rrName(name string, rtype uint16, target string) DNSRecord {
	return DNSRecord{Name: name, Type: rtype, Class: classIN, TTL: 3600, RData: domainToBytes(target)}
}

func rrSOA(zone string) DNSRecord {
	rdata := append(domainToBytes("ns."+zone), domainToBytes("admin."+zone)...)
	for _, v := range []uint32{1, 3600, 600, 86400, 120} { // serial, refresh, retry, expire, minimum
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	return DNSRecord{Name: zone, Type: typeSOA, Class: classIN, TTL: 300, RData: rdata}
}

func mockResponse(req *DNSMessage, rep *mockReply, truncate bool) []byte {
	b := newMsgBuilder()
	h := DNSHeader{ID: req.Header.ID, Flags: flagQR | uint16(rep.rcode), QDCount: 1}
	if rep.aa {
		h.Flags |= flagAA
	}
	if rep.ra {
		h.Flags |= flagRA
	}
	q := req.Questions[0]
	b.writeName(q.Name)
	b.buf = binary.BigEndian.AppendUint16(b.buf, q.QType)
	b.buf = binary.BigEndian.AppendUint16(b.buf, q.QClass)
	if truncate {
		h.Flags |= flagTC
		return b.finish(h)
	}
	for _, rr := range rep.answers {
		b.writeRecord(rr)
	}
	for _, rr := range rep.authority {
		b.writeRecord(rr)
	}
	for _, rr := range rep.additional {
		b.writeRecord(rr)
	}
	h.ANCount, h.NSCount, h.ARCount = uint16(len(rep.answers)), uint16(len(rep.authority)), uint16(len(rep.additional))
	return b.finish(h)
}

func (m *mockServer) respond(raw []byte, overUDP bool) []byte {
	req, err := parseMessage(raw)
	if err != nil || len(req.Questions) != 1 {
		return nil
	}
	m.queries.Add(1)
	rep := m.handler(req.Questions[0])
	if rep == nil {
		return nil
	}
	return mockResponse(req, rep, overUDP && rep.tcOverUDP)
}

func (m *mockServer) serve() {
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := m.udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := m.respond(buf[:n], true); resp != nil {
				m.udp.WriteToUDP(resp, src)
			}
		}
	}()
	go func() {
		for {
			conn, err := m.tcp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				lenBuf := make([]byte, 2)
				if _, err := c.Read(lenBuf); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(lenBuf))
				if _, err := readFull(c, msg); err != nil {
					return
				}
				if resp := m.respond(msg, false); resp != nil {
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
				}
			}(conn)
		}
	}()
}

func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := c.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += k
	}
	return n, nil
}

func (m *mockServer) close() {
	m.udp.Close()
	m.tcp.Close()
}

// startMockServers — hepsi aynı portta, farklı loopback IP'lerinde.
//
// Port, işletim sisteminin verdiği geçici port yerine geniş bir aralıktan rastgele
// seçilir: Windows geçici portları neredeyse sıralı dağıtır ve CI makinelerinde
// Hyper-V/WinNAT TCP için yüzlük port blokları ayırır (excluded port range).
// Geçici port böyle bir bloğa denk gelince ardışık tüm denemeler aynı blokta kalıp
// başarısız oluyordu.
func startMockServers(t *testing.T, handlers map[string]func(DNSQuestion) *mockReply) (string, map[string]*mockServer) {
	t.Helper()
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Skipf("127.0.0.2 kullanılamıyor: %v", err) // ör. macOS'ta yalnızca 127.0.0.1 tanımlıdır
	}
	probe.Close()

	var lastErr error
	for attempt := 0; attempt < 100; attempt++ {
		port := 20000 + rand.IntN(25000)
		servers, err := bindMockServers(handlers, port)
		if err != nil {
			lastErr = err
			continue
		}
		for _, s := range servers {
			s.serve()
		}
		t.Cleanup(func() {
			for _, s := range servers {
				s.close()
			}
		})
		return fmt.Sprint(port), servers
	}
	t.Fatalf("sahte sunucular için ortak port bulunamadı (son hata: %v)", lastErr)
	return "", nil
}

// bindMockServers — tüm adreslerde aynı porta UDP+TCP bağlan; biri olmazsa hepsini kapat
func bindMockServers(handlers map[string]func(DNSQuestion) *mockReply, port int) (map[string]*mockServer, error) {
	servers := make(map[string]*mockServer)
	fail := func(err error) (map[string]*mockServer, error) {
		for _, s := range servers {
			s.close()
		}
		return nil, err
	}
	for ip, h := range handlers {
		addr := net.JoinHostPort(ip, fmt.Sprint(port))
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fail(err)
		}
		u, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fail(err)
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			u.Close()
			return fail(err)
		}
		servers[ip] = &mockServer{ip: ip, handler: h, udp: u, tcp: l}
	}
	return servers, nil
}

func under(name, zone string) bool {
	name = normalizeName(name)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// testHierarchy — tüm sahte sunucuları başlat
func testHierarchy(t *testing.T) (string, map[string]*mockServer) {
	bigTXT := func() []DNSRecord {
		var out []DNSRecord
		for i := 0; i < 40; i++ {
			txt := fmt.Sprintf("kayit-%02d-%s", i, strings.Repeat("x", 90))
			out = append(out, DNSRecord{Name: "big.example.test", Type: typeTXT, Class: classIN, TTL: 300,
				RData: append([]byte{byte(len(txt))}, txt...)})
		}
		return out
	}()

	return startMockServers(t, map[string]func(DNSQuestion) *mockReply{
		"127.0.0.2": func(q DNSQuestion) *mockReply { // KÖK
			switch {
			case normalizeName(q.Name) == "com" && q.QType == typeNS:
				return &mockReply{authority: []DNSRecord{rrName("com", typeNS, "a.gtld-servers.net")}}
			case under(q.Name, "test"):
				return &mockReply{
					authority:  []DNSRecord{rrName("test", typeNS, "ns1.nic.test")},
					additional: []DNSRecord{rrA("ns1.nic.test", "127.0.0.3")},
				}
			}
			return &mockReply{rcode: rcodeNXDomain, aa: true, authority: []DNSRecord{rrSOA("")}}
		},
		"127.0.0.3": func(q DNSQuestion) *mockReply { // TLD "test"
			switch {
			case under(q.Name, "example.test"):
				return &mockReply{
					authority:  []DNSRecord{rrName("example.test", typeNS, "ns1.example.test")},
					additional: []DNSRecord{rrA("ns1.example.test", "127.0.0.4")},
				}
			case under(q.Name, "noglue.test"): // Glue yok — NS adı ayrıca çözülmeli
				return &mockReply{authority: []DNSRecord{rrName("noglue.test", typeNS, "ns.example.test")}}
			case under(q.Name, "sibling.test"): // Yetki alanı dışı glue — güvenilmemeli
				return &mockReply{
					authority:  []DNSRecord{rrName("sibling.test", typeNS, "ns.evil.zz")},
					additional: []DNSRecord{rrA("ns.evil.zz", "127.0.0.9")},
				}
			case under(q.Name, "lame.test"):
				return &mockReply{
					authority:  []DNSRecord{rrName("lame.test", typeNS, "ns1.lame.test"), rrName("lame.test", typeNS, "ns2.lame.test")},
					additional: []DNSRecord{rrA("ns1.lame.test", "127.0.0.5"), rrA("ns2.lame.test", "127.0.0.4")},
				}
			}
			return &mockReply{rcode: rcodeNXDomain, aa: true, authority: []DNSRecord{rrSOA("test")}}
		},
		"127.0.0.4": func(q DNSQuestion) *mockReply { // example.test + noglue.test + lame.test
			name := normalizeName(q.Name)
			soa := []DNSRecord{rrSOA("example.test")}
			switch {
			case name == "www.example.test" && q.QType == typeA:
				return &mockReply{aa: true, answers: []DNSRecord{rrA(q.Name, "1.2.3.4")}}
			case name == "www.example.test":
				return &mockReply{aa: true, authority: soa} // NODATA
			case name == "alias.example.test" && q.QType == typeA:
				return &mockReply{aa: true, answers: []DNSRecord{
					rrName(q.Name, typeCNAME, "www.example.test"), rrA("www.example.test", "1.2.3.4")}}
			case name == "far.example.test":
				return &mockReply{aa: true, answers: []DNSRecord{rrName(q.Name, typeCNAME, "www.noglue.test")}}
			case name == "ns.example.test" && q.QType == typeA:
				return &mockReply{aa: true, answers: []DNSRecord{rrA(q.Name, "127.0.0.4")}}
			case name == "poison.example.test":
				return &mockReply{aa: true, answers: []DNSRecord{rrA(q.Name, "9.9.9.9"), rrA("www.victim.zz", "6.6.6.6")}}
			case name == "big.example.test" && q.QType == typeTXT:
				return &mockReply{aa: true, answers: bigTXT, tcOverUDP: true}
			case name == "mail.example.test" && q.QType == typeMX:
				return &mockReply{aa: true, answers: []DNSRecord{{Name: q.Name, Type: typeMX, Class: classIN, TTL: 300,
					RData: append([]byte{0, 10}, domainToBytes("mx1.example.test")...)}}}
			case name == "www.noglue.test" && q.QType == typeA:
				return &mockReply{aa: true, answers: []DNSRecord{rrA(q.Name, "5.6.7.8")}}
			case name == "www.lame.test" && q.QType == typeA:
				return &mockReply{aa: true, answers: []DNSRecord{rrA(q.Name, "7.7.7.7")}}
			}
			return &mockReply{rcode: rcodeNXDomain, aa: true, authority: soa}
		},
		"127.0.0.5": func(q DNSQuestion) *mockReply { // Bozuk (lame) sunucu
			return &mockReply{rcode: rcodeRefused}
		},
		"127.0.0.9": func(q DNSQuestion) *mockReply { // Araya giren (İSS benzeri) çözümleyici
			return &mockReply{ra: true, answers: []DNSRecord{rrA(q.Name, "6.6.6.6")}}
		},
	})
}

func testResolver(port string, roots ...string) *Resolver {
	if len(roots) == 0 {
		roots = []string{"127.0.0.2"}
	}
	r := newResolver(roots, newDNSCache(1000), newResolverMetrics())
	r.port = port
	r.udpTimeout = 400 * time.Millisecond
	r.tcpTimeout = time.Second
	return r
}

// setupGlobals — sunucu işleyicisinin kullandığı global nesneleri hazırla
func setupGlobals(t *testing.T, r *Resolver) {
	t.Helper()
	cfg = defaultConfig()
	resolver = r
	metrics = r.metrics
	queryLog = newQueryLog(100)
	blocker = newBlocklist()
	app = newApp("app")
	setAutoLocalForwarders(nil)
}

// makeQuery — istemci tarafı sorgu paketi (RD=1, isteğe bağlı EDNS)
func makeQuery(name string, qtype uint16, edns bool) []byte {
	q := buildQuery(name, qtype)
	q[2] |= byte(flagRD >> 8)
	if !edns {
		q = q[:len(q)-11] // OPT kaydını çıkar
		binary.BigEndian.PutUint16(q[10:12], 0)
	}
	return q
}
