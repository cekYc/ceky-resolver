package main

import (
	"testing"
	"time"
)

func answerIPs(ans Answer) []string {
	var out []string
	for _, rr := range ans.Records {
		if ip := recordIP(rr); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

func TestResolveThroughHierarchy(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)

	ans := r.Resolve("WWW.Example.Test.", typeA)
	if ans.Rcode != rcodeSuccess || len(answerIPs(ans)) != 1 || answerIPs(ans)[0] != "1.2.3.4" {
		t.Fatalf("beklenen 1.2.3.4, gelen rcode=%d %v", ans.Rcode, answerIPs(ans))
	}
	if ans.Cached {
		t.Fatal("ilk yanıt önbellekten gelmemeli")
	}
	if again := r.Resolve("www.example.test", typeA); !again.Cached {
		t.Fatal("ikinci yanıt önbellekten gelmeli")
	}
	if zone, servers := r.zones.closest("mail.example.test"); zone != "example.test" || len(servers) == 0 {
		t.Fatalf("delegasyon önbelleğe alınmalı, gelen %q %v", zone, servers)
	}
}

func TestDelegationCacheSkipsRoot(t *testing.T) {
	port, servers := testHierarchy(t)
	r := testResolver(port)
	r.Resolve("www.example.test", typeA)
	rootBefore := servers["127.0.0.2"].queries.Load()
	r.Resolve("alias.example.test", typeA)
	if got := servers["127.0.0.2"].queries.Load(); got != rootBefore {
		t.Fatalf("bilinen bölge için kök sunucuya tekrar sorulmamalı (%d → %d)", rootBefore, got)
	}
}

func TestNoDataIsNotNXDomain(t *testing.T) {
	// Eski sürüm IPv4-only alan adlarının AAAA sorgusuna NXDOMAIN döndürüyordu;
	// bu, tarayıcıların siteyi "yok" sanmasına yol açar.
	port, _ := testHierarchy(t)
	r := testResolver(port)
	ans := r.Resolve("www.example.test", typeAAAA)
	if ans.Rcode != rcodeSuccess || len(ans.Records) != 0 {
		t.Fatalf("NODATA bekleniyordu, gelen rcode=%d kayıt=%d", ans.Rcode, len(ans.Records))
	}
	if len(ans.Authority) != 1 || ans.Authority[0].Type != typeSOA {
		t.Fatal("NODATA yanıtında SOA olmalı")
	}
}

func TestNXDomain(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	for _, name := range []string{"nx.example.test", "yok.test", "hic.zz"} {
		if ans := r.Resolve(name, typeA); ans.Rcode != rcodeNXDomain {
			t.Errorf("%s: NXDOMAIN bekleniyordu, gelen %d", name, ans.Rcode)
		}
	}
}

func TestCNAMEChains(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)

	ans := r.Resolve("alias.example.test", typeA)
	if len(ans.Records) != 2 || ans.Records[0].Type != typeCNAME || answerIPs(ans)[0] != "1.2.3.4" {
		t.Fatalf("aynı bölgede CNAME zinciri hatalı: %+v", ans.Records)
	}

	// Başka bölgeye CNAME + o bölgenin NS'inin glue kaydı yok
	ans = r.Resolve("far.example.test", typeA)
	if ans.Rcode != rcodeSuccess || len(answerIPs(ans)) != 1 || answerIPs(ans)[0] != "5.6.7.8" {
		t.Fatalf("bölgeler arası CNAME çözülemedi: rcode=%d %+v", ans.Rcode, ans.Records)
	}
	if ans.Records[0].Type != typeCNAME || rdataName(ans.Records[0].RData) != "www.noglue.test" {
		t.Fatal("yanıt CNAME kaydıyla başlamalı")
	}
}

func TestPoisonedAnswersIgnored(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	ans := r.Resolve("poison.example.test", typeA)
	if ips := answerIPs(ans); len(ips) != 1 || ips[0] != "9.9.9.9" {
		t.Fatalf("yalnızca sorulan ismin kaydı dönmeli, gelen %v", ips)
	}
	if _, ok := r.cache.Get("www.victim.zz", typeA); ok {
		t.Fatal("alakasız kayıt önbelleğe girmemeli")
	}
}

func TestOutOfBailiwickGlueRejected(t *testing.T) {
	port, servers := testHierarchy(t)
	r := testResolver(port)
	ans := r.Resolve("www.sibling.test", typeA)
	if ans.Rcode != rcodeServFail {
		t.Fatalf("SERVFAIL bekleniyordu, gelen %d %v", ans.Rcode, answerIPs(ans))
	}
	if n := servers["127.0.0.9"].queries.Load(); n != 0 {
		t.Fatalf("yetki alanı dışındaki glue adresine sorgu gitmemeli (%d sorgu)", n)
	}
}

func TestHijackedAnswersRejected(t *testing.T) {
	// Kök sunucu adresine giden sorguyu bir İSS çözümleyicisi yanıtlarsa (AA=0, RA=1)
	// uydurulmuş cevap kabul edilmemeli
	port, _ := testHierarchy(t)
	r := testResolver(port, "127.0.0.9")
	if ans := r.Resolve("www.example.test", typeA); ans.Rcode != rcodeServFail {
		t.Fatalf("yetkisiz cevap reddedilmeliydi, gelen rcode=%d %v", ans.Rcode, answerIPs(ans))
	}
}

func TestLameServerSkipped(t *testing.T) {
	port, _ := testHierarchy(t)
	for i := 0; i < 5; i++ { // Sunucu sırası rastgele
		r := testResolver(port)
		if ips := answerIPs(r.Resolve("www.lame.test", typeA)); len(ips) != 1 || ips[0] != "7.7.7.7" {
			t.Fatalf("bozuk sunucu atlanmalıydı, gelen %v", ips)
		}
	}
}

func TestTruncatedFallsBackToTCP(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	ans := r.Resolve("big.example.test", typeTXT)
	if ans.Rcode != rcodeSuccess || len(ans.Records) != 40 {
		t.Fatalf("TCP ile 40 TXT kaydı bekleniyordu, gelen rcode=%d n=%d", ans.Rcode, len(ans.Records))
	}
}

func TestForceTCPTransport(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	r.forceTCP.Store(true)
	if ips := answerIPs(r.Resolve("www.example.test", typeA)); len(ips) != 1 {
		t.Fatalf("yalnızca TCP ile de çözülmeli, gelen %v", ips)
	}
}

func TestMXRDataSurvives(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	ans := r.Resolve("mail.example.test", typeMX)
	if len(ans.Records) != 1 || rdataName(ans.Records[0].RData[2:]) != "mx1.example.test" {
		t.Fatalf("MX kaydı bozuk: %+v", ans.Records)
	}
}

func TestServeStaleWhenUpstreamDown(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	r.Resolve("www.example.test", typeA)

	// Kaydın süresini doldur, tüm sunucuları erişilemez yap
	key := cacheKey("www.example.test", typeA)
	r.cache.mu.Lock()
	e := r.cache.entries[key]
	e.ExpiresAt = time.Now().Add(-time.Minute)
	r.cache.entries[key] = e
	r.cache.mu.Unlock()
	r.zones.flush()
	r.roots = []string{"127.0.0.99"}

	ans := r.Resolve("www.example.test", typeA)
	if ans.Rcode != rcodeSuccess || len(answerIPs(ans)) != 1 || ans.Records[0].TTL != staleReplyTTL {
		t.Fatalf("bayat yanıt bekleniyordu, gelen rcode=%d %+v", ans.Rcode, ans.Records)
	}
}

func TestProbeDetectsInterception(t *testing.T) {
	port, _ := testHierarchy(t)

	if got := testResolver(port, "127.0.0.2").probeTransport(false); got != "ok" {
		t.Errorf("gerçek kök sunucu: ok bekleniyordu, gelen %s", got)
	}
	if got := testResolver(port, "127.0.0.9").probeTransport(false); got != "intercepted" {
		t.Errorf("araya giren sunucu: intercepted bekleniyordu, gelen %s", got)
	}
	if got := testResolver(port, "127.0.0.99").probeTransport(false); got != "blocked" {
		t.Errorf("yanıtsız sunucu: blocked bekleniyordu, gelen %s", got)
	}
	p := testResolver(port, "127.0.0.9").Probe()
	if p.Healthy() {
		t.Error("müdahale edilen ağ sağlıklı sayılmamalı")
	}
}

func TestTraceShowsEveryHop(t *testing.T) {
	port, _ := testHierarchy(t)
	r := testResolver(port)
	r.Resolve("www.example.test", typeA) // Trace önbelleği kullanmamalı

	steps, ans := r.Trace("www.example.test", typeA)
	if ans.Rcode != rcodeSuccess {
		t.Fatalf("trace çözümlemesi başarısız: %d", ans.Rcode)
	}
	kinds := []string{}
	for _, s := range steps {
		kinds = append(kinds, s.Kind)
	}
	if len(steps) != 3 || kinds[0] != "root" || kinds[1] != "tld" || kinds[2] != "auth" {
		t.Fatalf("kök → TLD → yetkili adımları bekleniyordu, gelen %v", kinds)
	}
}

func TestSingleflightCoalesces(t *testing.T) {
	port, servers := testHierarchy(t)
	r := testResolver(port)
	done := make(chan Answer, 10)
	for i := 0; i < 10; i++ {
		go func() { done <- r.Resolve("www.noglue.test", typeA) }()
	}
	for i := 0; i < 10; i++ {
		if ans := <-done; len(answerIPs(ans)) != 1 {
			t.Fatalf("eşzamanlı sorgu başarısız: %+v", ans)
		}
	}
	if n := servers["127.0.0.2"].queries.Load(); n > 3 {
		t.Fatalf("eşzamanlı özdeş sorgular birleştirilmeli; köke %d sorgu gitti", n)
	}
}
