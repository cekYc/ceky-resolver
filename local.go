package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

// ==================== YEREL YANITLAR ====================

// Yalnızca yerel ağda anlamı olan alan adları — kök sunuculara sızdırılmaz
var localSuffixes = []string{
	"local", "lan", "home", "home.arpa", "internal", "localdomain", "intranet", "private",
}

// Özel IP bloklarının ters (PTR) bölgeleri — RFC 6303
var privateReverseZones = func() []string {
	zones := []string{
		"10.in-addr.arpa", "127.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
		"d.f.ip6.arpa", "c.f.ip6.arpa", // fc00::/7
		"8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa", // fe80::/10
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", // ::1
	}
	for i := 16; i <= 31; i++ {
		zones = append(zones, fmt.Sprintf("%d.172.in-addr.arpa", i))
	}
	return zones
}()

func hasZoneSuffix(name string, zones []string) bool {
	for _, z := range zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return true
		}
	}
	return false
}

// localAnswer — internete çıkmadan yanıtlanabilen sorgular
func localAnswer(name string, qtype uint16) (Answer, bool) {
	switch {
	case name == "localhost" || strings.HasSuffix(name, ".localhost"):
		var records []DNSRecord
		switch qtype {
		case typeA:
			records = []DNSRecord{{Name: name, Type: typeA, Class: classIN, TTL: 3600, RData: []byte{127, 0, 0, 1}}}
		case typeAAAA:
			records = []DNSRecord{{Name: name, Type: typeAAAA, Class: classIN, TTL: 3600, RData: net.IPv6loopback}}
		}
		return Answer{Rcode: rcodeSuccess, Records: records}, true

	case name == "use-application-dns.net":
		// Firefox bu alan adı yoksa kendi DoH sağlayıcısına (Cloudflare) geçmez.
		// Amaç hiçbir aracı DNS'e bağlı kalmamak olduğu için NXDOMAIN döndürülür.
		return Answer{Rcode: rcodeNXDomain}, true

	case hasZoneSuffix(name, privateReverseZones) || hasZoneSuffix(name, localSuffixes):
		if ans, ok := forwardLocal(name, qtype); ok {
			return ans, true
		}
		return Answer{Rcode: rcodeNXDomain}, true

	case name != "" && !strings.Contains(name, ".") && (qtype == typeA || qtype == typeAAAA):
		// Tek etiketli isimler ("nas", "router") önce modemin DNS'ine sorulur;
		// yerel sunucu yoksa normal şekilde kökten çözülür
		if ans, ok := forwardLocal(name, qtype); ok {
			return ans, true
		}
	}
	return Answer{}, false
}

// ==================== YEREL YÖNLENDİRME ====================

var (
	localFwdMu   sync.RWMutex
	autoLocalFwd []string // Sistem DNS yedeğinden bulunan modem/yerel DNS adresleri
)

func setAutoLocalForwarders(servers []string) {
	localFwdMu.Lock()
	defer localFwdMu.Unlock()
	autoLocalFwd = servers
}

// localForwarders — yerel isimlerin sorulacağı sunucular (yalnızca özel IP'ler)
func localForwarders() []string {
	localFwdMu.RLock()
	defer localFwdMu.RUnlock()
	var out []string
	seen := make(map[string]bool)
	add := func(s string, allowLoopback bool) {
		ip := net.ParseIP(s)
		if ip == nil || seen[s] || !(ip.IsPrivate() || ip.IsLinkLocalUnicast() || (allowLoopback && ip.IsLoopback())) {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range cfg.LocalForwarders {
		add(s, true)
	}
	// Otomatik bulunanlarda loopback yok: ör. systemd-resolved (127.0.0.53) sorguyu
	// tekrar bize göndereceği için döngü oluşurdu
	for _, s := range autoLocalFwd {
		add(s, false)
	}
	return out
}

// forwardLocal — yerel ismi modemin/yerel ağın DNS sunucusuna sor
func forwardLocal(name string, qtype uint16) (Answer, bool) {
	servers := localForwarders()
	if len(servers) == 0 || resolver == nil {
		return Answer{}, false
	}
	if ans, ok := resolver.cache.Get(name, qtype); ok {
		return ans, true
	}
	for _, server := range servers {
		query := buildQuery(name, qtype)
		query[2] |= byte(flagRD >> 8) // Yerel sunucudan özyineleme iste
		raw, err := resolver.exchangeUDP(server, query)
		if err != nil {
			continue
		}
		msg, err := parseMessage(raw)
		if err != nil || msg.Header.ID != binary.BigEndian.Uint16(query) || len(msg.Questions) != 1 ||
			normalizeName(msg.Questions[0].Name) != name {
			continue
		}
		rcode := msg.Header.Rcode()
		if rcode != rcodeSuccess && rcode != rcodeNXDomain {
			continue
		}
		_, _, chain := followChain(name, qtype, msg.Answers)
		ans := Answer{Rcode: rcode, Records: chain, Authority: soaRecords(msg)}
		resolver.cache.Set(name, qtype, ans)
		return ans, true
	}
	return Answer{}, false
}
