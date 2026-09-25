//go:build darwin

package main

import (
	"fmt"
	"net"
	"strings"
)

// ==================== macOS: SİSTEM DNS ====================
//
// Her ağ servisinin (Wi-Fi, Ethernet, ...) DNS ayarı "networksetup" ile okunur
// ve değiştirilir. Boş liste = DHCP'den gelen DNS (geri yüklemede "Empty").

// networkServices — etkin ağ servisleri (devre dışı olanlar "*" ile başlar)
func networkServices() ([]string, error) {
	out, err := runSystemCmd("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("networksetup çalıştırılamadı: %v", err)
	}
	var services []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue // İlk satır açıklamadır
		}
		services = append(services, line)
	}
	return services, nil
}

func serviceDNS(service string) []string {
	out, _ := runSystemCmd("networksetup", "-getdnsservers", service)
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); net.ParseIP(s) != nil {
			servers = append(servers, s)
		}
	}
	// Önceki bir kurulumdan kalan 127.0.0.1 → "otomatik" say
	if len(withoutOurAddrs(servers)) != len(servers) {
		return nil
	}
	return servers
}

func platformBackup() (*sysDNSBackup, error) {
	services, err := networkServices()
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("ağ servisi bulunamadı")
	}
	b := &sysDNSBackup{Original: platformCurrent()}
	for _, s := range services {
		b.Darwin = append(b.Darwin, darwinServiceDNS{Service: s, Servers: serviceDNS(s)})
	}
	return b, nil
}

func applyToServices(entries []darwinServiceDNS, addrs []string) error {
	ok := 0
	var lastErr error
	for _, e := range entries {
		out, err := runSystemCmd("networksetup", append([]string{"-setdnsservers", e.Service}, addrs...)...)
		if err != nil {
			lastErr = fmt.Errorf("%s: %v %s", e.Service, err, strings.TrimSpace(out))
			continue
		}
		ok++
	}
	if ok == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

func platformApply(b *sysDNSBackup, addrs []string) error {
	return applyToServices(b.Darwin, addrs)
}

func platformRestore(b *sysDNSBackup) error {
	var lastErr error
	for _, e := range b.Darwin {
		args := []string{"-setdnsservers", e.Service}
		if len(e.Servers) == 0 {
			args = append(args, "Empty")
		} else {
			args = append(args, e.Servers...)
		}
		if out, err := runSystemCmd("networksetup", args...); err != nil {
			lastErr = fmt.Errorf("%s: %v %s", e.Service, err, strings.TrimSpace(out))
		}
	}
	return lastErr
}

// platformReconcile — sonradan oluşturulan ağ servislerini de yönlendir
func platformReconcile(b *sysDNSBackup) (bool, error) {
	services, err := networkServices()
	if err != nil {
		return false, err
	}
	known := make(map[string]bool)
	for _, e := range b.Darwin {
		known[e.Service] = true
	}
	var added []darwinServiceDNS
	for _, s := range services {
		if !known[s] {
			added = append(added, darwinServiceDNS{Service: s, Servers: serviceDNS(s)})
		}
	}
	if len(added) == 0 {
		return false, nil
	}
	b.Darwin = append(b.Darwin, added...)
	return true, applyToServices(added, b.Addrs)
}

// platformCurrent — "scutil --dns" çıktısındaki nameserver satırları
func platformCurrent() []string {
	out, _ := runSystemCmd("scutil", "--dns")
	var servers []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			s := strings.TrimSpace(line[i+1:])
			if net.ParseIP(s) != nil && !seen[s] {
				seen[s] = true
				servers = append(servers, s)
			}
		}
	}
	return servers
}

func flushOSCache() {
	runSystemCmd("dscacheutil", "-flushcache")
	runSystemCmd("killall", "-HUP", "mDNSResponder")
}
