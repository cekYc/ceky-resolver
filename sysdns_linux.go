//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// ==================== LINUX: SİSTEM DNS ====================
//
// İki yöntem:
//  1. systemd-resolved çalışıyorsa ona "tüm alan adları için 127.0.0.1'e sor"
//     yapılandırması eklenir (Domains=~.). Yerel ağ arama alanları modeme gitmeye
//     devam eder.
//  2. Aksi halde /etc/resolv.conf yedeklenip yeniden yazılır; NetworkManager
//     varsa dosyanın üzerine yazmaması için "dns=none" ayarı eklenir.

// Testlerde geçici dizinlerle değiştirilebilir
var (
	resolvConfPath    = "/etc/resolv.conf"
	resolvedDropInDir = "/etc/systemd/resolved.conf.d"
	nmDropInDir       = "/etc/NetworkManager/conf.d"
)

const (
	dropInName   = "90-ceky-resolver.conf"
	resolvMarker = "# Ceky Resolver tarafından yönetiliyor"
)

func systemdResolvedActive() bool {
	out, err := runSystemCmd("systemctl", "is-active", "systemd-resolved")
	return err == nil && strings.TrimSpace(out) == "active"
}

func networkManagerActive() bool {
	out, err := runSystemCmd("systemctl", "is-active", "NetworkManager")
	return err == nil && strings.TrimSpace(out) == "active"
}

// resolvConfNameservers — resolv.conf içindeki nameserver adresleri
func resolvConfNameservers(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
			out = append(out, f[1])
		}
	}
	return out
}

// usesResolvedStub — resolv.conf systemd-resolved'ın 127.0.0.53 adresine mi bakıyor?
func usesResolvedStub(content string) bool {
	for _, ns := range resolvConfNameservers(content) {
		if ns == "127.0.0.53" {
			return true
		}
	}
	return false
}

func ourResolvConf(addrs []string) string {
	var sb strings.Builder
	sb.WriteString(resolvMarker + " — geri almak için: sudo ceky-resolver restore\n")
	for _, a := range addrs {
		sb.WriteString("nameserver " + a + "\n")
	}
	sb.WriteString("options edns0 trust-ad\n")
	return sb.String()
}

func platformBackup() (*sysDNSBackup, error) {
	lb := &linuxDNSBackup{}
	if info, err := os.Lstat(resolvConfPath); err == nil {
		lb.ResolvConfExisted = true
		if info.Mode()&os.ModeSymlink != 0 {
			lb.ResolvConfLink, _ = os.Readlink(resolvConfPath)
		} else {
			data, _ := os.ReadFile(resolvConfPath)
			lb.ResolvConfContent = string(data)
		}
	}
	b := &sysDNSBackup{Linux: lb}
	if data, err := os.ReadFile(resolvConfPath); err == nil {
		b.Original = resolvConfNameservers(string(data))
	}
	return b, nil
}

func platformApply(b *sysDNSBackup, addrs []string) error {
	lb := b.Linux
	if lb == nil {
		return fmt.Errorf("Linux yedeği eksik")
	}
	current, _ := os.ReadFile(resolvConfPath)

	// 1) systemd-resolved
	if systemdResolvedActive() {
		conf := "# Ceky Resolver — tüm DNS sorguları yerel rekürsif çözümleyiciye\n[Resolve]\nDNS=" +
			strings.Join(addrs, " ") + "\nDomains=~.\n"
		if err := writeFileAtomic(filepath.Join(resolvedDropInDir, dropInName), []byte(conf), 0644); err != nil {
			return err
		}
		lb.ResolvedDropIn = true
		if out, err := runSystemCmd("systemctl", "restart", "systemd-resolved"); err != nil {
			return fmt.Errorf("systemd-resolved yeniden başlatılamadı: %v %s", err, out)
		}
		if usesResolvedStub(string(current)) {
			return nil // Uygulamalar zaten resolved üzerinden bize ulaşıyor
		}
	}

	// 2) NetworkManager resolv.conf'a dokunmasın
	if _, err := os.Stat(nmDropInDir); err == nil {
		conf := "# Ceky Resolver — resolv.conf'u NetworkManager değil Ceky yönetiyor\n[main]\ndns=none\n"
		if err := writeFileAtomic(filepath.Join(nmDropInDir, dropInName), []byte(conf), 0644); err != nil {
			return err
		}
		lb.NMDropIn = true
		if networkManagerActive() {
			runSystemCmd("systemctl", "reload", "NetworkManager")
		}
	}

	// 3) resolv.conf'u yaz (sembolik bağlantıysa bağlantının kendisi değiştirilir)
	lb.ResolvConfManaged = true
	return writeFileAtomic(resolvConfPath, []byte(ourResolvConf(addrs)), 0644)
}

func platformRestore(b *sysDNSBackup) error {
	lb := b.Linux
	if lb == nil {
		return nil
	}
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if lb.ResolvConfManaged {
		switch {
		case lb.ResolvConfLink != "":
			os.Remove(resolvConfPath)
			keep(os.Symlink(lb.ResolvConfLink, resolvConfPath))
		case lb.ResolvConfExisted:
			keep(writeFileAtomic(resolvConfPath, []byte(lb.ResolvConfContent), 0644))
		default:
			os.Remove(resolvConfPath)
		}
	}
	if lb.NMDropIn {
		os.Remove(filepath.Join(nmDropInDir, dropInName))
		if networkManagerActive() {
			runSystemCmd("systemctl", "reload", "NetworkManager")
		}
	}
	if lb.ResolvedDropIn {
		os.Remove(filepath.Join(resolvedDropInDir, dropInName))
		runSystemCmd("systemctl", "restart", "systemd-resolved")
	}
	return firstErr
}

// platformReconcile — DHCP istemcisi vb. resolv.conf'un üzerine yazdıysa geri al
func platformReconcile(b *sysDNSBackup) (bool, error) {
	lb := b.Linux
	if lb == nil {
		return false, nil
	}
	if lb.ResolvedDropIn {
		if _, err := os.Stat(filepath.Join(resolvedDropInDir, dropInName)); os.IsNotExist(err) {
			return false, fmt.Errorf("systemd-resolved yapılandırması silinmiş")
		}
	}
	if lb.ResolvConfManaged {
		data, _ := os.ReadFile(resolvConfPath)
		if !strings.HasPrefix(string(data), resolvMarker) {
			return false, writeFileAtomic(resolvConfPath, []byte(ourResolvConf(b.Addrs)), 0644)
		}
	}
	return false, nil
}

func platformCurrent() []string {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return nil
	}
	servers := resolvConfNameservers(string(data))
	if usesResolvedStub(string(data)) {
		// Asıl sunucular systemd-resolved'da
		if out, err := runSystemCmd("resolvectl", "dns"); err == nil {
			seen := make(map[string]bool)
			servers = nil
			for _, f := range strings.Fields(out) {
				if net.ParseIP(f) != nil && !seen[f] {
					seen[f] = true
					servers = append(servers, f)
				}
			}
		}
	}
	return servers
}

func flushOSCache() {
	if commandExists("resolvectl") {
		runSystemCmd("resolvectl", "flush-caches")
	}
}
