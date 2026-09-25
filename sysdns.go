package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ==================== SİSTEM DNS AYARLARI ====================
//
// "Korumayı aç" = işletim sisteminin DNS sunucusunu 127.0.0.1 (+ ::1) yapmak.
// Değişiklikten ÖNCE mevcut ayarlar yedeklenir; "kapat", "restore" veya
// "uninstall" bu yedeği birebir geri yükler. Yedek, veri klasöründen bağımsız
// sabit bir sistem konumunda tutulur (servis ve uygulama aynı yedeği görür).

var errNotAdmin = errors.New("yönetici izni gerekli")

// sysDNSBackup — sistem DNS ayarlarının yedeği
type sysDNSBackup struct {
	OS        string    `json:"os"`
	CreatedAt time.Time `json:"createdAt"`
	Addrs     []string  `json:"addrs"`    // Sisteme yazılan Ceky adresleri
	Original  []string  `json:"original"` // Önceki etkin DNS sunucuları

	Windows     []winIfaceDNS      `json:"windows,omitempty"`
	WindowsSeen []int              `json:"windowsSeen,omitempty"`
	Darwin      []darwinServiceDNS `json:"darwin,omitempty"`
	Linux       *linuxDNSBackup    `json:"linux,omitempty"`
}

// winIfaceDNS — bir Windows ağ bağdaştırıcısının DNS ayarı
type winIfaceDNS struct {
	Index     int    `json:"index"`
	Alias     string `json:"alias"`
	V4        string `json:"v4"`        // Elle girilmiş IPv4 DNS'ler ("" = otomatik/DHCP)
	V6        string `json:"v6"`        // Elle girilmiş IPv6 DNS'ler ("" = otomatik)
	Effective string `json:"effective"` // O anki etkin DNS'ler
}

// darwinServiceDNS — bir macOS ağ servisinin DNS ayarı
type darwinServiceDNS struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"` // boş = otomatik (DHCP)
}

// linuxDNSBackup — Linux'ta değiştirilen dosyaların yedeği
type linuxDNSBackup struct {
	ResolvedDropIn    bool   `json:"resolvedDropIn"`    // systemd-resolved yapılandırması yazıldı
	ResolvConfManaged bool   `json:"resolvConfManaged"` // /etc/resolv.conf'u biz yazdık
	ResolvConfExisted bool   `json:"resolvConfExisted"`
	ResolvConfLink    string `json:"resolvConfLink,omitempty"`
	ResolvConfContent string `json:"resolvConfContent,omitempty"`
	NMDropIn          bool   `json:"nmDropIn"` // NetworkManager "dns=none" yapılandırması yazıldı
}

func backupPath() string {
	return filepath.Join(systemDataDir(), "sysdns_backup.json")
}

func loadBackup() (*sysDNSBackup, error) {
	data, err := os.ReadFile(backupPath())
	if err != nil {
		return nil, err
	}
	var b sysDNSBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func saveBackup(b *sysDNSBackup) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(backupPath(), data, 0600)
}

// backupExists — sistem DNS'i şu an Ceky'ye yönlü mü? (yedek varsa evet)
func backupExists() bool {
	_, err := os.Stat(backupPath())
	return err == nil
}

// enableSystemDNS — mevcut ayarları yedekle (daha önce alınmadıysa) ve sistemi Ceky'ye yönlendir
func enableSystemDNS(addrs []string) error {
	if !isAdmin() {
		return errNotAdmin
	}
	b, err := loadBackup()
	if err != nil {
		if b, err = platformBackup(); err != nil {
			return err
		}
		b.OS = runtime.GOOS
		b.CreatedAt = time.Now()
		b.Original = withoutOurAddrs(b.Original)
	}
	b.Addrs = addrs
	// Önce yedek diske yazılır, sonra ayar değiştirilir
	if err := saveBackup(b); err != nil {
		return err
	}
	if err := platformApply(b, addrs); err != nil {
		platformRestore(b)
		os.Remove(backupPath())
		return err
	}
	saveBackup(b) // Uygulama sırasında eklenen bilgiler (ör. Linux dosyaları)
	flushOSCache()
	return nil
}

// disableSystemDNS — yedekteki orijinal ayarları geri yükle
func disableSystemDNS() error {
	b, err := loadBackup()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !isAdmin() {
		return errNotAdmin
	}
	if err := platformRestore(b); err != nil {
		return err
	}
	os.Remove(backupPath())
	flushOSCache()
	return nil
}

// reconcileSystemDNS — sonradan eklenen ağ bağdaştırıcılarını / üzerine yazılan
// ayarları yakala (ör. DHCP istemcisinin resolv.conf'u değiştirmesi)
func reconcileSystemDNS() error {
	b, err := loadBackup()
	if err != nil {
		return err
	}
	changed, err := platformReconcile(b)
	if changed {
		saveBackup(b)
	}
	return err
}

// currentSystemDNS — işletim sisteminin o an kullandığı DNS sunucuları
func currentSystemDNS() []string {
	return platformCurrent()
}

// ==================== YARDIMCILAR ====================

// isOurAddr — loopback adresleri Ceky'nin kendisidir (yedeğe "orijinal" diye yazılmaz)
func isOurAddr(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.IsLoopback() && s != "127.0.0.53" // systemd-resolved stub'ı hariç
}

func withoutOurAddrs(list []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" || isOurAddr(s) || net.ParseIP(s) == nil || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// splitServers — "1.1.1.1,8.8.8.8" veya "1.1.1.1 8.8.8.8" → geçerli IP listesi
func splitServers(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if net.ParseIP(f) != nil {
			out = append(out, f)
		}
	}
	return out
}

// runSystemCmd — dış komut çalıştır (testlerde taklit edilebilir)
var runSystemCmd = func(name string, args ...string) (string, error) {
	out, err := hiddenCommand(name, args...).CombinedOutput()
	return string(out), err
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// hasLine — komut çıktısında tam olarak bu satır var mı?
func hasLine(out, line string) bool {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}
