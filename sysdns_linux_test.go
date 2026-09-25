//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeLinux — /etc dosyalarını geçici klasöre yönlendir, systemctl'i taklit et
func fakeLinux(t *testing.T, resolvedActive bool) (dir string, calls *[]string) {
	t.Helper()
	dir = t.TempDir()
	oldResolv, oldResolved, oldNM, oldRun := resolvConfPath, resolvedDropInDir, nmDropInDir, runSystemCmd
	t.Cleanup(func() {
		resolvConfPath, resolvedDropInDir, nmDropInDir, runSystemCmd = oldResolv, oldResolved, oldNM, oldRun
	})
	resolvConfPath = filepath.Join(dir, "resolv.conf")
	resolvedDropInDir = filepath.Join(dir, "resolved.conf.d")
	nmDropInDir = filepath.Join(dir, "NetworkManager", "conf.d")
	os.MkdirAll(nmDropInDir, 0755)

	var log []string
	runSystemCmd = func(name string, args ...string) (string, error) {
		log = append(log, name+" "+strings.Join(args, " "))
		if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
			if args[1] == "systemd-resolved" && resolvedActive {
				return "active\n", nil
			}
			return "inactive\n", os.ErrNotExist
		}
		return "", nil
	}
	return dir, &log
}

func TestLinuxResolvConfSymlinkRoundTrip(t *testing.T) {
	dir, _ := fakeLinux(t, false)
	target := filepath.Join(dir, "run-resolv.conf")
	os.WriteFile(target, []byte("nameserver 192.168.1.1\n"), 0644)
	os.Symlink(target, resolvConfPath)

	b, err := platformBackup()
	if err != nil {
		t.Fatal(err)
	}
	if b.Linux.ResolvConfLink != target || len(b.Original) != 1 || b.Original[0] != "192.168.1.1" {
		t.Fatalf("yedek hatalı: %+v %+v", b.Linux, b.Original)
	}
	if err := platformApply(b, []string{"127.0.0.1", "::1"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(resolvConfPath)
	if !strings.HasPrefix(string(data), resolvMarker) || !strings.Contains(string(data), "nameserver ::1") {
		t.Fatalf("resolv.conf yazılmadı:\n%s", data)
	}
	if info, _ := os.Lstat(resolvConfPath); info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("sembolik bağlantı normal dosyayla değiştirilmeli")
	}
	if orig, _ := os.ReadFile(target); string(orig) != "nameserver 192.168.1.1\n" {
		t.Fatal("bağlantının hedefi değiştirilmemeli")
	}
	if _, err := os.Stat(filepath.Join(nmDropInDir, dropInName)); err != nil {
		t.Fatal("NetworkManager dns=none ayarı yazılmalı")
	}

	// DHCP istemcisi üzerine yazarsa denetim geri alır
	os.Remove(resolvConfPath)
	os.WriteFile(resolvConfPath, []byte("nameserver 9.9.9.9\n"), 0644)
	platformReconcile(b)
	if data, _ := os.ReadFile(resolvConfPath); !strings.HasPrefix(string(data), resolvMarker) {
		t.Fatal("üzerine yazılan resolv.conf düzeltilmeli")
	}

	if err := platformRestore(b); err != nil {
		t.Fatal(err)
	}
	if link, err := os.Readlink(resolvConfPath); err != nil || link != target {
		t.Fatalf("sembolik bağlantı geri yüklenmeli: %q %v", link, err)
	}
	if _, err := os.Stat(filepath.Join(nmDropInDir, dropInName)); !os.IsNotExist(err) {
		t.Fatal("NetworkManager ayarı silinmeli")
	}
}

func TestLinuxRegularFileRoundTrip(t *testing.T) {
	fakeLinux(t, false)
	original := "# statik\nnameserver 195.175.39.39\nsearch lan\n"
	os.WriteFile(resolvConfPath, []byte(original), 0644)

	b, _ := platformBackup()
	if err := platformApply(b, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := platformRestore(b); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(resolvConfPath); string(data) != original {
		t.Fatalf("orijinal içerik birebir geri gelmeli:\n%s", data)
	}
}

func TestLinuxSystemdResolved(t *testing.T) {
	_, calls := fakeLinux(t, true)
	os.WriteFile(resolvConfPath, []byte("nameserver 127.0.0.53\noptions edns0\n"), 0644)

	b, _ := platformBackup()
	if err := platformApply(b, []string{"127.0.0.1", "::1"}); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(resolvedDropInDir, dropInName))
	if err != nil || !strings.Contains(string(conf), "DNS=127.0.0.1 ::1") || !strings.Contains(string(conf), "Domains=~.") {
		t.Fatalf("systemd-resolved yapılandırması hatalı: %s %v", conf, err)
	}
	if data, _ := os.ReadFile(resolvConfPath); !strings.Contains(string(data), "127.0.0.53") {
		t.Fatal("resolved stub'ı kullanılırken resolv.conf'a dokunulmamalı")
	}
	if b.Linux.ResolvConfManaged {
		t.Fatal("resolv.conf yönetilmemeli")
	}

	platformRestore(b)
	if _, err := os.Stat(filepath.Join(resolvedDropInDir, dropInName)); !os.IsNotExist(err) {
		t.Fatal("resolved yapılandırması silinmeli")
	}
	restarts := 0
	for _, c := range *calls {
		if c == "systemctl restart systemd-resolved" {
			restarts++
		}
	}
	if restarts != 2 {
		t.Fatalf("resolved açarken ve kapatırken yeniden başlatılmalı (%d)", restarts)
	}
}

func TestWithoutOurAddrs(t *testing.T) {
	got := withoutOurAddrs([]string{"127.0.0.1", "::1", "192.168.1.1", "127.0.0.53", "192.168.1.1", "bozuk"})
	if strings.Join(got, ",") != "192.168.1.1,127.0.0.53" {
		t.Fatalf("beklenmeyen sonuç: %v", got)
	}
}
