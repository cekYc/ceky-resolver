package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHostsLine(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0 ads.example.com":         "ads.example.com",
		"127.0.0.1  Tracker.Example.COM.": "tracker.example.com",
		"ads.example.com # yorum":         "ads.example.com",
		"||ad.doubleclick.net^":           "ad.doubleclick.net",
		"# yorum":                         "",
		"! adblock yorumu":                "",
		"127.0.0.1 localhost":             "",
		"0.0.0.0 0.0.0.0":                 "",
		"1.2.3.4":                         "",
		"com":                             "",
	}
	for line, want := range cases {
		if got := parseHostsLine(line); got != want {
			t.Errorf("parseHostsLine(%q) = %q, beklenen %q", line, got, want)
		}
	}
}

func TestBlocklistLoadAndAllow(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# liste\n0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"))
	}))
	defer srv.Close()

	os.WriteFile(filepath.Join(dir, "blocklist.txt"), []byte("ozel-reklam.example.org\n"), 0644)

	b := newBlocklist()
	b.sources = []string{srv.URL + "/hosts"}
	b.customFile = filepath.Join(dir, "blocklist.txt")
	b.allowFile = filepath.Join(dir, "allowlist.txt")
	b.cacheDir = filepath.Join(dir, "lists")
	b.client = srv.Client()
	b.enabled.Store(true)

	b.Load(false) // Henüz yerel kopya yok — yalnızca özel liste
	if !b.IsBlocked("ozel-reklam.example.org") || b.IsBlocked("ads.example.com") {
		t.Fatal("ilk yüklemede yalnızca özel liste olmalı")
	}

	b.Load(true)
	if b.Size() != 3 {
		t.Fatalf("3 domain bekleniyordu, gelen %d", b.Size())
	}
	if !b.IsBlocked("x.ads.example.com") || b.IsBlocked("example.com") {
		t.Fatal("alt domain engellenmeli, üst domain engellenmemeli")
	}

	// İzin listesi kalıcı olmalı
	if err := b.Allow("ads.example.com", true); err != nil {
		t.Fatal(err)
	}
	if b.IsBlocked("x.ads.example.com") {
		t.Fatal("izin verilen domain engellenmemeli")
	}
	data, _ := os.ReadFile(b.allowFile)
	if !strings.Contains(string(data), "ads.example.com") {
		t.Fatal("izin listesi dosyaya yazılmalı")
	}

	// Yeniden açılışta yerel kopyadan (internet olmadan) yüklenmeli
	b2 := newBlocklist()
	b2.sources, b2.cacheDir, b2.allowFile = b.sources, b.cacheDir, b.allowFile
	b2.enabled.Store(true)
	b2.Load(false)
	if !b2.IsBlocked("tracker.example.net") || b2.IsBlocked("ads.example.com") {
		t.Fatal("yerel kopya ve izin listesi yeniden yüklenmeli")
	}

	b2.enabled.Store(false)
	if b2.IsBlocked("tracker.example.net") {
		t.Fatal("kapalıyken hiçbir şey engellenmemeli")
	}

	if err := b.Allow("../etc/passwd", true); err == nil {
		t.Fatal("geçersiz domain reddedilmeli")
	}
}
