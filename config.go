package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ==================== YAPILANDIRMA (CONFIG) ====================

// Config — Ceky Resolver yapılandırma dosyası
type Config struct {
	// DNS
	DNSPort            int    `json:"dnsPort"`            // Varsayılan: 53
	BindAddr           string `json:"bindAddr"`           // Varsayılan: "127.0.0.1" (+ "::1")
	AllowPublicClients bool   `json:"allowPublicClients"` // Yerel ağ dışından sorgu kabul et (önerilmez)

	// Uygulama
	AutoEnable      bool     `json:"autoEnable"`            // Açılışta sistem DNS'ini Ceky'ye yönlendir
	FailSafe        bool     `json:"failSafe"`              // Kök sunuculara ulaşılamazsa eski DNS'e geçici dönüş
	Transport       string   `json:"transport"`             // "auto" | "udp" | "tcp"
	RootServers     []string `json:"rootServers,omitempty"` // Özel kök sunucu listesi (boş = yerleşik)
	LocalForwarders []string `json:"localForwarders"`       // .lan / .home.arpa gibi yerel isimler için modem DNS'i
	Verbose         bool     `json:"verbose"`               // Her çözümleme adımını konsola yaz

	// Dashboard
	DashboardPort int  `json:"dashboardPort"` // Varsayılan: 9090
	DashboardOn   bool `json:"dashboardOn"`   // Varsayılan: true

	// DoH / DoT
	DoHEnabled bool   `json:"dohEnabled"` // Varsayılan: true
	DoTEnabled bool   `json:"dotEnabled"` // Varsayılan: true
	DoHPort    int    `json:"dohPort"`    // Varsayılan: 8080
	DoTPort    int    `json:"dotPort"`    // Varsayılan: 853
	CertFile   string `json:"certFile"`   // Varsayılan: "cert.pem"
	KeyFile    string `json:"keyFile"`    // Varsayılan: "key.pem"
	AutoTLS    bool   `json:"autoTLS"`    // Sertifika yoksa otomatik oluştur

	// Reklam Engelleme
	BlocklistEnabled      bool     `json:"blocklistEnabled"`      // Varsayılan: true
	BlocklistURLs         []string `json:"blocklistUrls"`         // Online kaynaklar
	BlocklistFile         string   `json:"blocklistFile"`         // Yerel özel engelleme listesi
	AllowlistFile         string   `json:"allowlistFile"`         // Asla engellenmeyecek domain'ler
	BlocklistRefreshHours int      `json:"blocklistRefreshHours"` // Listeleri yenileme aralığı

	// Önbellek
	CacheEnabled    bool `json:"cacheEnabled"`    // Varsayılan: true
	CacheMaxEntries int  `json:"cacheMaxEntries"` // Varsayılan: 10000
	CacheCleanupSec int  `json:"cacheCleanupSec"` // Varsayılan: 60

	// Performans
	QueryLogSize  int `json:"queryLogSize"`  // Varsayılan: 1000
	StatsInterval int `json:"statsInterval"` // Konsol istatistik aralığı (saniye), 0=kapalı
}

// Varsayılan yapılandırma
func defaultConfig() Config {
	return Config{
		DNSPort:  53,
		BindAddr: "127.0.0.1",

		AutoEnable:      true,
		FailSafe:        true,
		Transport:       "auto",
		LocalForwarders: []string{},

		DashboardPort: 9090,
		DashboardOn:   true,

		DoHEnabled: true,
		DoTEnabled: true,
		DoHPort:    8080,
		DoTPort:    853,
		CertFile:   "cert.pem",
		KeyFile:    "key.pem",
		AutoTLS:    true,

		BlocklistEnabled:      true,
		BlocklistURLs:         append([]string(nil), defaultBlocklistURLs...),
		BlocklistFile:         "blocklist.txt",
		AllowlistFile:         "allowlist.txt",
		BlocklistRefreshHours: 24,

		CacheEnabled:    true,
		CacheMaxEntries: 10000,
		CacheCleanupSec: 60,

		QueryLogSize:  1000,
		StatsInterval: 30,
	}
}

const configFile = "config.json"

// Veri klasörü — config.json, sertifikalar, listeler burada tutulur
var dataDir = "."

// dataPath — göreli yolları veri klasörüne göre çöz
func dataPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dataDir, p)
}

// resolveDataDir — öncelik: -data > exe yanındaki config.json (taşınabilir mod) >
// çalışma klasöründeki config.json > sistem klasörü (yönetici) > kullanıcı klasörü
func resolveDataDir(flagValue string) string {
	if flagValue != "" {
		if abs, err := filepath.Abs(flagValue); err == nil {
			return abs
		}
		return flagValue
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, configFile)); err == nil {
			return dir
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(wd, configFile)); err == nil {
			return wd
		}
	}
	if isAdmin() {
		return systemDataDir()
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ceky-resolver")
	}
	return "."
}

// Yapılandırma dosyasını yükle (yoksa varsayılanı oluştur)
func loadConfig() Config {
	cfg := defaultConfig()
	path := dataPath(configFile)

	data, err := os.ReadFile(path)
	if err != nil {
		// Dosya yok — varsayılanı oluştur
		saveConfig(cfg)
		fmt.Printf("║ 📄 Yapılandırma oluşturuldu: %s\n", path)
		return cfg
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("║ ⚠ config.json okuma hatası: %v (varsayılan kullanılıyor)\n", err)
		return defaultConfig()
	}

	// Yeni sürümle gelen ayarlar dosyaya eklensin
	saveConfig(cfg)
	return cfg
}

// peekConfig — yapılandırmayı yalnızca oku (dosya yoksa oluşturma)
func peekConfig() Config {
	c := defaultConfig()
	if data, err := os.ReadFile(dataPath(configFile)); err == nil {
		if json.Unmarshal(data, &c) != nil {
			return defaultConfig()
		}
	}
	return c
}

// Yapılandırmayı dosyaya kaydet
func saveConfig(cfg Config) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(dataDir, 0755)
	os.WriteFile(dataPath(configFile), data, 0644)
}

// ==================== OTOMATİK TLS SERTİFİKA ====================

// Self-signed TLS sertifikası oluştur (ECDSA P-256, 1 yıl)
func generateSelfSignedCert(certPath, keyPath string) error {
	// Özel anahtar oluştur
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("anahtar üretme hatası: %v", err)
	}

	// Sertifika şablonu
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ceky Resolver"},
			CommonName:   "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 yıl

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames:    []string{"localhost", "ceky-resolver.local"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	// Sertifikayı oluştur
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("sertifika oluşturma hatası: %v", err)
	}

	// Sertifika dosyasını yaz
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Anahtar dosyasını yaz
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return nil
}

// TLS sertifikasını kontrol et, yoksa oluştur
func ensureTLSCerts(cfg Config) (string, string) {
	certPath := dataPath(cfg.CertFile)
	keyPath := dataPath(cfg.KeyFile)

	// Her iki dosya da var mı?
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	if certErr == nil && keyErr == nil {
		fmt.Println("║ 🔒 TLS sertifikası bulundu")
		return certPath, keyPath
	}

	if !cfg.AutoTLS {
		fmt.Println("║ ⚠ TLS sertifikası bulunamadı (autoTLS kapalı)")
		return "", ""
	}

	// Otomatik oluştur
	fmt.Println("║ 🔐 TLS sertifikası oluşturuluyor (ECDSA P-256)...")
	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		fmt.Printf("║ ⚠ Sertifika oluşturulamadı: %v\n", err)
		return "", ""
	}

	fmt.Printf("║ ✓ Sertifika oluşturuldu: %s + %s (1 yıl geçerli)\n", certPath, keyPath)
	return certPath, keyPath
}
