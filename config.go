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
	"os"
	"time"
)

// ==================== YAPILANDIRMA (CONFIG) ====================

// Config — Ceky Resolver yapılandırma dosyası
type Config struct {
	// DNS
	DNSPort  int    `json:"dnsPort"`  // Varsayılan: 53
	BindAddr string `json:"bindAddr"` // Varsayılan: "127.0.0.1"

	// Dashboard
	DashboardPort int  `json:"dashboardPort"` // Varsayılan: 9090
	DashboardOn   bool `json:"dashboardOn"`   // Varsayılan: true

	// DoH / DoT
	DoHPort  int    `json:"dohPort"`  // Varsayılan: 8080 (HTTP) veya 8443 (HTTPS)
	DoTPort  int    `json:"dotPort"`  // Varsayılan: 853
	CertFile string `json:"certFile"` // Varsayılan: "cert.pem"
	KeyFile  string `json:"keyFile"`  // Varsayılan: "key.pem"
	AutoTLS  bool   `json:"autoTLS"`  // Sertifika yoksa otomatik oluştur

	// Reklam Engelleme
	BlocklistEnabled bool     `json:"blocklistEnabled"` // Varsayılan: true
	BlocklistURLs    []string `json:"blocklistUrls"`    // Online kaynaklar
	BlocklistFile    string   `json:"blocklistFile"`    // Yerel dosya

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

		DashboardPort: 9090,
		DashboardOn:   true,

		DoHPort:  8080,
		DoTPort:  853,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
		AutoTLS:  true,

		BlocklistEnabled: true,
		BlocklistURLs: []string{
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			"https://adaway.org/hosts.txt",
		},
		BlocklistFile: "blocklist.txt",

		CacheEnabled:    true,
		CacheMaxEntries: 10000,
		CacheCleanupSec: 60,

		QueryLogSize:  1000,
		StatsInterval: 30,
	}
}

const configFile = "config.json"

// Yapılandırma dosyasını yükle (yoksa varsayılanı oluştur)
func loadConfig() Config {
	cfg := defaultConfig()

	data, err := os.ReadFile(configFile)
	if err != nil {
		// Dosya yok — varsayılanı oluştur
		saveConfig(cfg)
		fmt.Printf("║ 📄 Yapılandırma oluşturuldu: %s\n", configFile)
		return cfg
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("║ ⚠ config.json okuma hatası: %v (varsayılan kullanılıyor)\n", err)
		return defaultConfig()
	}

	return cfg
}

// Yapılandırmayı dosyaya kaydet
func saveConfig(cfg Config) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(configFile, data, 0644)
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

		DNSNames: []string{"localhost", "ceky-resolver.local"},
		// IP adresleri
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
	keyFile, err := os.Create(keyPath)
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
	certPath := cfg.CertFile
	keyPath := cfg.KeyFile

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
