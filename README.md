<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT">
  <img src="https://img.shields.io/badge/DNS-Recursive-orange?style=for-the-badge" alt="DNS">
</p>

<h1 align="center">Ceky Resolver</h1>

<p align="center">
  <b>Sıfırdan Go ile yazılmış, gerçek rekursif DNS çözümleyici.</b><br>
  Reklam engelleme · Canlı dashboard · DoH/DoT · Yüksek performans
</p>

---

## Ne İşe Yarar?

Ceky Resolver, bilgisayarınızdaki **tüm DNS trafiğini** üstlenir. Her alan adı sorgusunu kök sunuculardan başlayarak kendi kendine çözer — Google DNS, Cloudflare veya başka bir aracıya ihtiyaç duymaz.

```
Tarayıcın → Ceky Resolver → Kök Sunucu → TLD → Yetkili Sunucu → IP adresi
                ↓
          Reklam mı? → 0.0.0.0 (engelle)
          Önbellekte mi? → Anında yanıt (0ms)
```

## Özellikler

| Özellik | Açıklama |
|---------|----------|
| **Gerçek Rekursif Çözümleme** | Kök sunuculardan başlayarak iteratif DNS çözümleme (proxy değil) |
| **Reklam Engelleme** | 78.000+ domain engellenir (StevenBlack + AdAway listeleri) |
| **Canlı Web Dashboard** | Gerçek zamanlı grafikler, istatistikler, sorgu logları |
| **Yüksek Performans** | Goroutine-per-request, sync.Pool buffer havuzu |
| **Akıllı Önbellek** | TTL-uyumlu cache, tekrarlayan sorgular 0ms'de yanıtlanır |
| **DNS-over-TLS (DoT)** | RFC 7858 uyumlu şifreli DNS |
| **DNS-over-HTTPS (DoH)** | RFC 8484 uyumlu HTTPS üzerinden DNS |
| **Otomatik TLS** | Self-signed ECDSA P-256 sertifika otomatik üretilir |
| **Yapılandırılabilir** | `config.json` ile tüm ayarlar tek dosyada |
| **Tek Binary** | Dış bağımlılık yok, tek exe çalışır |

## Hızlı Başlangıç

### Gereksinimler

- [Go 1.21+](https://go.dev/dl/)
- Windows 10/11

### Derle ve Çalıştır

```bash
git clone https://github.com/cekYc/ceky-resolver.git
cd ceky-resolver
go build -o ceky-resolver.exe .
.\ceky-resolver.exe
```

İlk çalıştırmada otomatik olarak:
- `config.json` oluşturulur (tüm ayarlar)
- `cert.pem` + `key.pem` üretilir (TLS sertifikası)
- Reklam engelleme listeleri indirilir (~78K domain)

### Dashboard'u Aç

Tarayıcında **http://127.0.0.1:9090** adresine git:

- Anlık sorgu trafiği grafiği
- Engelleme oranları ve sayaçları
- Son sorgular tablosu (canlı güncellenir)
- En çok sorgulanan / engellenen domain'ler
- Sunucu performans metrikleri (kök/TLD/yetkili)

## Sistem DNS'i Olarak Kullanma

Ceky Resolver'ı bilgisayarınızın varsayılan DNS'i yapmak için:

### Otomatik Kurulum (Önerilen)

```powershell
# PowerShell'i YÖNETİCİ olarak aç
.\setup.ps1 -Install
```

Bu script:
1. DNS'inizi `127.0.0.1`'e yönlendirir
2. Eski DNS ayarlarınızı yedekler (`dns_backup.json`)
3. Bilgisayar açıldığında otomatik başlatır (Windows Servisi)

### Kaldırma

```powershell
.\setup.ps1 -Uninstall
```

DNS ayarlarınız otomatik olarak eski haline döner.

### Manuel Kurulum

1. `config.json`'da portu `53` yapın
2. PowerShell'i **Yönetici** olarak açın
3. `.\ceky-resolver.exe` çalıştırın
4. **Ağ Ayarları → DNS Sunucusu → 127.0.0.1**

## Yapılandırma

İlk çalıştırmada oluşturulan `config.json`:

```json
{
  "dnsPort": 2053,
  "bindAddr": "127.0.0.1",
  "dashboardPort": 9090,
  "dashboardOn": true,
  "dohPort": 8080,
  "dotPort": 853,
  "autoTLS": true,
  "blocklistEnabled": true,
  "blocklistUrls": [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt"
  ],
  "blocklistFile": "blocklist.txt",
  "cacheEnabled": true,
  "cacheMaxEntries": 10000,
  "queryLogSize": 1000
}
```

| Ayar | Varsayılan | Açıklama |
|------|-----------|----------|
| `dnsPort` | `2053` | DNS dinleme portu (`53` = sistem DNS'i) |
| `dashboardPort` | `9090` | Web dashboard portu |
| `dohPort` | `8080` | DNS-over-HTTPS portu |
| `dotPort` | `853` | DNS-over-TLS portu |
| `autoTLS` | `true` | Sertifika yoksa otomatik oluştur |
| `blocklistEnabled` | `true` | Reklam engelleme açık/kapalı |
| `blocklistFile` | `blocklist.txt` | Özel engelleme listesi dosyası |
| `queryLogSize` | `1000` | Dashboard'da gösterilen max sorgu sayısı |
| `statsInterval` | `30` | Konsol istatistik aralığı (saniye, `0`=kapalı) |

### Özel Engelleme Listesi

Kendi engelleme kurallarınızı `blocklist.txt` dosyasına ekleyebilirsiniz:

```
# Özel engelleme kuralları
reklam.example.com
tracker.example.com
0.0.0.0 baska-reklam.com
```

## Mimari

```
ceky-resolver/
├── main.go          # Çekirdek: DNS parser, rekursif resolver, cache, metrikler
├── blocklist.go     # Reklam engelleme motoru (Pi-hole mantığı)
├── server.go        # Goroutine handler, DoT sunucusu, DoH sunucusu
├── querylog.go      # Sorgu kayıt sistemi (dairesel buffer, zaman serisi)
├── dashboard.go     # Web dashboard (embedded HTML/CSS/JS, SSE, JSON API)
├── config.go        # Yapılandırma sistemi + otomatik TLS sertifika üretimi
├── setup.ps1        # Windows kurulum/kaldırma scripti
├── config.json      # Çalışma zamanı ayarları (otomatik oluşur)
├── examples/
│   ├── query_test.go    # Basit DNS sorgu örneği
│   └── adblock_test.go  # Reklam engelleme test örneği
└── go.mod
```

### Çözümleme Akışı

```
İstemci Sorgusu (google.com)
       │
       ├─ Engelli mi? ──→ Evet → 0.0.0.0 yanıtı
       │
       ├─ Önbellekte mi? ──→ Evet → Hemen yanıtla (0ms)
       │
       └─ Rekursif Çözümleme:
            │
            ├─ 1. Kök Sunucu (198.41.0.4) → "com. için ns1.gtld.net'e sor"
            │
            ├─ 2. TLD Sunucu (ns1.gtld.net) → "google.com için ns1.google.com'a sor"
            │
            └─ 3. Yetkili Sunucu (ns1.google.com) → "google.com = 142.250.187.46"
                     │
                     └─ Önbelleğe kaydet (TTL'e göre)
```

### Teknolojiler

- **Dil:** Go (sıfır dış bağımlılık)
- **Protokol:** DNS (RFC 1035), EDNS0 (RFC 6891), DoT (RFC 7858), DoH (RFC 8484)
- **Eşzamanlılık:** Goroutine-per-request, `sync.Pool`, `sync.RWMutex`, `sync/atomic`
- **Dashboard:** Vanilla JS, Canvas grafik, SSE (Server-Sent Events)
- **TLS:** ECDSA P-256, otomatik self-signed sertifika

## API Endpoints

Dashboard aşağıdaki JSON API'lerini sunar:

| Endpoint | Açıklama |
|----------|----------|
| `GET /` | Web dashboard (HTML) |
| `GET /api/stats` | Genel istatistikler |
| `GET /api/queries` | Son 50 sorgu |
| `GET /api/timeseries` | Zaman serisi (grafik verisi) |
| `GET /api/top-domains` | En çok sorgulanan 10 domain |
| `GET /api/top-blocked` | En çok engellenen 10 domain |
| `GET /api/stream` | SSE — gerçek zamanlı akış |

## Lisans

MIT License — istediğiniz gibi kullanın, değiştirin, dağıtın.

## Katkıda Bulunma

1. Fork'layın
2. Feature branch oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit'leyin (`git commit -m 'Yeni özellik eklendi'`)
4. Push'layın (`git push origin yeni-ozellik`)
5. Pull Request açın

---

<p align="center">
  <b>Ceky Resolver</b> — İnterneti kendi kurallarınla kullan 
</p>
