<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-0078D6?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT">
  <img src="https://img.shields.io/badge/DNS-Recursive-orange?style=for-the-badge" alt="DNS">
</p>

<h1 align="center">Ceky Resolver</h1>

<p align="center">
  <b>İnternete hiçbir DNS sağlayıcısına bağlı kalmadan erişin.</b><br>
  Google, Cloudflare veya internet sağlayıcınızın DNS'i yerine alan adlarını<br>
  doğrudan kök sunuculardan başlayarak <b>kendi bilgisayarınızda</b> çözen uygulama.
</p>

---

## Ne İşe Yarar?

Bir siteye girdiğinizde bilgisayarınız önce "bu adresin IP'si ne?" diye bir DNS sunucusuna sorar. Bu sunucu genellikle internet sağlayıcınızındır (ya da Google `8.8.8.8`, Cloudflare `1.1.1.1`). O sunucu:

- Hangi siteleri ziyaret ettiğinizi görür ve kaydedebilir,
- Bazı alan adlarını hiç yokmuş gibi gösterebilir ya da başka bir adrese yönlendirebilir,
- Çöktüğünde ya da yavaşladığında internetiniz de "yokmuş" gibi olur.

**Ceky Resolver** bu aracıyı ortadan kaldırır. Her sorguyu, internetin en tepesindeki 13 kök sunucudan başlayarak adım adım kendisi çözer:

```
Tarayıcınız → Ceky Resolver (kendi bilgisayarınızda)
                  │
                  ├─ Reklam/takipçi mi?      → engelle (0.0.0.0)
                  ├─ Önbellekte mi?          → anında yanıt
                  └─ Kök sunucu  (.)         → "com için şuraya sor"
                     TLD sunucusu (com)      → "google.com için şuraya sor"
                     Yetkili sunucu          → "google.com = 142.250.187.46"
```

Arada **hiçbir DNS şirketi yoktur**: ne Google, ne Cloudflare, ne de internet sağlayıcınızın DNS'i.

## Özellikler

| | |
|---|---|
| 🌐 **Gerçek rekürsif çözümleme** | Kök → TLD → yetkili sunucu. Proxy/aracı değil. |
| 🖥️ **Tek tıkla kullanım** | Çift tıklayın; kontrol paneli tarayıcıda açılır, sistem DNS'i otomatik ayarlanır. |
| ↩️ **Güvenli geri alma** | Eski DNS ayarlarınız yedeklenir; kapattığınızda birebir geri yüklenir. |
| 🛟 **Güvenli mod** | Kök sunuculara ulaşılamazsa (ör. otel Wi-Fi giriş sayfası) internetiniz kesilmesin diye eski DNS'e geçici olarak döner, bağlantı düzelince korumayı yeniden açar. |
| 🕵️ **Müdahale tespiti** | İnternet sağlayıcınız DNS trafiğini ele geçirip sahte yanıt veriyorsa bunu tespit eder, sahte yanıtları reddeder ve mümkünse TCP ile engeli aşar. |
| 🛡️ **Reklam engelleme** | 75.000+ reklam/takipçi alan adı (StevenBlack + AdAway). Tek tıkla "izin ver". |
| 🔎 **Bağlantı testi** | Bir alan adının kökten itibaren hangi sunucular üzerinden çözüldüğünü adım adım gösterir. |
| ⚙️ **Kalıcı kurulum** | İsterseniz bilgisayar açılışında arka planda otomatik başlar (Windows Görev Zamanlayıcı / macOS launchd / Linux systemd). |
| 🏠 **Yerel ağ isimleri** | `yazici.lan`, `nas.home.arpa` gibi isimler internete sızdırılmaz; modeminiz biliyorsa ona sorulur. |
| 🔒 **Güvenlik** | Önbellek zehirlenmesine karşı koruma (rastgele ID, yetki alanı/bailiwick kontrolü, yetkisiz yanıt reddi), kötü niyetli paketlere karşı sağlam ayrıştırıcı. |
| 📦 **Tek dosya** | Dış bağımlılık yok. Tek bir program dosyası. |

## Hızlı Başlangıç

### Windows

1. [Son sürüm sayfasından](https://github.com/cekYc/ceky-resolver/releases/latest) `ceky-resolver-windows-amd64.zip` dosyasını indirin ve bir klasöre çıkarın.
2. **`ceky-resolver.exe`'ye çift tıklayın.**
   - "Windows kişisel bilgisayarınızı korudu" uyarısı çıkarsa: **Ek bilgi → Yine de çalıştır** (program imzasız olduğu için).
   - Yönetici izni sorulduğunda **Evet** deyin (DNS ayarını değiştirebilmek için gerekli).
3. Kontrol paneli tarayıcıda açılır (**http://127.0.0.1:9090**) ve koruma otomatik olarak açılır.

Siyah pencere açık kaldığı sürece koruma çalışır. **Pencereyi kapatırsanız DNS ayarlarınız eski haline döner.**

Bilgisayar her açıldığında arka planda kendiliğinden çalışsın istiyorsanız panelde **"Kalıcı Kur"** düğmesine basın (ya da `Kalici-Kur.cmd` dosyasına çift tıklayın).

| Dosya | Ne yapar |
|---|---|
| `ceky-resolver.exe` | Uygulamayı başlatır, paneli açar |
| `Kalici-Kur.cmd` | Açılışta otomatik başlaması için kurar |
| `Kaldir.cmd` | Kalıcı kurulumu kaldırır, DNS ayarlarını geri yükler |
| `Acil-DNS-Geri-Yukle.cmd` | İnternet çalışmıyorsa DNS ayarlarını hemen eski haline getirir |

### macOS ve Linux

Terminalde tek satır (son sürümü indirir ve kalıcı olarak kurar):

```bash
curl -fsSL https://raw.githubusercontent.com/cekYc/ceky-resolver/main/scripts/install.sh | sh
```

Ya da elle: [sürüm sayfasından](https://github.com/cekYc/ceky-resolver/releases/latest) işletim sisteminize uygun `.tar.gz` dosyasını indirip çıkarın ve:

```bash
sudo ./ceky-resolver            # Şimdilik çalıştır (Ctrl+C ile kapatınca DNS geri yüklenir)
sudo ./ceky-resolver install    # Kalıcı kur
```

> **macOS:** Tarayıcıdan indirilen dosya "geliştirici doğrulanamadı" uyarısı verirse: `xattr -d com.apple.quarantine ceky-resolver`

Kontrol paneli: **http://127.0.0.1:9090**

## İnternetim Çalışmıyor, Ne Yapmalıyım?

Önce paneldeki **"Korumayı Kapat"** düğmesini deneyin. Panel açılmıyorsa:

| Sistem | Komut |
|---|---|
| Windows | `Acil-DNS-Geri-Yukle.cmd` dosyasına çift tıklayın |
| macOS / Linux | `sudo ceky-resolver restore` |

Bu komut DNS ayarlarınızı, Ceky Resolver'ı açmadan önceki haline **birebir** geri getirir. Tamamen kaldırmak için: `ceky-resolver uninstall` (Windows'ta `Kaldir.cmd`).

> ⚠️ Programı kaldırmadan önce silerseniz DNS ayarınız `127.0.0.1`'de kalır ve internet çalışmaz. Böyle bir durumda programı yeniden indirip `restore` komutunu çalıştırın.

## Kontrol Paneli

**http://127.0.0.1:9090** — yalnızca kendi bilgisayarınızdan erişilebilir.

- **Koruma durumu** ve tek tıkla aç/kapat
- **Kök sunuculara erişim:** erişilebilir / *İSS araya giriyor → TCP ile aşılıyor* / erişilemiyor
- **Bağlantı testi:** bir alan adının kökten itibaren nasıl çözüldüğünü adım adım görün
- Canlı sorgu trafiği grafiği, son sorgular, en çok sorgulanan/engellenen alan adları
- Engellenen bir sorguya **"İzin ver"** — o site bir daha engellenmez
- Reklam engellemeyi aç/kapat, önbelleği temizle, kalıcı kurulum

## Bilmeniz Gerekenler (Sınırlamalar)

Ceky Resolver'ı dürüstçe anlatmak gerekirse:

- **Aracı DNS'e bağımlılığı kaldırır, ama sorguları şifrelemez.** Kök ve yetkili sunucular şifreli bağlantı sunmadığı için sorgular ağ üzerinde düz metin olarak gider. İnternet sağlayıcınız hangi alan adlarını sorguladığınızı yine *görebilir*; ancak artık yanıtı o vermez, değiştiremez ve kendi DNS sunucusunda sizin adınıza kayıt tutmaz.
- **İnternet sağlayıcısı müdahalesi:** Bazı sağlayıcılar tüm DNS (UDP/53) trafiğini kendi sunucularına yönlendirir. Ceky bunu tespit eder ve sahte yanıtları kabul etmez; TCP açıksa onunla devam eder. İkisi de engelliyse o ağda bağımsız çözümleme mümkün değildir ve güvenli mod devreye girer.
- **Yalnızca DNS katmanıyla ilgilidir.** DNS tabanlı engelleri aşar; IP adresi veya SNI tabanlı engellemeleri aşmaz (bu bir VPN değildir).
- **DNSSEC doğrulaması henüz yok** (yol haritasında). Zehirlenmeye karşı rastgele sorgu kimliği, yetki alanı kontrolü ve yetkisiz yanıt reddi uygulanır.
- İlk ziyarette bir alan adının çözülmesi birkaç on milisaniye daha uzun sürebilir; sonrakiler önbellekten anında gelir.

## Evdeki Tüm Cihazlar İçin (Raspberry Pi / Sunucu)

`config.json` dosyasında `"bindAddr": "0.0.0.0"` yapıp modeminizin DHCP ayarlarında DNS sunucusu olarak bu bilgisayarın yerel IP'sini verin. Güvenlik için varsayılan olarak yalnızca yerel ağdan (192.168.x.x, 10.x.x.x vb.) gelen sorgular yanıtlanır. Linux ARM (Raspberry Pi) paketi de sürümlerde mevcuttur.

## Yapılandırma

Ayarlar `config.json` dosyasındadır (ilk çalıştırmada oluşur):

| Sistem | Konum |
|---|---|
| Windows | `C:\ProgramData\CekyResolver\config.json` |
| macOS | `/Library/Application Support/CekyResolver/config.json` |
| Linux | `/var/lib/ceky-resolver/config.json` |

`config.json` programla aynı klasördeyse o kullanılır (taşınabilir mod).

| Ayar | Varsayılan | Açıklama |
|------|-----------|----------|
| `autoEnable` | `true` | Açılışta sistem DNS'ini Ceky'ye yönlendir (panelden değiştirilir) |
| `failSafe` | `true` | Kök sunuculara ulaşılamazsa eski DNS'e geçici dönüş |
| `transport` | `"auto"` | `auto` / `udp` / `tcp` — müdahale varsa otomatik TCP |
| `dnsPort` | `53` | DNS dinleme portu |
| `bindAddr` | `127.0.0.1` | Dinleme adresi (`::1` otomatik eklenir). Ağ için `0.0.0.0` |
| `allowPublicClients` | `false` | Yerel ağ dışından sorgu kabul et (önerilmez) |
| `localForwarders` | `[]` | Yerel isimler (`.lan`, `.home.arpa`) için modem DNS'i, ör. `["192.168.1.1"]` |
| `rootServers` | *(yerleşik)* | Özel kök sunucu listesi |
| `dashboardPort` | `9090` | Kontrol paneli portu |
| `blocklistEnabled` | `true` | Reklam engelleme |
| `blocklistUrls` | StevenBlack, AdAway | Engelleme listeleri (hosts veya `\|\|domain^` biçimi) |
| `blocklistFile` / `allowlistFile` | `blocklist.txt` / `allowlist.txt` | Özel engelleme / izin listeleri |
| `blocklistRefreshHours` | `24` | Listelerin yenilenme aralığı |
| `dohEnabled` / `dotEnabled` | `true` | DNS-over-HTTPS (8080) / DNS-over-TLS (853) sunucuları |
| `cacheMaxEntries` | `10000` | Önbellek boyutu |
| `verbose` | `false` | Her çözümleme adımını konsola yaz |

## Komut Satırı

```
ceky-resolver                Uygulamayı başlat ve kontrol panelini aç
ceky-resolver install        Kalıcı kur (bilgisayar açılınca arka planda başlar)
ceky-resolver uninstall      Kalıcı kurulumu kaldır, DNS ayarlarını geri yükle
ceky-resolver restore        ACİL DURUM: DNS ayarlarını hemen eski haline getir
ceky-resolver status         Durumu göster
ceky-resolver version        Sürümü göster

Seçenekler:  -data <klasör>   -no-browser
```

## Kaynaktan Derleme

```bash
git clone https://github.com/cekYc/ceky-resolver.git
cd ceky-resolver
go build -o ceky-resolver .          # Windows: go build -o ceky-resolver.exe .
go test ./...                        # Sahte kök/TLD/yetkili sunucularla uçtan uca testler
scripts/build-release.sh 5.0.0       # Tüm platformlar için dist/ altına paketler
```

Yeni sürüm yayınlamak için bir etiket göndermek yeterli; GitHub Actions tüm platformlar için derleyip [Releases](https://github.com/cekYc/ceky-resolver/releases) sayfasına yükler:

```bash
git tag v5.0.0 && git push origin v5.0.0
```

## Mimari

```
ceky-resolver/
├── main.go            # Komut satırı (run / install / uninstall / restore / status)
├── app.go             # Uygulama yaşam döngüsü + koruma denetleyicisi (güvenli mod)
├── resolver.go        # Rekürsif çözümleyici, müdahale tespiti, bağlantı testi
├── dns.go             # DNS paket ayrıştırma/oluşturma (RFC 1035, EDNS0)
├── cache.go           # Yanıt + delegasyon önbelleği, bayat yanıt, tekil uçuş
├── server.go          # UDP/TCP/DoT/DoH dinleyicileri, ortak sorgu işleyici
├── local.go           # localhost, yerel ağ isimleri, Firefox DoH kanaryası
├── blocklist.go       # Reklam engelleme + izin listesi
├── dashboard.go       # Kontrol paneli API'si (+ web/index.html)
├── sysdns_*.go        # Sistem DNS ayarı: yedekle / uygula / geri yükle (Windows, macOS, Linux)
├── service_*.go       # Kalıcı kurulum (Görev Zamanlayıcı, launchd, systemd)
├── platform_*.go      # Yönetici izni, tarayıcı açma
├── scripts/           # Sürüm derleme + macOS/Linux kurulum betiği
└── packaging/windows/ # Çift tıklanabilir Windows yardımcıları
```

### Çözümleme Akışı

```
İstemci Sorgusu (www.example.com)
       │
       ├─ Yerel isim mi? (localhost, *.lan) ──→ Yerelde yanıtla
       ├─ Engelli mi? ──→ 0.0.0.0 / ::
       ├─ Önbellekte mi? ──→ Hemen yanıtla
       └─ Rekürsif Çözümleme (bilinen en yakın bölgeden başlar):
            ├─ Kök Sunucu     → yönlendirme: com (glue kayıtlarıyla)
            ├─ TLD Sunucu     → yönlendirme: example.com
            └─ Yetkili Sunucu → cevap (AA bayraklı) → önbelleğe al
               • CNAME başka bölgeye gidiyorsa hedef ayrıca çözülür
               • Yanıt vermeyen/bozuk sunucular atlanır
               • Sunuculara ulaşılamazsa son bilinen yanıt sunulur
```

## Kontrol Paneli API'si

Yalnızca `127.0.0.1` üzerinden erişilebilir. Değişiklik yapan istekler sayfaya gömülü bir anahtar (`X-Ceky-Token`) ister; böylece ziyaret ettiğiniz başka siteler ayarlarınızı değiştiremez veya sorgu geçmişinizi okuyamaz.

| Endpoint | Açıklama |
|----------|----------|
| `GET /api/app/state` | Koruma, ağ ve kurulum durumu |
| `GET /api/stats` · `/api/queries` · `/api/timeseries` | İstatistikler, son sorgular, grafik verisi |
| `GET /api/top-domains` · `/api/top-blocked` | En çok sorgulanan / engellenen |
| `GET /api/stream` | SSE — gerçek zamanlı akış |
| `POST /api/app/protection` | `{"enabled": true/false}` |
| `POST /api/app/blocklist` | `{"enabled": true/false}` |
| `POST /api/app/allow` | `{"domain": "...", "allowed": true/false}` |
| `POST /api/app/test` | `{"domain": "..."}` — adım adım çözümleme |
| `POST /api/app/flush` · `/api/app/install` · `/api/app/quit` | Önbellek temizle, kalıcı kur, çıkış |

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
