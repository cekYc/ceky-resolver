# ═══════════════════════════════════════════════════
#  Ceky Resolver — Kurulum & Yapılandırma Script'i
#  PowerShell'i YÖNETİCİ olarak çalıştırın!
# ═══════════════════════════════════════════════════

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status
)

$ErrorActionPreference = "Stop"
$resolverPath = $PSScriptRoot
$exePath = Join-Path $resolverPath "ceky-resolver.exe"
$taskName = "CekyResolver"

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║    Ceky Resolver — Kurulum Sihirbazı    ║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─── DURUM KONTROLÜ ───
function Show-Status {
    Write-Banner
    Write-Host "  Durum Kontrolü" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────" -ForegroundColor DarkGray

    # Exe var mı?
    if (Test-Path $exePath) {
        $size = (Get-Item $exePath).Length / 1MB
        Write-Host "  ✓ ceky-resolver.exe ($([math]::Round($size,1)) MB)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ ceky-resolver.exe bulunamadı" -ForegroundColor Red
        Write-Host "    → go build -o ceky-resolver.exe ." -ForegroundColor DarkGray
    }

    # Config var mı?
    $configPath = Join-Path $resolverPath "config.json"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        Write-Host "  ✓ config.json (DNS port: $($config.dnsPort))" -ForegroundColor Green
    } else {
        Write-Host "  ○ config.json (ilk çalıştırmada oluşacak)" -ForegroundColor DarkGray
    }

    # Sertifika var mı?
    $certPath = Join-Path $resolverPath "cert.pem"
    if (Test-Path $certPath) {
        Write-Host "  ✓ TLS sertifikası mevcut" -ForegroundColor Green
    } else {
        Write-Host "  ○ TLS sertifikası (otomatik oluşturulacak)" -ForegroundColor DarkGray
    }

    # Port 53 aktif mi?
    Write-Host ""
    $port53 = netstat -ano | Select-String ":53\s" | Where-Object { $_ -match "UDP.*:53\s" }
    if ($port53) {
        Write-Host "  ⚠ Port 53 zaten kullanımda:" -ForegroundColor Yellow
        $port53 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "  ✓ Port 53 müsait" -ForegroundColor Green
    }

    # Zamanlanmış görev var mı?
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "  ✓ Windows Servisi: $($task.State)" -ForegroundColor Green
    } else {
        Write-Host "  ○ Windows Servisi kurulu değil" -ForegroundColor DarkGray
    }

    # Mevcut DNS
    Write-Host ""
    Write-Host "  Mevcut DNS Ayarları:" -ForegroundColor Yellow
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Select-Object InterfaceAlias, ServerAddresses -First 3 |
        ForEach-Object {
            Write-Host "    $($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" -ForegroundColor DarkGray
        }
    Write-Host ""
}

# ─── KURULUM ───
function Install-Resolver {
    Write-Banner

    if (-not (Test-Admin)) {
        Write-Host "  ✗ Yönetici yetkisi gerekli!" -ForegroundColor Red
        Write-Host "    PowerShell'i sağ tık → 'Yönetici olarak çalıştır' ile açın" -ForegroundColor Yellow
        return
    }

    Write-Host "  Kurulum Başlıyor..." -ForegroundColor Green
    Write-Host ""

    # 1) Exe kontrolü
    if (-not (Test-Path $exePath)) {
        Write-Host "  [1/4] Derleniyor..." -ForegroundColor Yellow
        Push-Location $resolverPath
        go build -o ceky-resolver.exe .
        Pop-Location
        if (-not (Test-Path $exePath)) {
            Write-Host "  ✗ Derleme başarısız!" -ForegroundColor Red
            return
        }
    }
    Write-Host "  [1/4] ✓ Exe hazır" -ForegroundColor Green

    # 2) Windows DNS'ini 127.0.0.1 yap
    Write-Host "  [2/4] DNS ayarlanıyor → 127.0.0.1" -ForegroundColor Yellow

    # Aktif ağ adaptörlerini bul
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $backupFile = Join-Path $resolverPath "dns_backup.json"
    $backupData = @()

    foreach ($adapter in $adapters) {
        # Mevcut DNS'i yedekle
        $currentDns = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
        $backupData += @{
            InterfaceIndex = $adapter.ifIndex
            InterfaceAlias = $adapter.InterfaceAlias
            OriginalDNS = $currentDns
        }

        # DNS'i 127.0.0.1 + 8.8.8.8 (yedek) yap
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("127.0.0.1", "8.8.8.8")
        Write-Host "    ✓ $($adapter.InterfaceAlias) → 127.0.0.1, 8.8.8.8" -ForegroundColor Green
    }

    # DNS yedeğini kaydet
    $backupData | ConvertTo-Json -Depth 3 | Set-Content $backupFile
    Write-Host "    DNS yedeği: dns_backup.json" -ForegroundColor DarkGray

    # 3) Zamanlanmış görev (otomatik başlatma)
    Write-Host "  [3/4] Windows Servisi oluşturuluyor..." -ForegroundColor Yellow

    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute $exePath -WorkingDirectory $resolverPath
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Ceky Resolver — Rekursif DNS + Reklam Engelleme" | Out-Null
    Write-Host "  [3/4] ✓ Bilgisayar açıldığında otomatik başlayacak" -ForegroundColor Green

    # 4) Servisi hemen başlat
    Write-Host "  [4/4] Başlatılıyor..." -ForegroundColor Yellow
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 2

    # Kontrol
    $running = Get-ScheduledTask -TaskName $taskName
    if ($running.State -eq "Running") {
        Write-Host "  [4/4] ✓ Ceky Resolver çalışıyor!" -ForegroundColor Green
    } else {
        Write-Host "  [4/4] ⚠ Başlatma sorunu, manuel deneyin: .\ceky-resolver.exe" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Kurulum tamamlandı!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  DNS:       127.0.0.1:53" -ForegroundColor White
    Write-Host "  Dashboard: http://127.0.0.1:9090" -ForegroundColor White
    Write-Host "  Kaldırma:  .\setup.ps1 -Uninstall" -ForegroundColor DarkGray
    Write-Host ""
}

# ─── KALDIRMA ───
function Uninstall-Resolver {
    Write-Banner

    if (-not (Test-Admin)) {
        Write-Host "  ✗ Yönetici yetkisi gerekli!" -ForegroundColor Red
        return
    }

    Write-Host "  Kaldırma Başlıyor..." -ForegroundColor Yellow
    Write-Host ""

    # 1) Servisi durdur ve kaldır
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") {
            Stop-ScheduledTask -TaskName $taskName
            Start-Sleep -Seconds 1
        }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "  ✓ Windows Servisi kaldırıldı" -ForegroundColor Green
    }

    # 2) DNS'i geri al
    $backupFile = Join-Path $resolverPath "dns_backup.json"
    if (Test-Path $backupFile) {
        $backupData = Get-Content $backupFile | ConvertFrom-Json
        foreach ($entry in $backupData) {
            if ($entry.OriginalDNS -and $entry.OriginalDNS.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceIndex $entry.InterfaceIndex -ServerAddresses $entry.OriginalDNS
                Write-Host "  ✓ $($entry.InterfaceAlias) → $($entry.OriginalDNS -join ', ')" -ForegroundColor Green
            } else {
                Set-DnsClientServerAddress -InterfaceIndex $entry.InterfaceIndex -ResetServerAddresses
                Write-Host "  ✓ $($entry.InterfaceAlias) → DHCP (otomatik)" -ForegroundColor Green
            }
        }
        Remove-Item $backupFile -Force
    } else {
        # Yedek yoksa DHCP'ye dön
        Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
            Write-Host "  ✓ $($_.InterfaceAlias) → DHCP (otomatik)" -ForegroundColor Green
        }
    }

    # 3) Çalışan process'i durdur
    Get-Process -Name "ceky-resolver" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "  ✓ Process durduruldu" -ForegroundColor Green

    Write-Host ""
    Write-Host "  ═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Kaldırma tamamlandı. DNS ayarları eski haline döndü." -ForegroundColor Green
    Write-Host "  Dosyalar yerinde kaldı (elle silebilirsiniz)." -ForegroundColor DarkGray
    Write-Host ""
}

# ─── ANA AKIŞ ───
if ($Install) {
    Install-Resolver
} elseif ($Uninstall) {
    Uninstall-Resolver
} elseif ($Status) {
    Show-Status
} else {
    Write-Banner
    Write-Host "  Kullanım:" -ForegroundColor Yellow
    Write-Host "    .\setup.ps1 -Status     Sistem durumunu göster" -ForegroundColor White
    Write-Host "    .\setup.ps1 -Install    Kur ve DNS'i ayarla" -ForegroundColor White
    Write-Host "    .\setup.ps1 -Uninstall  Kaldır ve DNS'i geri al" -ForegroundColor White
    Write-Host ""
    Write-Host "  Not: -Install ve -Uninstall için Yönetici yetkisi gerekir." -ForegroundColor DarkGray
    Write-Host ""
}
