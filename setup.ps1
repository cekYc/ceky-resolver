# ═══════════════════════════════════════════════════
#  Ceky Resolver — Kurulum Script'i (geriye dönük uyumluluk)
#  Artık tüm işlemleri programın kendisi yapıyor; bu script
#  yalnızca gerekirse derleyip ilgili komutu çağırır.
# ═══════════════════════════════════════════════════

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Restore,
    [switch]$Status
)

$ErrorActionPreference = "Stop"
$exePath = Join-Path $PSScriptRoot "ceky-resolver.exe"

if (-not (Test-Path $exePath)) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Host "  ✗ ceky-resolver.exe bulunamadı." -ForegroundColor Red
        Write-Host "    Hazır sürümü indirin: https://github.com/cekYc/ceky-resolver/releases/latest" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  Derleniyor..." -ForegroundColor Yellow
    Push-Location $PSScriptRoot
    go build -o ceky-resolver.exe .
    Pop-Location
}

# Yönetici izni gerekiyorsa program kendisi UAC penceresi açar
if ($Install)       { & $exePath install }
elseif ($Uninstall) { & $exePath uninstall }
elseif ($Restore)   { & $exePath restore }
elseif ($Status)    { & $exePath status }
else {
    Write-Host ""
    Write-Host "  Kullanım:" -ForegroundColor Yellow
    Write-Host "    .\setup.ps1 -Install     Kalıcı kur (açılışta otomatik başlar)" -ForegroundColor White
    Write-Host "    .\setup.ps1 -Uninstall   Kaldır ve DNS ayarlarını geri yükle" -ForegroundColor White
    Write-Host "    .\setup.ps1 -Restore     ACİL: DNS ayarlarını hemen geri yükle" -ForegroundColor White
    Write-Host "    .\setup.ps1 -Status      Durumu göster" -ForegroundColor White
    Write-Host ""
    Write-Host "  Ya da sadece ceky-resolver.exe'ye çift tıklayın." -ForegroundColor DarkGray
    Write-Host ""
}
