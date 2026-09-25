//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"unicode/utf16"
)

// ==================== WINDOWS: SİSTEM DNS ====================
//
// Her ağ bağdaştırıcısının elle girilmiş (statik) DNS ayarı kayıt defterinden
// okunur; boşsa bağdaştırıcı DHCP kullanıyordur ve geri yüklemede "otomatik"e döner.

const psBackupScript = `
$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$out = @()
foreach ($a in @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })) {
  $g = $a.InterfaceGuid
  $v4 = [string](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -Name NameServer).NameServer
  $v6 = [string](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -Name NameServer).NameServer
  $eff = (@((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex).ServerAddresses) | Where-Object { $_ }) -join ','
  $out += [pscustomobject]@{ index = [int]$a.ifIndex; alias = [string]$a.InterfaceAlias; v4 = $v4; v6 = $v6; effective = [string]$eff }
}
ConvertTo-Json -InputObject @($out) -Compress
`

// runPowerShell — betiği -EncodedCommand ile çalıştır (tırnak/kaçış sorunu olmaz)
func runPowerShell(script string) (string, error) {
	u := utf16.Encode([]rune(script))
	buf := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	return runSystemCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(buf))
}

func queryWindowsAdapters() ([]winIfaceDNS, error) {
	out, err := runPowerShell(psBackupScript)
	start, end := strings.Index(out, "["), strings.LastIndex(out, "]")
	if start < 0 || end < start {
		return nil, fmt.Errorf("ağ bağdaştırıcıları okunamadı: %v %s", err, strings.TrimSpace(out))
	}
	var ifaces []winIfaceDNS
	if err := json.Unmarshal([]byte(out[start:end+1]), &ifaces); err != nil {
		return nil, err
	}
	for i := range ifaces {
		// Önceki bir kurulumdan kalan 127.0.0.1 statik ayarı "otomatik" sayılır
		v4, v6 := splitServers(ifaces[i].V4), splitServers(ifaces[i].V6)
		if len(withoutOurAddrs(v4)) != len(v4) || len(withoutOurAddrs(v6)) != len(v6) {
			v4, v6 = nil, nil
		}
		ifaces[i].V4, ifaces[i].V6 = strings.Join(v4, ","), strings.Join(v6, ",")
	}
	return ifaces, nil
}

// upInterfaceIndexes — açık (up) ve loopback olmayan arayüzler
func upInterfaceIndexes() []int {
	var out []int
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			out = append(out, i.Index)
		}
	}
	return out
}

func platformBackup() (*sysDNSBackup, error) {
	ifaces, err := queryWindowsAdapters()
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("etkin ağ bağdaştırıcısı bulunamadı")
	}
	b := &sysDNSBackup{Windows: ifaces, WindowsSeen: upInterfaceIndexes()}
	for _, i := range ifaces {
		b.Original = append(b.Original, splitServers(i.Effective)...)
	}
	return b, nil
}

func psList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		if net.ParseIP(s) != nil { // Betiğe yalnızca doğrulanmış IP'ler girer
			quoted = append(quoted, "'"+s+"'")
		}
	}
	return "@(" + strings.Join(quoted, ",") + ")"
}

func applyToAdapters(ifaces []winIfaceDNS, addrs []string) error {
	var v4 []string
	for _, a := range addrs {
		if net.ParseIP(a).To4() != nil {
			v4 = append(v4, a)
		}
	}
	var sb strings.Builder
	sb.WriteString("$ErrorActionPreference = 'Continue'\n")
	for _, i := range ifaces {
		fmt.Fprintf(&sb, `try { Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s -ErrorAction Stop; Write-Output 'OK' }
catch { try { Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s -ErrorAction Stop; Write-Output 'OK' } catch { Write-Output ('HATA %d: ' + $_.Exception.Message) } }
`, i.Index, psList(addrs), i.Index, psList(v4), i.Index)
	}
	sb.WriteString("Clear-DnsClientCache\n")

	out, err := runPowerShell(sb.String())
	if !hasLine(out, "OK") {
		return fmt.Errorf("DNS ayarlanamadı: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

func platformApply(b *sysDNSBackup, addrs []string) error {
	return applyToAdapters(b.Windows, addrs)
}

func platformRestore(b *sysDNSBackup) error {
	var sb strings.Builder
	sb.WriteString("$ErrorActionPreference = 'Continue'\n")
	for _, i := range b.Windows {
		fmt.Fprintf(&sb, "try { Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses -ErrorAction Stop } catch {}\n", i.Index)
		static := append(splitServers(i.V4), splitServers(i.V6)...)
		if len(static) > 0 {
			fmt.Fprintf(&sb, "try { Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s -ErrorAction Stop } catch {}\n",
				i.Index, psList(static))
		}
	}
	sb.WriteString("Clear-DnsClientCache\nWrite-Output 'BITTI'\n")
	out, err := runPowerShell(sb.String())
	if !hasLine(out, "BITTI") {
		return fmt.Errorf("DNS geri yüklenemedi: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

// platformReconcile — sonradan açılan bağdaştırıcıları (ör. yeni Wi-Fi kartı) da yönlendir
func platformReconcile(b *sysDNSBackup) (bool, error) {
	seen := make(map[int]bool)
	for _, i := range b.WindowsSeen {
		seen[i] = true
	}
	current := upInterfaceIndexes()
	fresh := false
	for _, i := range current {
		if !seen[i] {
			fresh = true
		}
	}
	if !fresh {
		return false, nil
	}

	for _, i := range current {
		if !seen[i] {
			seen[i] = true
			b.WindowsSeen = append(b.WindowsSeen, i)
		}
	}
	ifaces, err := queryWindowsAdapters()
	if err != nil {
		return true, err
	}
	known := make(map[int]bool)
	for _, i := range b.Windows {
		known[i.Index] = true
	}
	var added []winIfaceDNS
	for _, i := range ifaces {
		if !known[i.Index] {
			added = append(added, i)
		}
	}
	if len(added) == 0 {
		return true, nil
	}
	b.Windows = append(b.Windows, added...)
	return true, applyToAdapters(added, b.Addrs)
}

func platformCurrent() []string {
	out, _ := runPowerShell(`(@(Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses }) | Sort-Object -Unique) -join ','`)
	return splitServers(strings.TrimSpace(out))
}

// Önbellek temizliği PowerShell betiklerinin içinde yapılıyor
func flushOSCache() {}
