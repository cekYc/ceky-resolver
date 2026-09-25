//go:build windows

package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// ==================== WINDOWS: KALICI KURULUM ====================
// Bilgisayar açılışında SYSTEM hesabıyla çalışan bir Görev Zamanlayıcı görevi.

const serviceName = "CekyResolver"

func installedExePath() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "CekyResolver", "ceky-resolver.exe")
}

func xmlEscape(s string) string {
	var sb strings.Builder
	xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

func taskXML(exe, data string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Ceky Resolver — bağımsız rekürsif DNS çözümleyici</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(exe) + `</Command>
      <Arguments>service -data "` + xmlEscape(data) + `"</Arguments>
      <WorkingDirectory>` + xmlEscape(filepath.Dir(exe)) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
}

func registerService(exe, data string) error {
	// schtasks, XML dosyasını UTF-16 (BOM'lu) bekler
	u := utf16.Encode([]rune(taskXML(exe, data)))
	buf := []byte{0xFF, 0xFE}
	for _, c := range u {
		buf = append(buf, byte(c), byte(c>>8))
	}
	tmp := filepath.Join(os.TempDir(), "ceky-resolver-task.xml")
	if err := os.WriteFile(tmp, buf, 0644); err != nil {
		return err
	}
	defer os.Remove(tmp)

	if out, err := runSystemCmd("schtasks", "/Create", "/TN", serviceName, "/XML", tmp, "/F"); err != nil {
		return fmt.Errorf("görev oluşturulamadı: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

func startService() error {
	if out, err := runSystemCmd("schtasks", "/Run", "/TN", serviceName); err != nil {
		return fmt.Errorf("görev başlatılamadı: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

// stopService — görev sonlandırılır (DNS geri yüklemesini çağıran taraf yapar)
func stopService() error {
	runSystemCmd("schtasks", "/End", "/TN", serviceName)
	return nil
}

func unregisterService() error {
	if out, err := runSystemCmd("schtasks", "/Delete", "/TN", serviceName, "/F"); err != nil {
		return fmt.Errorf("görev silinemedi: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

func serviceInstalled() bool {
	_, err := runSystemCmd("schtasks", "/Query", "/TN", serviceName)
	return err == nil
}

// Görev sonlandırıldığında süreç kendi DNS ayarını geri alamaz
const serviceStopRestoresDNS = false
