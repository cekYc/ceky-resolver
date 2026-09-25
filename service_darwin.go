//go:build darwin

package main

import (
	"fmt"
	"os"
	"strings"
)

// ==================== macOS: KALICI KURULUM (launchd) ====================

const (
	serviceName  = "com.cekyc.ceky-resolver"
	launchdPlist = "/Library/LaunchDaemons/com.cekyc.ceky-resolver.plist"
)

func installedExePath() string { return "/usr/local/bin/ceky-resolver" }

func plistEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func registerService(exe, data string) error {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + serviceName + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + plistEscape(exe) + `</string>
    <string>service</string>
    <string>-data</string>
    <string>` + plistEscape(data) + `</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Library/Logs/ceky-resolver.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/ceky-resolver.log</string>
</dict>
</plist>
`
	return os.WriteFile(launchdPlist, []byte(plist), 0644)
}

func startService() error {
	out, err := runSystemCmd("launchctl", "bootstrap", "system", launchdPlist)
	if err != nil {
		// Zaten yüklüyse yeniden başlat
		if out2, err2 := runSystemCmd("launchctl", "kickstart", "-k", "system/"+serviceName); err2 != nil {
			return fmt.Errorf("servis başlatılamadı: %v %s %s", err, strings.TrimSpace(out), strings.TrimSpace(out2))
		}
	}
	return nil
}

// stopService — launchd SIGTERM gönderir, süreç DNS ayarını kendisi geri yükler
func stopService() error {
	runSystemCmd("launchctl", "bootout", "system/"+serviceName)
	return nil
}

func unregisterService() error {
	stopService()
	if err := os.Remove(launchdPlist); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func serviceInstalled() bool {
	_, err := os.Stat(launchdPlist)
	return err == nil
}

const serviceStopRestoresDNS = true
