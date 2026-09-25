//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
)

// ==================== LINUX: KALICI KURULUM (systemd) ====================

const (
	serviceName = "ceky-resolver"
	systemdUnit = "/etc/systemd/system/ceky-resolver.service"
)

func installedExePath() string { return "/usr/local/bin/ceky-resolver" }

func registerService(exe, data string) error {
	if !commandExists("systemctl") {
		return fmt.Errorf("systemd bulunamadı — %s service -data %s komutunu açılışta elle çalıştırın", exe, data)
	}
	unit := `[Unit]
Description=Ceky Resolver — bağımsız rekürsif DNS çözümleyici
After=network.target
Before=nss-lookup.target
Wants=nss-lookup.target

[Service]
Type=simple
ExecStart="` + exe + `" service -data "` + data + `"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(systemdUnit, []byte(unit), 0644); err != nil {
		return err
	}
	runSystemCmd("systemctl", "daemon-reload")
	if out, err := runSystemCmd("systemctl", "enable", serviceName); err != nil {
		return fmt.Errorf("servis etkinleştirilemedi: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

func startService() error {
	if out, err := runSystemCmd("systemctl", "restart", serviceName); err != nil {
		return fmt.Errorf("servis başlatılamadı: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

// stopService — systemd SIGTERM gönderir, süreç DNS ayarını kendisi geri yükler
func stopService() error {
	runSystemCmd("systemctl", "stop", serviceName)
	return nil
}

func unregisterService() error {
	runSystemCmd("systemctl", "disable", "--now", serviceName)
	if err := os.Remove(systemdUnit); err != nil && !os.IsNotExist(err) {
		return err
	}
	runSystemCmd("systemctl", "daemon-reload")
	return nil
}

func serviceInstalled() bool {
	_, err := os.Stat(systemdUnit)
	return err == nil
}

const serviceStopRestoresDNS = true
