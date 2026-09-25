//go:build !windows && !darwin && !linux

package main

import "errors"

// ==================== DESTEKLENMEYEN PLATFORMLAR ====================

const serviceName = "ceky-resolver"

var errNoService = errors.New("bu işletim sisteminde kalıcı kurulum desteklenmiyor — 'ceky-resolver service' komutunu açılışta elle çalıştırın")

func installedExePath() string             { return "/usr/local/bin/ceky-resolver" }
func registerService(string, string) error { return errNoService }
func startService() error                  { return errNoService }
func stopService() error                   { return nil }
func unregisterService() error             { return nil }
func serviceInstalled() bool               { return false }

const serviceStopRestoresDNS = true
