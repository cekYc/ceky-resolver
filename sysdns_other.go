//go:build !windows && !darwin && !linux

package main

import "errors"

// ==================== DESTEKLENMEYEN PLATFORMLAR ====================
// DNS sunucusu çalışır; yalnızca sistem ayarının otomatik değiştirilmesi yoktur.

var errUnsupported = errors.New("bu işletim sisteminde sistem DNS ayarı otomatik değiştirilemiyor — /etc/resolv.conf'u elle düzenleyin")

func platformBackup() (*sysDNSBackup, error)        { return nil, errUnsupported }
func platformApply(*sysDNSBackup, []string) error   { return errUnsupported }
func platformRestore(*sysDNSBackup) error           { return nil }
func platformReconcile(*sysDNSBackup) (bool, error) { return false, nil }
func platformCurrent() []string                     { return nil }
func flushOSCache()                                 {}
