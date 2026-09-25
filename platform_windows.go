//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// ==================== WINDOWS PLATFORM ====================

var (
	shell32                   = syscall.NewLazyDLL("shell32.dll")
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procIsUserAnAdmin         = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW         = shell32.NewProc("ShellExecuteW")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// isAdmin — süreç yönetici (elevated) olarak mı çalışıyor?
func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

// systemDataDir — servis ve yönetici modunda kullanılan ortak klasör
func systemDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "CekyResolver")
}

// relaunchElevated — UAC penceresiyle kendini yönetici olarak yeniden başlat
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))

	const swShowNormal = 1
	r, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), swShowNormal)
	if r <= 32 {
		return fmt.Errorf("yönetici izni verilmedi (kod %d)", r)
	}
	return nil
}

// openBrowser — Yönetici süreçten açılan tarayıcı da yönetici olmasın diye
// adres Explorer'a (normal kullanıcı oturumu) devredilir
func openBrowser(url string) {
	exec.Command("explorer.exe", url).Start()
}

// ownsConsole — konsol penceresi bu süreç için mi açıldı (çift tıklama)?
func ownsConsole() bool {
	var ids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), 2)
	return n == 1
}

// redirectOutput — Servis modunda konsol yok; çıktı log dosyasına yazılır
func redirectOutput(path string) {
	if info, err := os.Stat(path); err == nil && info.Size() > 5<<20 {
		os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	os.Stdout = f
	os.Stderr = f
}

// hiddenCommand — pencere açmadan çalışan alt süreç
func hiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd
}
