//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"syscall"
)

// ==================== macOS / LINUX PLATFORM ====================

// isAdmin — root olarak mı çalışıyoruz?
func isAdmin() bool {
	return os.Geteuid() == 0
}

// systemDataDir — servis ve yönetici modunda kullanılan ortak klasör
func systemDataDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/CekyResolver"
	}
	return "/var/lib/ceky-resolver"
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// relaunchElevated — terminaldeysek süreci "sudo" ile yeniden başlat (geri dönmez)
func relaunchElevated(args []string) error {
	if !isTerminal(os.Stdin) {
		return errors.New("terminal yok")
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	fmt.Println("🔑 Sistem DNS ayarını değiştirmek için yönetici izni gerekiyor (sudo parolanız istenecek)...")
	return syscall.Exec(sudo, append([]string{"sudo", exe}, args...), os.Environ())
}

// openBrowser — sudo ile çalışıyorsak tarayıcıyı asıl kullanıcı adına aç
func openBrowser(url string) {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	} else if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return // Grafik oturum yok (sunucu)
	}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && isAdmin() {
		args := []string{"-u", sudoUser}
		if runtime.GOOS != "darwin" {
			env := []string{"env"}
			for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"} {
				if v := os.Getenv(k); v != "" {
					env = append(env, k+"="+v)
				}
			}
			if u, err := user.Lookup(sudoUser); err == nil {
				env = append(env, "XDG_RUNTIME_DIR=/run/user/"+u.Uid)
			}
			args = append(args, env...)
		}
		exec.Command("sudo", append(args, opener, url)...).Start()
		return
	}
	exec.Command(opener, url).Start()
}

// ownsConsole — Windows'a özgü (çift tıklamayla açılan konsol)
func ownsConsole() bool { return false }

// redirectOutput — Unix'te servis çıktısını systemd/launchd toplar
func redirectOutput(string) {}

func hiddenCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
