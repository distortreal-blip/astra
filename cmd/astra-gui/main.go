package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

const appVersion = "0.1"

type clientProcess struct {
	cmd     *exec.Cmd
	name    string
	logOut  *os.File
	logErr  *os.File
	logDir  string
	started time.Time
}

func main() {
	root := repoRoot()
	logDir := filepath.Join(root, "logs")
	_ = os.MkdirAll(logDir, 0755)

	a := app.New()
	a.Settings().SetTheme(newCosmicTheme())
	w := a.NewWindow("Astra")
	w.CenterOnScreen()
	// Figma design: 300×600, vertical
	w.Resize(fyne.NewSize(300, 600))
	w.SetFixedSize(false)

	status := widget.NewLabel("Отключено")
	status.Alignment = fyne.TextAlignCenter

	var current *clientProcess
	resetToken := true

	startTun := func() {
		if current != nil {
			return
		}
		if err := ensureBinary(root,
			filepath.Join(root, "astra-tun-client.exe"),
			filepath.Join(root, "cmd", "astra-tun-client")); err != nil {
			dialog.ShowError(err, w)
			return
		}
		if resetToken {
			_ = os.Remove(filepath.Join(root, "token.dat"))
		}
		proc, err := runClient(root, logDir, "astra-tun-client",
			filepath.Join(root, "astra-tun-client.exe"),
			filepath.Join(root, "configs", "astra-tun-client.json"))
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		current = proc
		status.SetText(fmt.Sprintf("Подключено (PID %d)", proc.cmd.Process.Pid))
	}

	stopTun := func() {
		if current != nil {
			stopClient(current)
			current = nil
			status.SetText("Отключено")
		}
	}

	var powerBtn *widget.Button
	powerBtn = widget.NewButton("  ⏻  Connect  ", func() {
		if current != nil {
			stopTun()
			powerBtn.SetText("  ⏻  Connect  ")
		} else {
			startTun()
			powerBtn.SetText("  ⏻  Disconnect  ")
		}
	})
	powerBtn.Importance = widget.HighImportance
	powerBtn.Resize(fyne.NewSize(180, 64))

	openLogsBtn := widget.NewButton("Открыть логи", func() {
		openPath(logDir)
	})
	openLogsBtn.Importance = widget.LowImportance

	// Layout from Figma SVG: title at top, power center, status, Open logs pill at bottom
	title := widget.NewLabelWithStyle("Astra", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	version := widget.NewLabelWithStyle("v."+appVersion, fyne.TextAlignCenter, fyne.TextStyle{})
	versionLabel := container.NewCenter(version)
	titleBlock := container.NewVBox(title, versionLabel)

	top := container.NewVBox(
		layout.NewSpacer(),
		titleBlock,
		layout.NewSpacer(),
		container.NewCenter(powerBtn),
		layout.NewSpacer(),
		status,
		layout.NewSpacer(),
	)
	// Bottom: pill-style "Open logs" (SVG: ~103×26, rx 9)
	openLogsWrap := container.NewCenter(openLogsBtn)
	content := container.NewBorder(nil, openLogsWrap, nil, nil, top)
	w.SetContent(content)

	w.ShowAndRun()
}

func runClient(root, logDir, name, binPath, configPath string) (*clientProcess, error) {
	logOutPath := filepath.Join(logDir, name+".out.log")
	logErrPath := filepath.Join(logDir, name+".err.log")
	logOut, err := os.OpenFile(logOutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	logErr, err := os.OpenFile(logErrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		_ = logOut.Close()
		return nil, err
	}
	cmd := exec.Command(binPath, "-config", configPath)
	cmd.Dir = root
	cmd.Stdout = io.MultiWriter(logOut)
	cmd.Stderr = io.MultiWriter(logErr)
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		_ = logOut.Close()
		_ = logErr.Close()
		return nil, err
	}
	return &clientProcess{
		cmd:     cmd,
		name:    name,
		logOut:  logOut,
		logErr:  logErr,
		logDir:  logDir,
		started: time.Now(),
	}, nil
}

func stopClient(proc *clientProcess) {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return
	}
	_ = proc.cmd.Process.Kill()
	_, _ = proc.cmd.Process.Wait()
	if proc.logOut != nil {
		_ = proc.logOut.Close()
	}
	if proc.logErr != nil {
		_ = proc.logErr.Close()
	}
}

func ensureBinary(root, binPath, cmdPath string) error {
	if _, err := os.Stat(binPath); err == nil {
		return nil
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("missing %s and Go is not installed", filepath.Base(binPath))
	}
	buildCmd := exec.Command(goBin, "build", "-o", binPath, cmdPath)
	buildCmd.Dir = root
	hideWindow(buildCmd)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build failed: %s", string(out))
	}
	return nil
}

func repoRoot() string {
	exe, err := os.Executable()
	if err != nil {
		if cwd, err2 := os.Getwd(); err2 == nil {
			return cwd
		}
		return "."
	}
	return filepath.Dir(exe)
}

func openPath(path string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("explorer", path).Start()
	case "darwin":
		_ = exec.Command("open", path).Start()
	default:
		_ = exec.Command("xdg-open", path).Start()
	}
}

func hideWindow(cmd *exec.Cmd) {
	if runtime.GOOS != "windows" {
		return
	}
	cmd.SysProcAttr = windowsSysProcAttrHide()
}
