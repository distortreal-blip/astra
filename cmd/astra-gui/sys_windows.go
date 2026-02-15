//go:build windows

package main

import "syscall"

func windowsSysProcAttrHide() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
