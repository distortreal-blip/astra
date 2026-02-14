//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	directionOutbound = 0
	directionInbound  = 1
)

type divertAddress struct {
	IfIdx     uint32
	SubIfIdx  uint32
	Direction uint8
	_         [7]byte
}

type divertHandle uintptr

var (
	// Use standard DLL search (includes current/exe directory), since users
	// commonly place WinDivert.dll рядом с astra-divert-client.exe.
	winDivertDLL          = windows.NewLazyDLL("WinDivert.dll")
	procOpen              = winDivertDLL.NewProc("WinDivertOpen")
	procRecv              = winDivertDLL.NewProc("WinDivertRecv")
	procSend              = winDivertDLL.NewProc("WinDivertSend")
	procClose             = winDivertDLL.NewProc("WinDivertClose")
	procHelperCalcChecksum = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
)

func openDivert(filter string) (divertHandle, error) {
	if err := winDivertDLL.Load(); err != nil {
		return 0, err
	}
	filterBytes := append([]byte(filter), 0)
	h, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(&filterBytes[0])),
		uintptr(0), // WINDIVERT_LAYER_NETWORK
		uintptr(0), // priority
		uintptr(0), // flags
	)
	if h == uintptr(^uintptr(0)) || h == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, fmt.Errorf("WinDivertOpen failed")
	}
	return divertHandle(h), nil
}

func (h divertHandle) Close() error {
	r1, _, callErr := procClose.Call(uintptr(h))
	if r1 == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return callErr
		}
		return fmt.Errorf("WinDivertClose failed")
	}
	return nil
}

func (h divertHandle) Recv(packet []byte) (int, divertAddress, error) {
	if len(packet) == 0 {
		return 0, divertAddress{}, nil
	}

	// WinDivert 2.x signature:
	// WinDivertRecv(handle, pPacket, packetLen, pRecvLen, pAddr)
	var recvLen uint32
	var addr divertAddress
	r1, _, callErr := procRecv.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 != 0 {
		if recvLen <= uint32(len(packet)) {
			return int(recvLen), addr, nil
		}
		return 0, addr, fmt.Errorf("recv length out of range: %d", recvLen)
	}

	// Fallback for older order used by old wrappers:
	// WinDivertRecv(handle, pPacket, packetLen, pAddr, pRecvLen)
	recvLen = 0
	addr = divertAddress{}
	r1, _, callErr = procRecv.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&recvLen)),
	)
	if r1 != 0 {
		if recvLen <= uint32(len(packet)) {
			return int(recvLen), addr, nil
		}
		return 0, addr, fmt.Errorf("recv length out of range: %d", recvLen)
	}

	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		return 0, divertAddress{}, callErr
	}
	return 0, divertAddress{}, fmt.Errorf("WinDivertRecv failed")
}

func (h divertHandle) Send(packet []byte, addr divertAddress) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}

	// WinDivert 2.x signature:
	// WinDivertSend(handle, pPacket, packetLen, pSendLen, pAddr)
	var sentLen uint32
	r1, _, callErr := procSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sentLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 != 0 {
		return int(sentLen), nil
	}

	// Fallback for older order used by old wrappers:
	// WinDivertSend(handle, pPacket, packetLen, pAddr, pSendLen)
	sentLen = 0
	r1, _, callErr = procSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&sentLen)),
	)
	if r1 != 0 {
		return int(sentLen), nil
	}

	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		return 0, callErr
	}
	return 0, fmt.Errorf("WinDivertSend failed")
}

func calcDivertChecksums(packet []byte) {
	if len(packet) == 0 {
		return
	}
	_, _, _ = procHelperCalcChecksum.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(0),
	)
}
