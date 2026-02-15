//go:build windows

package main

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WINDIVERT_ADDRESS layout matching basil00/Divert include/windivert.h exactly.
// INT64 Timestamp; UINT32 (Layer:8, Event:8, Sniffed:1, Outbound:1, ...); UINT32 Reserved2; union { Network; ... } [64 bytes].
type divertAddress struct {
	Timestamp  int64
	Flags32    uint32 // Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8
	Reserved2  uint32
	IfIdx      uint32 // WINDIVERT_DATA_NETWORK
	SubIfIdx   uint32
	_          [56]byte // union padding to 64 bytes (Reserved3[64])
}

// Outbound returns true if the packet is outbound (Outbound bit in Flags32).
func (a *divertAddress) Outbound() bool {
	return (a.Flags32>>17)&1 != 0
}

// NewInboundAddress returns an address for WinDivertSend of an inbound packet on the given interface.
func NewInboundAddress(ifIdx, subIfIdx uint32) divertAddress {
	const (
		layerNetwork   = 0
		eventNetPacket = 0
		bitImpostor    = 19
		bitIPChecksum  = 21
		bitTCPChecksum = 22
	)
	a := divertAddress{}
	a.Flags32 = (layerNetwork & 0xff) | (eventNetPacket&0xff)<<8 | 1<<bitImpostor | 1<<bitIPChecksum | 1<<bitTCPChecksum
	a.IfIdx = ifIdx
	a.SubIfIdx = subIfIdx
	return a
}

// ToInbound returns a copy of the address with only Outbound=0 for reinjecting as inbound.
// Checksum flags are left to WinDivertHelperCalcChecksums(packet, pAddr); we do not set Impostor
// so the driver may treat this as a normal re-injection of a diverted packet.
func (a *divertAddress) ToInbound() divertAddress {
	const bitOutbound = 17
	out := *a
	out.Flags32 = out.Flags32 &^ (1 << bitOutbound)
	return out
}

type divertHandle uintptr

var (
	winDivertDLL          = windows.NewLazyDLL("WinDivert.dll")
	procOpen              = winDivertDLL.NewProc("WinDivertOpen")
	procRecv              = winDivertDLL.NewProc("WinDivertRecv")
	procSend              = winDivertDLL.NewProc("WinDivertSend")
	procSendEx             = winDivertDLL.NewProc("WinDivertSendEx")
	procClose             = winDivertDLL.NewProc("WinDivertClose")
	procHelperCalcChecksum = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
	procGetParam          = winDivertDLL.NewProc("WinDivertGetParam")
)

const (
	recvOrderUnknown      int32 = 0
	recvOrderAddrThenLen  int32 = 1 // (pAddr, pRecvLen) - official docs
	recvOrderLenThenAddr  int32 = 2 // (pRecvLen, pAddr) - seen in some bindings
)

var recvOrder atomic.Int32

const (
	sendOrderUnknown     int32 = 0
	sendOrderAddrThenLen int32 = 1 // (pAddr, pSendLen) - official docs
	sendOrderLenThenAddr int32 = 2 // (pSendLen, pAddr) - seen in some bindings
)

var sendOrder atomic.Int32

func openDivert(filter string, flags uint64) (divertHandle, error) {
	if err := winDivertDLL.Load(); err != nil {
		return 0, err
	}
	filterBytes := append([]byte(filter), 0)
	h, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(&filterBytes[0])),
		uintptr(0), // WINDIVERT_LAYER_NETWORK
		uintptr(0), // priority
		uintptr(flags), // flags
	)
	if h == uintptr(^uintptr(0)) || h == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, fmt.Errorf("WinDivertOpen failed")
	}
	return divertHandle(h), nil
}

// GetVersion returns (major, minor) of the loaded driver via WinDivertGetParam, or 0,0 on failure.
func (h divertHandle) GetVersion() (major, minor uint64) {
	if winDivertDLL.Load() != nil {
		return 0, 0
	}
	var v uint64
	// WINDIVERT_PARAM_VERSION_MAJOR = 3, WINDIVERT_PARAM_VERSION_MINOR = 4
	r1, _, _ := procGetParam.Call(uintptr(h), 3, uintptr(unsafe.Pointer(&v)))
	if r1 == 0 {
		return 0, 0
	}
	major = v
	r1, _, _ = procGetParam.Call(uintptr(h), 4, uintptr(unsafe.Pointer(&v)))
	if r1 == 0 {
		return major, 0
	}
	return major, v
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

	try := func(order int32) (int, divertAddress, bool, error) {
		var recvLen uint32
		var addr divertAddress
		var r1 uintptr
		var callErr error
		switch order {
		case recvOrderAddrThenLen:
			r1, _, callErr = procRecv.Call(
				uintptr(h),
				uintptr(unsafe.Pointer(&packet[0])),
				uintptr(len(packet)),
				uintptr(unsafe.Pointer(&addr)),
				uintptr(unsafe.Pointer(&recvLen)),
			)
		case recvOrderLenThenAddr:
			r1, _, callErr = procRecv.Call(
				uintptr(h),
				uintptr(unsafe.Pointer(&packet[0])),
				uintptr(len(packet)),
				uintptr(unsafe.Pointer(&recvLen)),
				uintptr(unsafe.Pointer(&addr)),
			)
		default:
			return 0, divertAddress{}, false, fmt.Errorf("unknown recv order")
		}
		if r1 == 0 {
			if callErr != nil && callErr != windows.ERROR_SUCCESS {
				return 0, divertAddress{}, false, callErr
			}
			return 0, divertAddress{}, false, nil
		}
		if recvLen == 0 || recvLen > uint32(len(packet)) {
			return 0, divertAddress{}, false, fmt.Errorf("recv length out of range: %d", recvLen)
		}
		return int(recvLen), addr, true, nil
	}

	// Prefer cached order once we know it.
	if cached := recvOrder.Load(); cached != recvOrderUnknown {
		if n, addr, ok, err := try(cached); ok {
			return n, addr, nil
		} else if err != nil {
			// Fall through to auto-detect.
		}
	}

	// WinDivert 2.x uses (pRecvLen, pAddr) per docs; try that first.
	n, addr, ok, err := try(recvOrderLenThenAddr)
	if ok {
		recvOrder.Store(recvOrderLenThenAddr)
		return n, addr, nil
	}
	n, addr, ok, err2 := try(recvOrderAddrThenLen)
	if ok {
		recvOrder.Store(recvOrderAddrThenLen)
		return n, addr, nil
	}
	if err2 != nil {
		return 0, divertAddress{}, err2
	}
	if err != nil {
		return 0, divertAddress{}, err
	}
	return 0, divertAddress{}, fmt.Errorf("WinDivertRecv failed")
}

func (h divertHandle) Send(packet []byte, addr divertAddress) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}

	try := func(order int32) (int, bool, error) {
		var sentLen uint32
		var r1 uintptr
		var callErr error
		switch order {
		case sendOrderAddrThenLen:
			r1, _, callErr = procSend.Call(
				uintptr(h),
				uintptr(unsafe.Pointer(&packet[0])),
				uintptr(len(packet)),
				uintptr(unsafe.Pointer(&addr)),
				uintptr(unsafe.Pointer(&sentLen)),
			)
		case sendOrderLenThenAddr:
			r1, _, callErr = procSend.Call(
				uintptr(h),
				uintptr(unsafe.Pointer(&packet[0])),
				uintptr(len(packet)),
				uintptr(unsafe.Pointer(&sentLen)),
				uintptr(unsafe.Pointer(&addr)),
			)
		default:
			return 0, false, fmt.Errorf("unknown send order")
		}
		if r1 == 0 {
			if callErr != nil && callErr != windows.ERROR_SUCCESS {
				return 0, false, callErr
			}
			return 0, false, nil
		}
		return int(sentLen), true, nil
	}

	if cached := sendOrder.Load(); cached != sendOrderUnknown {
		if n, ok, err := try(cached); ok {
			return n, nil
		} else if err != nil {
			// Fall through to auto-detect.
		}
	}

	// WinDivert 2.x uses (pSendLen, pAddr) per docs; try that first.
	n, ok, err := try(sendOrderLenThenAddr)
	if ok {
		sendOrder.Store(sendOrderLenThenAddr)
		return n, nil
	}
	n, ok, err2 := try(sendOrderAddrThenLen)
	if ok {
		sendOrder.Store(sendOrderAddrThenLen)
		return n, nil
	}
	if err2 != nil {
		return 0, err2
	}
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("WinDivertSend failed")
}

// sizeofDivertAddress is the size of WINDIVERT_ADDRESS for WinDivertSendEx addrLen.
const sizeofDivertAddress = 80

// SendEx uses WinDivertSendEx with explicit addrLen (flags=0, no overlapped).
// Returns (0, error) if SendEx is not available in the DLL (e.g. WinDivert 1.4).
func (h divertHandle) SendEx(packet []byte, addr *divertAddress) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}
	if procSendEx.Addr() == 0 {
		return 0, fmt.Errorf("WinDivertSendEx not available")
	}
	var sentLen uint32
	r1, _, callErr := procSendEx.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sentLen)),
		uintptr(0), // flags
		uintptr(unsafe.Pointer(addr)),
		uintptr(sizeofDivertAddress),
		uintptr(0), // lpOverlapped
	)
	if r1 == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, fmt.Errorf("WinDivertSendEx failed")
	}
	return int(sentLen), nil
}

// calcDivertChecksums recalculates IP/TCP/UDP checksums in the packet.
// If pAddr is not nil, the helper will set IPChecksum/TCPChecksum/UDPChecksum flags in the address.
func calcDivertChecksums(packet []byte, pAddr *divertAddress) {
	if len(packet) == 0 {
		return
	}
	addrPtr := uintptr(0)
	if pAddr != nil {
		addrPtr = uintptr(unsafe.Pointer(pAddr))
	}
	_, _, _ = procHelperCalcChecksum.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		addrPtr,
		uintptr(0), // flags
	)
}
