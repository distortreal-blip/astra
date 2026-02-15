package tun

import (
	"fmt"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const packetOffset = 16

// numReadBufs is the number of buffers passed to TUN Read on Linux (GSO can return multiple segments).
const numReadBufs = 64
const readBufSize = 2048 // each segment typically ≤ MTU

type Device struct {
	Tun  tun.Device
	Name string
	MTU  int

	// Linux GSO: Read can return multiple segments; we pass multiple bufs and queue extras.
	mu      sync.Mutex
	pending [][]byte
	readBufs [][]byte
}

func Create(name string, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = 1400
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}
	actualMTU, err := dev.MTU()
	if err == nil {
		mtu = actualMTU
	}
	actualName, err := dev.Name()
	if err == nil {
		name = actualName
	}
	d := &Device{Tun: dev, Name: name, MTU: mtu}
	if runtime.GOOS == "linux" {
		d.readBufs = make([][]byte, numReadBufs)
		for i := range d.readBufs {
			d.readBufs[i] = make([]byte, readBufSize)
		}
	}
	return d, nil
}

func Close(dev *Device) error {
	if dev == nil || dev.Tun == nil {
		return nil
	}
	return dev.Tun.Close()
}

func ReadPacket(dev *Device, buf []byte) (int, error) {
	if dev == nil || dev.Tun == nil {
		return 0, fmt.Errorf("tun not initialized")
	}
	// Linux with GSO: serve queued packets first, then use multi-buffer Read to avoid "too many segments".
	if dev.readBufs != nil {
		dev.mu.Lock()
		if len(dev.pending) > 0 {
			p := dev.pending[0]
			dev.pending = dev.pending[1:]
			dev.mu.Unlock()
			n := copy(buf, p)
			return n, nil
		}
		dev.mu.Unlock()

		sizes := make([]int, len(dev.readBufs))
		n, err := dev.Tun.Read(dev.readBufs, sizes, 0)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}
		copy(buf, dev.readBufs[0][:sizes[0]])
		dev.mu.Lock()
		for i := 1; i < n; i++ {
			p := make([]byte, sizes[i])
			copy(p, dev.readBufs[i][:sizes[i]])
			dev.pending = append(dev.pending, p)
		}
		dev.mu.Unlock()
		return sizes[0], nil
	}

	bufs := [][]byte{buf}
	sizes := make([]int, 1)
	n, err := dev.Tun.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func WritePacket(dev *Device, buf []byte) (int, error) {
	if dev == nil || dev.Tun == nil {
		return 0, fmt.Errorf("tun not initialized")
	}
	// Linux wireguard/tun may require headroom for virtio headers when vnet is enabled.
	// Always provide a small offset-compatible buffer to keep behavior stable
	// across platforms and driver versions.
	frame := make([]byte, packetOffset+len(buf))
	copy(frame[packetOffset:], buf)
	bufs := [][]byte{frame}
	n, err := dev.Tun.Write(bufs, packetOffset)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(buf), nil
}
