package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

type Device struct {
	Tun  tun.Device
	Name string
	MTU  int
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
	return &Device{Tun: dev, Name: name, MTU: mtu}, nil
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
	bufs := [][]byte{buf}
	n, err := dev.Tun.Write(bufs, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(buf), nil
}
