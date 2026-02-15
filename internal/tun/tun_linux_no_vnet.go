//go:build linux

package tun

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const cloneDevicePath = "/dev/net/tun"
const ifReqSize = unix.IFNAMSIZ + 64

// simpleTun is a Linux TUN device created without IFF_VNET_HDR, so the kernel
// delivers one packet per read (no GSO/GRO) and "too many segments" never occurs.
type simpleTun struct {
	file   *os.File
	name   string
	mtu    int
	events chan wgtun.Event
	once   sync.Once
}

func (s *simpleTun) File() *os.File                                      { return s.file }
func (s *simpleTun) MTU() (int, error)                                   { return s.mtu, nil }
func (s *simpleTun) Name() (string, error)                               { return s.name, nil }
func (s *simpleTun) Events() <-chan wgtun.Event                          { return s.events }
func (s *simpleTun) BatchSize() int                                      { return 1 }
func (s *simpleTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	n, err := s.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
func (s *simpleTun) Write(bufs [][]byte, offset int) (int, error) {
	var total int
	for i := range bufs {
		n, err := s.file.Write(bufs[i][offset:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
func (s *simpleTun) Close() error {
	var err error
	s.once.Do(func() {
		close(s.events)
		err = s.file.Close()
	})
	return err
}

// createTUNNoVNet creates a TUN device with IFF_TUN|IFF_NO_PI only (no IFF_VNET_HDR).
// The kernel then delivers one packet per read and never uses GSO/GRO.
func createTUNNoVNet(name string, mtu int) (wgtun.Device, error) {
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTUN(%q): %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}
	// IFF_TUN | IFF_NO_PI only — no IFF_VNET_HDR, so no GSO/GRO
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	actualName := ifr.Name()
	file := os.NewFile(uintptr(nfd), cloneDevicePath)

	// Set MTU via ioctl (SIOCSIFMTU)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.O_CLOEXEC, 0)
	if err != nil {
		file.Close()
		return nil, err
	}
	ifrMTU, err := unix.NewIfreq(actualName)
	if err != nil {
		unix.Close(fd)
		file.Close()
		return nil, err
	}
	ifrMTU.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(int(fd), unix.SIOCSIFMTU, ifrMTU); err != nil {
		unix.Close(fd)
		file.Close()
		return nil, fmt.Errorf("set MTU: %w", err)
	}
	unix.Close(fd)

	events := make(chan wgtun.Event, 2)
	events <- wgtun.EventUp

	return &simpleTun{file: file, name: actualName, mtu: mtu, events: events}, nil
}

func init() {
	createTUNNoVNetFn = func(name string, mtu int) (wgtun.Device, error) {
		return createTUNNoVNet(name, mtu)
	}
}
