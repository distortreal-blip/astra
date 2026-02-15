//go:build windows

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// addedRoutes holds routes we added so we can remove them on shutdown (LIFO).
var addedRoutesMu sync.Mutex
var addedRoutes []routeEntry

type routeEntry struct {
	ifName string
	prefix string // e.g. "0.0.0.0/0"
}

// SetInterfaceAddress sets the IPv4 address and mask on the interface (e.g. 10.10.0.2/24).
func SetInterfaceAddress(ifName, addrCIDR string) error {
	addr, mask, err := parseCIDR(addrCIDR)
	if err != nil {
		return err
	}
	// netsh interface ip set address name="Astra" source=static address=10.10.0.2 mask=255.255.255.0
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+quote(ifName), "source=static", "address="+addr, "mask="+mask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// AddRoute adds a route via the interface (non-persistent). prefix like "0.0.0.0/0", nexthop like "10.10.0.1".
// Uses metric=1 so Windows prefers this route over the physical adapter's default (otherwise "no internet" / local IP).
func AddRoute(ifName, prefix, nexthop string) error {
	// netsh interface ip add route prefix=0.0.0.0/0 nexthop=10.10.0.1 interface="Astra" metric=1
	out, err := exec.Command("netsh", "interface", "ip", "add", "route",
		"prefix="+prefix, "nexthop="+nexthop, "interface="+quote(ifName), "metric=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add route %s: %w: %s", prefix, err, bytes.TrimSpace(out))
	}
	addedRoutesMu.Lock()
	addedRoutes = append(addedRoutes, routeEntry{ifName: ifName, prefix: prefix})
	addedRoutesMu.Unlock()
	return nil
}

// DeleteRoute deletes one route by prefix and interface.
func DeleteRoute(ifName, prefix string) error {
	out, err := exec.Command("netsh", "interface", "ip", "delete", "route",
		"prefix="+prefix, "interface="+quote(ifName)).CombinedOutput()
	if err != nil {
		// Route might already be gone
		return fmt.Errorf("netsh delete route %s: %w: %s", prefix, err, bytes.TrimSpace(out))
	}
	return nil
}

// RemoveAllRoutesForInterface removes all routes that use this interface (e.g. after a crash).
func RemoveAllRoutesForInterface(ifName string) error {
	// netsh interface ip show route interface="Astra"
	out, err := exec.Command("netsh", "interface", "ip", "show", "route", "interface="+quote(ifName)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh show route: %w: %s", err, bytes.TrimSpace(out))
	}
	// Parse lines like "0.0.0.0/0 ..." and delete each
	prefixRe := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+/\d+)`)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var prefixes []string
	for scanner.Scan() {
		line := scanner.Text()
		if m := prefixRe.FindStringSubmatch(line); len(m) > 1 {
			prefixes = append(prefixes, m[1])
		}
	}
	for _, p := range prefixes {
		_ = DeleteRoute(ifName, p)
	}
	return nil
}

// RemoveAddedRoutes removes all routes we added (call on shutdown).
func RemoveAddedRoutes() {
	addedRoutesMu.Lock()
	list := make([]routeEntry, len(addedRoutes))
	copy(list, addedRoutes)
	addedRoutes = nil
	addedRoutesMu.Unlock()
	// Remove in reverse order
	for i := len(list) - 1; i >= 0; i-- {
		_ = DeleteRoute(list[i].ifName, list[i].prefix)
	}
}

func quote(s string) string {
	if strings.Contains(s, " ") {
		return `"` + s + `"`
	}
	return s
}

func parseCIDR(cidr string) (addr, mask string, err error) {
	// e.g. "10.10.0.2/24" -> "10.10.0.2", "255.255.255.0"
	idx := strings.Index(cidr, "/")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid CIDR: %s", cidr)
	}
	addr = strings.TrimSpace(cidr[:idx])
	maskLen := strings.TrimSpace(cidr[idx+1:])
	switch maskLen {
	case "24":
		mask = "255.255.255.0"
	case "16":
		mask = "255.255.0.0"
	case "8":
		mask = "255.0.0.0"
	case "32":
		mask = "255.255.255.255"
	case "0":
		mask = "0.0.0.0"
	default:
		return "", "", fmt.Errorf("unsupported mask /%s", maskLen)
	}
	return addr, mask, nil
}
