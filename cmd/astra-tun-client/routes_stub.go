//go:build !windows

package main

// SetInterfaceAddress is a no-op on non-Windows (address set by OS/tooling).
func SetInterfaceAddress(ifName, addrCIDR string) error {
	return nil
}

// AddRoute is a no-op on non-Windows (caller manages routes).
func AddRoute(ifName, prefix, nexthop string) error {
	return nil
}

// DeleteRoute is a no-op on non-Windows.
func DeleteRoute(ifName, prefix string) error {
	return nil
}

// RemoveAllRoutesForInterface is a no-op on non-Windows.
func RemoveAllRoutesForInterface(ifName string) error {
	return nil
}

// RemoveAddedRoutes is a no-op on non-Windows.
func RemoveAddedRoutes() {}
