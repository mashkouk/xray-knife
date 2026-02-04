package utils

import (
	"fmt"
	"net"
)

// incrementIP increments an IP address by 1 (IPv4 or IPv6)
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// IPOrCIDRToList converts a single IP or CIDR to a list of IP strings
func IPOrCIDRToList(input string) ([]string, error) {
	// Case 1: CIDR
	if ip, ipNet, err := net.ParseCIDR(input); err == nil {
		var ips []string
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			ips = append(ips, ip.String())
		}
		return ips, nil
	}

	// Case 2: Single IP
	if ip := net.ParseIP(input); ip != nil {
		return []string{ip.String()}, nil
	}

	return nil, fmt.Errorf("invalid IP or CIDR: %s", input)
}

// Backward compatibility
func CIDRtoListIP(cidr string) ([]string, error) {
	return IPOrCIDRToList(cidr)
}

// IsIPv6 checks whether the given string is a valid IPv6 address
func IsIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil
}
