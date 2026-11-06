//go:build linux

package xdp

import (
	"net"
	"os/exec"
	"strings"
)

func parseVia(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func neighMAC(iface, via string) ([6]byte, bool) {
	var gw [6]byte
	args := []string{"neigh", "show", "dev", iface}
	if via != "" {
		args = []string{"neigh", "show", via, "dev", iface}
	}
	nout, _ := exec.Command("ip", args...).CombinedOutput()
	prefer := func(line string) bool {
		return strings.Contains(line, "PERMANENT") || strings.Contains(line, "REACHABLE") || strings.Contains(line, "DELAY") || strings.Contains(line, "STALE")
	}
	var fallback [6]byte
	var hasFallback bool
	for _, line := range strings.Split(string(nout), "\n") {
		if !strings.Contains(line, "lladdr") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "lladdr" && i+1 < len(fields) {
				mac, err := net.ParseMAC(fields[i+1])
				if err != nil || len(mac) < 6 {
					continue
				}
				if prefer(line) {
					copy(gw[:], mac[:6])
					return gw, true
				}
				if !hasFallback {
					copy(fallback[:], mac[:6])
					hasFallback = true
				}
			}
		}
	}
	if hasFallback {
		return fallback, true
	}
	return gw, false
}

func resolveEgressMACs(iface string) (gw, local [6]byte, ok bool) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) < 6 {
		return gw, local, false
	}
	copy(local[:], ifi.HardwareAddr[:6])

	via := ""
	if out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput(); err == nil {
		via = parseVia(string(out))
	}
	if via == "" {
		// route get often reveals via even for onlink / policy routes
		if out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").CombinedOutput(); err == nil {
			via = parseVia(string(out))
		}
	}

	if via != "" {
		if mac, ok := neighMAC(iface, via); ok {
			return mac, local, true
		}
		_, _ = exec.Command("ping", "-c", "1", "-W", "1", via).CombinedOutput()
		if mac, ok := neighMAC(iface, via); ok {
			return mac, local, true
		}
	}
	// last resort: any usable neigh on iface (common onlink VPS gateways)
	if mac, ok := neighMAC(iface, ""); ok {
		return mac, local, true
	}
	return gw, local, false
}
