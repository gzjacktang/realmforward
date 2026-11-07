package fwd

import "fmt"

type Rule struct {
	ID        uint32
	LocalPort uint16
	DestIP    string
	DestPort  uint16
	Proto     string // tcp|udp|both
	Enabled   bool
}

type Stats struct {
	Packets uint64
	Bytes   uint64
}

type Status struct {
	Loaded    bool   `json:"loaded"`
	Mode      string `json:"mode"` // nftables
	Iface     string `json:"iface"`
	Error     string `json:"error,omitempty"`
	RuleCount int    `json:"rule_count"`
}

func ExpandProtoNames(p string) ([]string, error) {
	switch p {
	case "tcp", "TCP":
		return []string{"tcp"}, nil
	case "udp", "UDP":
		return []string{"udp"}, nil
	case "both", "tcp+udp", "TCP+UDP":
		return []string{"tcp", "udp"}, nil
	default:
		return nil, fmt.Errorf("unsupported proto %q (use tcp/udp/both)", p)
	}
}

func NormalizeProto(p string) (string, error) {
	switch p {
	case "tcp", "TCP":
		return "tcp", nil
	case "udp", "UDP":
		return "udp", nil
	case "both", "tcp+udp", "TCP+UDP", "all":
		return "both", nil
	default:
		return "", fmt.Errorf("unsupported proto %q", p)
	}
}
