package xdp

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
	Mode      string `json:"mode"` // native|generic|""
	Iface     string `json:"iface"`
	Error     string `json:"error,omitempty"`
	SNATMin   uint16 `json:"snat_min"`
	SNATMax   uint16 `json:"snat_max"`
	CsumMode  uint8  `json:"csum_mode"` // 0=safe, 1=fast
	RuleCount int    `json:"rule_count"`
}

func ProtoNumber(p string) (uint8, error) {
	switch p {
	case "tcp", "TCP":
		return 6, nil
	case "udp", "UDP":
		return 17, nil
	default:
		return 0, fmt.Errorf("unsupported proto %q", p)
	}
}

// ExpandProtos returns BPF protocol numbers for tcp/udp/both.
func ExpandProtos(p string) ([]uint8, error) {
	switch p {
	case "tcp", "TCP":
		return []uint8{6}, nil
	case "udp", "UDP":
		return []uint8{17}, nil
	case "both", "tcp+udp", "TCP+UDP":
		return []uint8{6, 17}, nil
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
