package listen

import (
	"os/exec"
	"strconv"
	"strings"
)

type Entry struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process"`
}

// Snapshot parses `ss -lntup` best-effort.
func Snapshot() []Entry {
	out, err := exec.Command("ss", "-lntup").CombinedOutput()
	if err != nil {
		return nil
	}
	var entries []Entry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		local := fields[4]
		port := parsePort(local)
		if port == 0 {
			continue
		}
		proc := ""
		if idx := strings.Index(line, `users:(("`); idx >= 0 {
			rest := line[idx+len(`users:(("`):]
			if end := strings.Index(rest, `"`); end > 0 {
				proc = rest[:end]
			}
		}
		entries = append(entries, Entry{Port: port, Proto: proto, Process: proc})
	}
	return entries
}

func Find(port int, proto string) *Entry {
	proto = strings.ToLower(proto)
	for _, e := range Snapshot() {
		if e.Port == port && e.Proto == proto {
			return &e
		}
	}
	return nil
}

func parsePort(local string) int {
	// formats: 0.0.0.0:80  [::]:80  *:80
	if i := strings.LastIndex(local, ":"); i >= 0 {
		p, _ := strconv.Atoi(local[i+1:])
		return p
	}
	return 0
}
