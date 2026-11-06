package firewall

import "testing"

func TestCsvHasPort(t *testing.T) {
	if !csvHasPort("80, 443, 14444", 14444) {
		t.Fatal("expected 14444 in set")
	}
	if csvHasPort("80, 443", 14444) {
		t.Fatal("did not expect 14444")
	}
}

func TestPortsExcept(t *testing.T) {
	got := portsExcept("22, 80, 14444", 14444)
	if len(got) != 2 || got[0] != 22 || got[1] != 80 {
		t.Fatalf("closing 14444 from {22,80,14444}: got %#v want [22 80]", got)
	}
	got = portsExcept("14444", 14444)
	if len(got) != 0 {
		t.Fatalf("sole port: got %#v want empty", got)
	}
	got = portsExcept("80, 443", 14444)
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("exclude absent: got %#v", got)
	}
	// set line sample used by closeNft
	m2 := reNftSet.FindStringSubmatch("meta l4proto tcp tcp dport { 22, 80, 14444 } accept # handle 12")
	if m2 == nil {
		t.Fatal("set parse failed")
	}
	got = portsExcept(m2[2], 14444)
	if len(got) != 2 || got[0] != 22 || got[1] != 80 {
		t.Fatalf("from set match: got %#v", got)
	}
}

func TestReNftDport(t *testing.T) {
	m := reNftDport.FindStringSubmatch("tcp dport 22282 accept comment \"ssh\"")
	if m == nil || m[1] != "tcp" || m[2] != "22282" {
		t.Fatalf("dport parse failed: %#v", m)
	}
	m2 := reNftSet.FindStringSubmatch("meta l4proto tcp tcp dport { 80, 443, 8443 } accept")
	if m2 == nil || m2[1] != "tcp" {
		t.Fatalf("set parse failed: %#v", m2)
	}
	if !csvHasPort(m2[2], 8443) {
		t.Fatal("8443 should be in set")
	}
}

func TestDiscoverNftInputSample(t *testing.T) {
	// Ensure regexes see a typical Debian inet filter input header line.
	window := `chain input { type filter hook input priority filter; policy drop;`
	if !reNftHook.MatchString(window) {
		t.Fatal("hook input not matched")
	}
}
