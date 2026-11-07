package auth

import (
	"path/filepath"
	"testing"

	"github.com/gzjacktang/nftforward/internal/store"
)

func TestLoginRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc := New(st)
	created, plain, err := svc.EnsureFreshInstall("admin")
	if err != nil || !created || plain == "" {
		t.Fatalf("bootstrap: created=%v plain=%q err=%v", created, plain, err)
	}
	tok, err := svc.Login("admin", plain)
	if err != nil || tok == "" {
		t.Fatalf("login: %v", err)
	}
	if !svc.Valid(tok) {
		t.Fatal("token invalid")
	}
	created2, _, err := svc.EnsureFreshInstall("admin")
	if err != nil || created2 {
		t.Fatalf("second bootstrap should no-op: %v %v", created2, err)
	}
}
