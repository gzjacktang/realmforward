package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db *sql.DB
}

type ForwardRule struct {
	ID        int64  `json:"id"`
	LocalPort int    `json:"local_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Enabled   bool   `json:"enabled"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
	Packets   uint64 `json:"packets,omitempty"`
	Bytes     uint64 `json:"bytes,omitempty"`
}

type AuditLog struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	Source string `json:"source"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "panel.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err = s.db.Exec(string(schema)); err != nil {
		return err
	}
	// probe whether proto=both is accepted; if not, rebuild table
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO forward_rules(local_port, dest_ip, dest_port, proto, enabled, note) VALUES(65534,'127.0.0.1',1,'both',0,'mig-probe')`)
	if err == nil {
		_, _ = tx.Exec(`DELETE FROM forward_rules WHERE local_port=65534 AND note='mig-probe'`)
		return tx.Commit()
	}
	_ = tx.Rollback()

	_, err = s.db.Exec(`
CREATE TABLE forward_rules_mig (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    proto TEXT NOT NULL CHECK (proto IN ('tcp', 'udp', 'both')),
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(local_port, proto)
);
INSERT INTO forward_rules_mig(id, local_port, dest_ip, dest_port, proto, enabled, note, created_at)
  SELECT id, local_port, dest_ip, dest_port, proto, enabled, note, created_at FROM forward_rules;
DROP TABLE forward_rules;
ALTER TABLE forward_rules_mig RENAME TO forward_rules;
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);
`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) EnsureAdmin(username, passwordHash string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO users(id, username, password_hash) VALUES(1, ?, ?)`, username, passwordHash)
	return err
}

func (s *Store) GetUser() (username, hash string, err error) {
	err = s.db.QueryRow(`SELECT username, password_hash FROM users WHERE id=1`).Scan(&username, &hash)
	return
}

func (s *Store) UpdateUser(username, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET username=?, password_hash=?, updated_at=datetime('now') WHERE id=1`, username, hash)
	return err
}

func (s *Store) UpdateUsername(username string) error {
	_, err := s.db.Exec(`UPDATE users SET username=?, updated_at=datetime('now') WHERE id=1`, username)
	return err
}

func (s *Store) UpdatePassword(hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=1`, hash)
	return err
}

func (s *Store) CreateSession(token string, ttl time.Duration) error {
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO sessions(token, expires_at) VALUES(?, ?)`, token, exp)
	return err
}

func (s *Store) ValidSession(token string) (bool, error) {
	var exp string
	err := s.db.QueryRow(`SELECT expires_at FROM sessions WHERE token=?`, token).Scan(&exp)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		return false, err
	}
	if time.Now().After(t) {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
		return false, nil
	}
	return true, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (s *Store) ListForwards() ([]ForwardRule, error) {
	rows, err := s.db.Query(`SELECT id, local_port, dest_ip, dest_port, proto, enabled, note, created_at FROM forward_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ForwardRule, 0)
	for rows.Next() {
		var r ForwardRule
		var en int
		if err := rows.Scan(&r.ID, &r.LocalPort, &r.DestIP, &r.DestPort, &r.Proto, &en, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetForward(id int64) (*ForwardRule, error) {
	var r ForwardRule
	var en int
	err := s.db.QueryRow(`SELECT id, local_port, dest_ip, dest_port, proto, enabled, note, created_at FROM forward_rules WHERE id=?`, id).
		Scan(&r.ID, &r.LocalPort, &r.DestIP, &r.DestPort, &r.Proto, &en, &r.Note, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.Enabled = en == 1
	return &r, nil
}

func (s *Store) AddForward(localPort int, destIP string, destPort int, proto, note string, enabled bool) (int64, error) {
	proto = strings.ToLower(proto)
	if proto == "tcp+udp" || proto == "all" {
		proto = "both"
	}
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.Exec(`INSERT INTO forward_rules(local_port, dest_ip, dest_port, proto, enabled, note) VALUES(?,?,?,?,?,?)`,
		localPort, destIP, destPort, proto, en, note)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateForward(id int64, localPort int, destIP string, destPort int, proto, note string) error {
	proto = strings.ToLower(proto)
	if proto == "tcp+udp" || proto == "all" {
		proto = "both"
	}
	_, err := s.db.Exec(`UPDATE forward_rules SET local_port=?, dest_ip=?, dest_port=?, proto=?, note=? WHERE id=?`,
		localPort, destIP, destPort, proto, note, id)
	return err
}

func (s *Store) UpdateForwardEnabled(id int64, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`UPDATE forward_rules SET enabled=? WHERE id=?`, en, id)
	return err
}

func (s *Store) DeleteForward(id int64) error {
	_, err := s.db.Exec(`DELETE FROM forward_rules WHERE id=?`, id)
	return err
}

func (s *Store) AddAudit(source, actor, action, result, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit_logs(source, actor, action, result, detail) VALUES(?,?,?,?,?)`,
		source, actor, action, result, detail)
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, ts, source, actor, action, result, detail FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditLog, 0)
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.TS, &a.Source, &a.Actor, &a.Action, &a.Result, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}
