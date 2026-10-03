package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("rule not found")

type Rule struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	PublicPort uint16 `json:"publicPort"`
	DestIP     string `json:"destIP"`
	DestPort   uint16 `json:"destPort"`
	Protocol   string `json:"protocol"`
	Enabled    bool   `json:"enabled"`
	// KeepClientIP skips MASQUERADE so the destination sees the real client
	// address. Replies must then route back through the tunnel.
	KeepClientIP bool      `json:"keepClientIP"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure database: %w", err)
	}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT '',
			public_port INTEGER NOT NULL CHECK(public_port BETWEEN 1 AND 65535),
			dest_ip TEXT NOT NULL,
			dest_port INTEGER NOT NULL CHECK(dest_port BETWEEN 1 AND 65535),
			protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp', 'both')),
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(public_port, protocol)
		);
	`)
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	columns, err := s.db.Query(`SELECT name FROM pragma_table_info('rules')`)
	if err != nil {
		return fmt.Errorf("read database columns: %w", err)
	}
	defer columns.Close()
	hasKeepClientIP := false
	for columns.Next() {
		var name string
		if err := columns.Scan(&name); err != nil {
			return fmt.Errorf("read database columns: %w", err)
		}
		hasKeepClientIP = hasKeepClientIP || name == "keep_client_ip"
	}
	if err := columns.Err(); err != nil {
		return fmt.Errorf("read database columns: %w", err)
	}
	columns.Close()
	if !hasKeepClientIP {
		if _, err := s.db.Exec(`ALTER TABLE rules ADD COLUMN keep_client_ip INTEGER NOT NULL DEFAULT 0 CHECK(keep_client_ip IN (0, 1))`); err != nil {
			return fmt.Errorf("migrate database: %w", err)
		}
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, public_port, dest_ip, dest_port, protocol, enabled, keep_client_ip, created_at, updated_at FROM rules ORDER BY public_port, protocol, id`)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()
	rules := make([]Rule, 0)
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	return rules, nil
}

func (s *Store) Add(ctx context.Context, rule Rule) (Rule, error) {
	if err := validateRule(rule); err != nil {
		return Rule{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `INSERT INTO rules(name, public_port, dest_ip, dest_port, protocol, enabled, keep_client_ip, created_at, updated_at) VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?)`, rule.Name, rule.PublicPort, rule.DestIP, rule.DestPort, rule.Protocol, rule.KeepClientIP, now, now)
	if err != nil {
		return Rule{}, fmt.Errorf("add rule: %w", err)
	}
	rule.ID, err = result.LastInsertId()
	if err != nil {
		return Rule{}, fmt.Errorf("read new rule id: %w", err)
	}
	rule.Enabled = true
	rule.CreatedAt, _ = time.Parse(time.RFC3339Nano, now)
	rule.UpdatedAt = rule.CreatedAt
	return rule, nil
}

func (s *Store) Update(ctx context.Context, rule Rule) (Rule, error) {
	if err := validateRule(rule); err != nil {
		return Rule{}, err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE rules SET name = ?, public_port = ?, dest_ip = ?, dest_port = ?, protocol = ?, keep_client_ip = ?, updated_at = ? WHERE id = ?`, rule.Name, rule.PublicPort, rule.DestIP, rule.DestPort, rule.Protocol, rule.KeepClientIP, time.Now().UTC().Format(time.RFC3339Nano), rule.ID)
	if err != nil {
		return Rule{}, fmt.Errorf("update rule: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Rule{}, fmt.Errorf("check updated rule: %w", err)
	}
	if count == 0 {
		return Rule{}, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, public_port, dest_ip, dest_port, protocol, enabled, keep_client_ip, created_at, updated_at FROM rules WHERE id = ?`, rule.ID)
	if err != nil {
		return Rule{}, fmt.Errorf("read updated rule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return Rule{}, ErrNotFound
	}
	updated, err := scanRule(rows)
	if err != nil {
		return Rule{}, err
	}
	return updated, nil
}

func (s *Store) ImportMissing(ctx context.Context, rules []Rule) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin rule import: %w", err)
	}
	defer tx.Rollback()

	existingRows, err := tx.QueryContext(ctx, `SELECT public_port, protocol FROM rules`)
	if err != nil {
		return 0, fmt.Errorf("read existing rules: %w", err)
	}
	type ruleKey struct {
		port     uint16
		protocol string
	}
	existing := make(map[ruleKey]bool)
	for existingRows.Next() {
		var port uint16
		var protocol string
		if err := existingRows.Scan(&port, &protocol); err != nil {
			existingRows.Close()
			return 0, fmt.Errorf("scan existing rule key: %w", err)
		}
		existing[ruleKey{port: port, protocol: protocol}] = true
	}
	if err := existingRows.Close(); err != nil {
		return 0, fmt.Errorf("close existing rules: %w", err)
	}
	if err := existingRows.Err(); err != nil {
		return 0, fmt.Errorf("read existing rule keys: %w", err)
	}

	imported := 0
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return 0, fmt.Errorf("invalid discovered rule: %w", err)
		}
		key := ruleKey{port: rule.PublicPort, protocol: rule.Protocol}
		if existing[key] {
			continue
		}
		if rule.Protocol == "both" && (existing[ruleKey{rule.PublicPort, "tcp"}] || existing[ruleKey{rule.PublicPort, "udp"}]) {
			continue
		}
		if rule.Protocol != "both" && existing[ruleKey{rule.PublicPort, "both"}] {
			continue
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		name := rule.Name
		if name == "" {
			name = "Imported from iptables"
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO rules(name, public_port, dest_ip, dest_port, protocol, enabled, created_at, updated_at) VALUES(?, ?, ?, ?, ?, 1, ?, ?)`, name, rule.PublicPort, rule.DestIP, rule.DestPort, rule.Protocol, now, now)
		if err != nil {
			return 0, fmt.Errorf("import rule on public port %d: %w", rule.PublicPort, err)
		}
		rule.ID, err = result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("read imported rule id: %w", err)
		}
		existing[key] = true
		imported++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit imported rules: %w", err)
	}
	return imported, nil
}

func (s *Store) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?`, enabled, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("update rule: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check updated rule: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check deleted rule: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanRule(row rowScanner) (Rule, error) {
	var rule Rule
	var enabled, keepClientIP int
	var createdAt, updatedAt string
	if err := row.Scan(&rule.ID, &rule.Name, &rule.PublicPort, &rule.DestIP, &rule.DestPort, &rule.Protocol, &enabled, &keepClientIP, &createdAt, &updatedAt); err != nil {
		return Rule{}, fmt.Errorf("scan rule: %w", err)
	}
	rule.Enabled = enabled == 1
	rule.KeepClientIP = keepClientIP == 1
	rule.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rule.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return rule, nil
}

func validateRule(rule Rule) error {
	if rule.PublicPort == 0 || rule.DestPort == 0 {
		return errors.New("ports must be between 1 and 65535")
	}
	address, err := netip.ParseAddr(rule.DestIP)
	if err != nil || !address.Is4() {
		return errors.New("destination must be a valid IPv4 address")
	}
	switch rule.Protocol {
	case "tcp", "udp", "both":
		return nil
	default:
		return errors.New("protocol must be tcp, udp, or both")
	}
}

// Matches reports whether the rule matches every word of a search query.
// A word can be part of the name, a port, the destination address or the
// #ID, or one of the keywords on/up/enabled, off/down/disabled, tcp, udp,
// real or masked. The web UI's search mirrors these rules.
func (r Rule) Matches(query string) bool {
	text := strings.ToLower(fmt.Sprintf("#%d %s :%d %s:%d %s", r.ID, r.Name, r.PublicPort, r.DestIP, r.DestPort, r.Protocol))
	for _, word := range strings.Fields(strings.ToLower(query)) {
		var ok bool
		switch word {
		case "on", "up", "enabled":
			ok = r.Enabled
		case "off", "down", "disabled":
			ok = !r.Enabled
		case "tcp", "udp":
			ok = r.Protocol == word || r.Protocol == "both"
		case "real":
			ok = r.KeepClientIP
		case "masked":
			ok = !r.KeepClientIP
		default:
			ok = strings.Contains(text, word)
		}
		if !ok {
			return false
		}
	}
	return true
}
