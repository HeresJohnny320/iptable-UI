package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestRuleLifecycle(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	rule, err := store.Add(ctx, Rule{Name: "minecraft", PublicPort: 25565, DestIP: "10.0.0.2", DestPort: 25565, Protocol: "both"})
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Enabled || rule.ID == 0 {
		t.Fatalf("unexpected inserted rule: %+v", rule)
	}
	if err := store.SetEnabled(ctx, rule.ID, false); err != nil {
		t.Fatal(err)
	}
	rules, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Enabled {
		t.Fatalf("disabled rule did not persist: %+v", rules)
	}
	if err := store.Delete(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	rules, err = store.List(ctx)
	if err != nil || len(rules) != 0 {
		t.Fatalf("expected no remaining rules, got %d: %v", len(rules), err)
	}
}

func TestRejectsInvalidRule(t *testing.T) {
	err := validateRule(Rule{PublicPort: 0, DestIP: "bad", DestPort: 0, Protocol: "icmp"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestImportMissingIsIdempotentAndPreservesDatabaseState(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	existing, err := store.Add(ctx, Rule{Name: "database rule", PublicPort: 8080, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnabled(ctx, existing.ID, false); err != nil {
		t.Fatal(err)
	}
	discovered := []Rule{
		{PublicPort: 8080, DestIP: "10.0.0.99", DestPort: 99, Protocol: "tcp"},
		{PublicPort: 51820, DestIP: "10.0.0.3", DestPort: 51820, Protocol: "udp"},
	}
	imported, err := store.ImportMissing(ctx, discovered)
	if err != nil || imported != 1 {
		t.Fatalf("expected one imported rule, got %d: %v", imported, err)
	}
	imported, err = store.ImportMissing(ctx, discovered)
	if err != nil || imported != 0 {
		t.Fatalf("expected repeat import to be a no-op, got %d: %v", imported, err)
	}
	rules, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Enabled || rules[0].Name != "database rule" {
		t.Fatalf("import overwrote existing database state: %+v", rules)
	}
}

func TestKeepClientIPIsStoredAndOldDatabasesMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', public_port INTEGER NOT NULL, dest_ip TEXT NOT NULL, dest_port INTEGER NOT NULL, protocol TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(public_port, protocol));
		INSERT INTO rules(name, public_port, dest_ip, dest_port, protocol, enabled, created_at, updated_at) VALUES('old', 80, '10.0.0.2', 80, 'tcp', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	database, err := Open(path)
	if err != nil {
		t.Fatalf("an old database should migrate: %v", err)
	}
	defer database.Close()
	ctx := context.Background()
	added, err := database.Add(ctx, Rule{PublicPort: 25565, DestIP: "10.0.0.3", DestPort: 25565, Protocol: "both", KeepClientIP: true})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := database.List(ctx)
	if err != nil || len(rules) != 2 || rules[0].KeepClientIP || !rules[1].KeepClientIP {
		t.Fatalf("unexpected rules after migration: %+v, %v", rules, err)
	}
	added.KeepClientIP = false
	if updated, err := database.Update(ctx, added); err != nil || updated.KeepClientIP {
		t.Fatalf("update should clear keepClientIP: %+v, %v", updated, err)
	}
}

func TestRuleMatchesSearch(t *testing.T) {
	minecraft := Rule{ID: 3, Name: "Minecraft", PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "both", Enabled: true, KeepClientIP: true}
	web := Rule{ID: 12, Name: "Website", PublicPort: 8080, DestIP: "192.168.1.20", DestPort: 80, Protocol: "tcp"}
	tests := []struct {
		query          string
		minecraft, web bool
	}{
		{"", true, true},
		{"25565", true, false},
		{"MINE", true, false},
		{"10.66", true, false},
		{"192.168.1.20:80", false, true},
		{"#12", false, true},
		{":80", false, true},
		{"on", true, false},
		{"up", true, false},
		{"off", false, true},
		{"udp", true, false}, // "both" carries UDP
		{"tcp", true, true},
		{"real", true, false},
		{"masked", false, true},
		{"tcp off", false, true},
		{"udp off", false, false},
		{"website 8080", false, true},
		{"nothing-like-this", false, false},
	}
	for _, test := range tests {
		if got := minecraft.Matches(test.query); got != test.minecraft {
			t.Errorf("minecraft.Matches(%q) = %v", test.query, got)
		}
		if got := web.Matches(test.query); got != test.web {
			t.Errorf("web.Matches(%q) = %v", test.query, got)
		}
	}
}
