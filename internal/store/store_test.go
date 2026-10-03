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

func TestSettingsBackupAndReplaceAll(t *testing.T) {
	directory := t.TempDir()
	database, err := Open(filepath.Join(directory, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if value, err := database.Setting(ctx, "theme"); err != nil || value != "" {
		t.Fatalf("unset setting should be empty: %q, %v", value, err)
	}
	if err := database.SetSetting(ctx, "theme", "ocean"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSetting(ctx, "theme", "midnight"); err != nil {
		t.Fatal(err)
	}
	original, err := database.Add(ctx, Rule{Name: "keep", PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}

	snapshot := filepath.Join(directory, "snapshot.db")
	if err := database.Backup(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Add(ctx, Rule{PublicPort: 443, DestIP: "10.0.0.3", DestPort: 443, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSetting(ctx, "theme", "light"); err != nil {
		t.Fatal(err)
	}

	backup, err := Open(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := backup.List(ctx)
	settings, _ := backup.Settings(ctx)
	backup.Close()
	if len(rules) != 1 || settings["theme"] != "midnight" {
		t.Fatalf("snapshot should hold the earlier state: %+v %v", rules, settings)
	}

	if err := database.ReplaceAll(ctx, rules, settings); err != nil {
		t.Fatal(err)
	}
	restored, _ := database.List(ctx)
	theme, _ := database.Setting(ctx, "theme")
	if len(restored) != 1 || restored[0].ID != original.ID || restored[0].Name != "keep" || !restored[0].CreatedAt.Equal(original.CreatedAt) || theme != "midnight" {
		t.Fatalf("restore should bring back the snapshot exactly: %+v theme=%q", restored, theme)
	}
	if err := database.ReplaceAll(ctx, []Rule{{ID: 9, PublicPort: 0, DestIP: "x", Protocol: "tcp"}}, nil); err == nil {
		t.Fatal("an invalid rule in a backup must be rejected")
	}
	if after, _ := database.List(ctx); len(after) != 1 {
		t.Fatal("a rejected restore must leave the database unchanged")
	}
}

func TestDeleteAll(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	for _, port := range []uint16{80, 443} {
		if _, err := database.Add(ctx, Rule{PublicPort: port, DestIP: "10.0.0.2", DestPort: port, Protocol: "tcp"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = database.SetSetting(ctx, "web.theme", "ocean")
	removed, err := database.DeleteAll(ctx)
	if err != nil || len(removed) != 2 {
		t.Fatalf("removed %d, err %v", len(removed), err)
	}
	if rules, _ := database.List(ctx); len(rules) != 0 {
		t.Fatalf("rules left: %+v", rules)
	}
	if theme, _ := database.Setting(ctx, "web.theme"); theme != "ocean" {
		t.Fatal("removing rules must keep settings")
	}
}

func TestCombineProtocols(t *testing.T) {
	rules := CombineProtocols([]Rule{
		{PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "tcp", Name: importedName},
		{PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "udp", Name: "Minecraft"},
		{PublicPort: 8080, DestIP: "10.66.0.3", DestPort: 80, Protocol: "tcp"},
		{PublicPort: 53, DestIP: "10.66.0.4", DestPort: 53, Protocol: "udp"},
		{PublicPort: 53, DestIP: "10.66.0.5", DestPort: 53, Protocol: "tcp"}, // different destination
	})
	if len(rules) != 4 || rules[0].Protocol != "both" || rules[0].Name != "Minecraft" {
		t.Fatalf("expected the 25565 pair combined and named, got %+v", rules)
	}
	for _, rule := range rules[1:] {
		if rule.Protocol == "both" {
			t.Fatalf("only matching pairs may be combined: %+v", rules)
		}
	}
}

func TestMergeProtocolPairs(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	add := func(rule Rule) Rule {
		added, err := database.Add(ctx, rule)
		if err != nil {
			t.Fatal(err)
		}
		return added
	}
	tcp := add(Rule{Name: importedName, PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "tcp"})
	add(Rule{Name: "Minecraft", PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "udp"})
	add(Rule{PublicPort: 8080, DestIP: "10.66.0.3", DestPort: 80, Protocol: "tcp"})
	differs := add(Rule{PublicPort: 53, DestIP: "10.66.0.4", DestPort: 53, Protocol: "tcp"})
	add(Rule{PublicPort: 53, DestIP: "10.66.0.4", DestPort: 53, Protocol: "udp"})
	if err := database.SetEnabled(ctx, differs.ID, false); err != nil {
		t.Fatal(err)
	}
	merged, err := database.MergeProtocolPairs(ctx)
	if err != nil || merged != 1 {
		t.Fatalf("merged %d, err %v", merged, err)
	}
	rules, _ := database.List(ctx)
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules left, got %+v", rules)
	}
	for _, rule := range rules {
		if rule.PublicPort == 25565 && (rule.ID != tcp.ID || rule.Protocol != "both" || rule.Name != "Minecraft") {
			t.Fatalf("pair should become one 'both' rule with the older ID and the real name: %+v", rule)
		}
	}
	if again, _ := database.MergeProtocolPairs(ctx); again != 0 {
		t.Fatal("merging twice must change nothing")
	}
}
