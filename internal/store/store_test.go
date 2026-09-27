package store

import (
	"context"
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
