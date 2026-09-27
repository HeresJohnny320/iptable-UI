package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

type recordingFirewall struct {
	callCount int
	lastRules []store.Rule
}

func (f *recordingFirewall) Reconcile(_ context.Context, rules []store.Rule) error {
	f.callCount++
	f.lastRules = append([]store.Rule(nil), rules...)
	return nil
}

func TestAddRejectsOverlappingProtocol(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := Service{Store: database, Firewall: &recordingFirewall{}}
	ctx := context.Background()
	_, err = service.Add(ctx, store.Rule{PublicPort: 8080, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Add(ctx, store.Rule{PublicPort: 8080, DestIP: "10.0.0.3", DestPort: 80, Protocol: "both"})
	if err == nil {
		t.Fatal("expected overlapping protocol to be rejected")
	}
	rules, err := database.List(ctx)
	if err != nil || len(rules) != 1 {
		t.Fatalf("conflicting rule should not be persisted, got %d rules: %v", len(rules), err)
	}
}

func TestAddReconcilesEnabledRule(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	firewall := &recordingFirewall{}
	service := Service{Store: database, Firewall: firewall}
	_, err = service.Add(context.Background(), store.Rule{PublicPort: 25565, DestIP: "10.0.0.4", DestPort: 25565, Protocol: "both"})
	if err != nil {
		t.Fatal(err)
	}
	if firewall.callCount != 1 || len(firewall.lastRules) != 1 || !firewall.lastRules[0].Enabled {
		t.Fatalf("enabled rule was not reconciled: %+v", firewall)
	}
}

func TestUpdateRuleChangesDestinationAndReconciles(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	firewall := &recordingFirewall{}
	service := Service{Store: database, Firewall: firewall}
	rule, err := service.Add(context.Background(), store.Rule{Name: "old", PublicPort: 25565, DestIP: "10.0.0.4", DestPort: 25565, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	rule.Name = "renamed"
	rule.DestIP = "10.0.0.9"
	rule.DestPort = 25566
	updated, err := service.Update(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed" || updated.DestIP != "10.0.0.9" || updated.DestPort != 25566 || !updated.Enabled {
		t.Fatalf("unexpected updated rule: %+v", updated)
	}
	if firewall.callCount != 2 || firewall.lastRules[0].DestIP != "10.0.0.9" {
		t.Fatalf("updated rule was not reconciled: %+v", firewall)
	}
}

func TestUpdateRejectsConflictingPort(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := Service{Store: database, Firewall: &recordingFirewall{}}
	first, err := service.Add(context.Background(), store.Rule{PublicPort: 8080, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Add(context.Background(), store.Rule{PublicPort: 8081, DestIP: "10.0.0.3", DestPort: 81, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	second.PublicPort = first.PublicPort
	if _, err := service.Update(context.Background(), second); err == nil {
		t.Fatal("expected port conflict to be rejected")
	}
}
