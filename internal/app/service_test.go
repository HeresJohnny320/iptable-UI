package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	fwpkg "github.com/HeresJohnny320/iptable-ui/internal/firewall"
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

type connectionFirewall struct {
	recordingFirewall
	closed        int
	disconnectErr error
	other         bool
	disconnected  []store.Rule
}

func (f *connectionFirewall) Disconnect(_ context.Context, rule store.Rule) (int, error) {
	f.disconnected = append(f.disconnected, rule)
	return f.closed, f.disconnectErr
}

func (f *connectionFirewall) OtherForwards(context.Context, uint16, string) (bool, error) {
	return f.other, nil
}

func TestDisableAndDeleteCloseConnections(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	firewall := &connectionFirewall{closed: 2}
	service := Service{Store: database, Firewall: firewall}
	ctx := context.Background()
	rule, err := service.Add(ctx, store.Rule{PublicPort: 25565, DestIP: "10.0.0.4", DestPort: 25565, Protocol: "udp"})
	if err != nil {
		t.Fatal(err)
	}

	notice, err := service.SetEnabled(ctx, rule.ID, false)
	if err != nil || notice != "Closed 2 open connection(s)" || len(firewall.disconnected) != 1 {
		t.Fatalf("disable: notice %q, err %v, disconnects %d", notice, err, len(firewall.disconnected))
	}
	if notice, err := service.SetEnabled(ctx, rule.ID, true); err != nil || notice != "" || len(firewall.disconnected) != 1 {
		t.Fatalf("enabling must not close connections: %q, %v", notice, err)
	}

	// Without conntrack, a disabled rule's DROP still cuts traffic, so no
	// hint is needed; a deleted rule has no DROP, so the user is told.
	firewall.disconnectErr = fmt.Errorf("wrapped: %w", fwpkg.ErrNoConntrack)
	if notice, _ := service.SetEnabled(ctx, rule.ID, false); notice != "" {
		t.Fatalf("disable without conntrack should not warn, got %q", notice)
	}
	firewall.other = true
	notice, err = service.Delete(ctx, rule.ID)
	if err != nil || !strings.Contains(notice, "install conntrack") || !strings.Contains(notice, "still forwards port 25565") {
		t.Fatalf("delete notice %q, err %v", notice, err)
	}
	if _, err := service.Delete(ctx, rule.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleting twice should report not found, got %v", err)
	}
}

func TestEditingForwardClosesOldConnections(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	firewall := &connectionFirewall{}
	service := Service{Store: database, Firewall: firewall}
	ctx := context.Background()
	rule, err := service.Add(ctx, store.Rule{Name: "a", PublicPort: 80, DestIP: "10.0.0.4", DestPort: 80, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	rule.Name = "renamed"
	if _, err := service.Update(ctx, rule); err != nil || len(firewall.disconnected) != 0 {
		t.Fatalf("renaming should keep connections: %v, %d", err, len(firewall.disconnected))
	}
	rule.DestIP = "10.0.0.5"
	if _, err := service.Update(ctx, rule); err != nil || len(firewall.disconnected) != 1 || firewall.disconnected[0].DestIP != "10.0.0.4" {
		t.Fatalf("moving the destination should close connections to the old one: %v, %+v", err, firewall.disconnected)
	}
}
