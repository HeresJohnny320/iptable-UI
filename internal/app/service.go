package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

type RuleStore interface {
	List(context.Context) ([]store.Rule, error)
	Add(context.Context, store.Rule) (store.Rule, error)
	Update(context.Context, store.Rule) (store.Rule, error)
	SetEnabled(context.Context, int64, bool) error
	Delete(context.Context, int64) error
	DeleteAll(context.Context) ([]store.Rule, error)
}

type Firewall interface {
	Reconcile(context.Context, []store.Rule) error
}

// ConnectionControl is implemented by firewalls that can close a forward's
// open connections and spot forwards made by other tools.
type ConnectionControl interface {
	Disconnect(context.Context, store.Rule) (int, error)
	OtherForwards(context.Context, uint16, string) (bool, error)
}

type Service struct {
	Store    RuleStore
	Firewall Firewall
	// BeforeDeleteAll runs before every rule is removed, to take a backup.
	// If it fails, nothing is removed.
	BeforeDeleteAll func(context.Context) error
}

func (s Service) List(ctx context.Context) ([]store.Rule, error) {
	return s.Store.List(ctx)
}

func (s Service) Add(ctx context.Context, rule store.Rule) (store.Rule, error) {
	existing, err := s.Store.List(ctx)
	if err != nil {
		return store.Rule{}, err
	}
	for _, current := range existing {
		if current.PublicPort == rule.PublicPort && protocolsOverlap(current.Protocol, rule.Protocol) {
			return store.Rule{}, fmt.Errorf("public port %d conflicts with rule %d (%s)", rule.PublicPort, current.ID, current.Protocol)
		}
	}
	added, err := s.Store.Add(ctx, rule)
	if err != nil {
		return store.Rule{}, err
	}
	if added.Enabled {
		if err := s.Reconcile(ctx); err != nil {
			return added, fmt.Errorf("rule saved but firewall apply failed: %w", err)
		}
	}
	return added, nil
}

func (s Service) Update(ctx context.Context, rule store.Rule) (store.Rule, error) {
	existing, err := s.Store.List(ctx)
	if err != nil {
		return store.Rule{}, err
	}
	found := false
	for _, current := range existing {
		if current.ID == rule.ID {
			found = true
			continue
		}
		if current.PublicPort == rule.PublicPort && protocolsOverlap(current.Protocol, rule.Protocol) {
			return store.Rule{}, fmt.Errorf("public port %d conflicts with rule %d (%s)", rule.PublicPort, current.ID, current.Protocol)
		}
	}
	if !found {
		return store.Rule{}, store.ErrNotFound
	}
	previous, _ := find(existing, rule.ID)
	updated, err := s.Store.Update(ctx, rule)
	if err != nil {
		return store.Rule{}, err
	}
	if err := s.Reconcile(ctx); err != nil {
		return updated, fmt.Errorf("rule saved but firewall apply failed: %w", err)
	}
	if previous.Enabled && !sameForward(previous, updated) {
		// Open connections still follow the old mapping until closed.
		if control, ok := s.Firewall.(ConnectionControl); ok {
			_, _ = control.Disconnect(ctx, previous)
		}
	}
	return updated, nil
}

// SetEnabled turns a rule on or off. The returned notice, when not empty,
// tells the user something they should know about the change.
func (s Service) SetEnabled(ctx context.Context, id int64, enabled bool) (string, error) {
	existing, err := s.Store.List(ctx)
	if err != nil {
		return "", err
	}
	rule, found := find(existing, id)
	if !found {
		return "", store.ErrNotFound
	}
	if err := s.Store.SetEnabled(ctx, id, enabled); err != nil {
		return "", err
	}
	if err := s.Reconcile(ctx); err != nil {
		return "", fmt.Errorf("rule state saved but firewall apply failed: %w", err)
	}
	if enabled {
		return "", nil
	}
	// A disabled rule DROPs its open connections, so conntrack is optional here.
	return s.closeConnections(ctx, rule, false), nil
}

// Delete removes a rule. The returned notice works like SetEnabled's.
func (s Service) Delete(ctx context.Context, id int64) (string, error) {
	existing, err := s.Store.List(ctx)
	if err != nil {
		return "", err
	}
	rule, found := find(existing, id)
	if !found {
		return "", store.ErrNotFound
	}
	if err := s.Store.Delete(ctx, id); err != nil {
		return "", err
	}
	if err := s.Reconcile(ctx); err != nil {
		return "", fmt.Errorf("rule deleted from database but firewall apply failed: %w", err)
	}
	return s.closeConnections(ctx, rule, true), nil
}

// LiveInspector is implemented by firewalls that can show their live rules.
type LiveInspector interface {
	LiveRules(context.Context) (string, error)
}

// LiveRules returns the forwards as the kernel has them right now.
func (s Service) LiveRules(ctx context.Context) (string, error) {
	inspector, ok := s.Firewall.(LiveInspector)
	if !ok {
		return "", errors.New("live firewall rules are unavailable")
	}
	return inspector.LiveRules(ctx)
}

// DeleteAll removes every rule, applies the empty rule set to the firewall
// and closes open connections. It returns how many rules were removed and an
// optional notice for the user.
func (s Service) DeleteAll(ctx context.Context) (int, string, error) {
	if s.BeforeDeleteAll != nil {
		if err := s.BeforeDeleteAll(ctx); err != nil {
			return 0, "", fmt.Errorf("nothing was removed because the backup failed: %w", err)
		}
	}
	removed, err := s.Store.DeleteAll(ctx)
	if err != nil {
		return 0, "", err
	}
	if err := s.Reconcile(ctx); err != nil {
		return len(removed), "", fmt.Errorf("rules removed from the database but firewall apply failed: %w", err)
	}
	control, ok := s.Firewall.(ConnectionControl)
	if !ok {
		return len(removed), "", nil
	}
	closed := 0
	for _, rule := range removed {
		count, err := control.Disconnect(ctx, rule)
		if errors.Is(err, firewall.ErrNoConntrack) {
			return len(removed), "Connections that were already open stay up until they go idle; install conntrack to close them immediately", nil
		}
		closed += count
	}
	if closed > 0 {
		return len(removed), fmt.Sprintf("Closed %d open connection(s)", closed), nil
	}
	return len(removed), "", nil
}

func (s Service) closeConnections(ctx context.Context, rule store.Rule, needConntrack bool) string {
	control, ok := s.Firewall.(ConnectionControl)
	if !ok {
		return ""
	}
	notes := make([]string, 0, 2)
	closed, err := control.Disconnect(ctx, rule)
	switch {
	case errors.Is(err, firewall.ErrNoConntrack):
		if needConntrack {
			notes = append(notes, "Connections that were already open stay up until they go idle; install conntrack to close them immediately")
		}
	case err != nil:
		notes = append(notes, "Could not close open connections: "+err.Error())
	case closed > 0:
		notes = append(notes, fmt.Sprintf("Closed %d open connection(s)", closed))
	}
	if other, err := control.OtherForwards(ctx, rule.PublicPort, rule.Protocol); err == nil && other {
		notes = append(notes, fmt.Sprintf("A rule outside iptable-ui (another script?) still forwards port %d; restart iptable-ui to take it over", rule.PublicPort))
	}
	return strings.Join(notes, ". ")
}

func find(rules []store.Rule, id int64) (store.Rule, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return store.Rule{}, false
}

func sameForward(first, second store.Rule) bool {
	return first.PublicPort == second.PublicPort && first.DestIP == second.DestIP && first.DestPort == second.DestPort &&
		first.Protocol == second.Protocol && first.KeepClientIP == second.KeepClientIP
}

func (s Service) Reconcile(ctx context.Context) error {
	if s.Firewall == nil {
		return errors.New("firewall manager is not configured")
	}
	rules, err := s.Store.List(ctx)
	if err != nil {
		return err
	}
	return s.Firewall.Reconcile(ctx, rules)
}

func protocolsOverlap(first, second string) bool {
	return first == second || first == "both" || second == "both"
}
