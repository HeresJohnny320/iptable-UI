package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

type RuleStore interface {
	List(context.Context) ([]store.Rule, error)
	Add(context.Context, store.Rule) (store.Rule, error)
	Update(context.Context, store.Rule) (store.Rule, error)
	SetEnabled(context.Context, int64, bool) error
	Delete(context.Context, int64) error
}

type Firewall interface {
	Reconcile(context.Context, []store.Rule) error
}

type Service struct {
	Store    RuleStore
	Firewall Firewall
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
	updated, err := s.Store.Update(ctx, rule)
	if err != nil {
		return store.Rule{}, err
	}
	if err := s.Reconcile(ctx); err != nil {
		return updated, fmt.Errorf("rule saved but firewall apply failed: %w", err)
	}
	return updated, nil
}

func (s Service) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	if err := s.Store.SetEnabled(ctx, id, enabled); err != nil {
		return err
	}
	if err := s.Reconcile(ctx); err != nil {
		return fmt.Errorf("rule state saved but firewall apply failed: %w", err)
	}
	return nil
}

func (s Service) Delete(ctx context.Context, id int64) error {
	if err := s.Store.Delete(ctx, id); err != nil {
		return err
	}
	if err := s.Reconcile(ctx); err != nil {
		return fmt.Errorf("rule deleted from database but firewall apply failed: %w", err)
	}
	return nil
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
