package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type Runtime struct {
	mu       sync.Mutex
	token    string
	address  string
	service  service
	setup    WireGuardSetup
	server   *http.Server
	listener net.Listener
}

func NewRuntime(token, address string, rules service, setup WireGuardSetup) *Runtime {
	return &Runtime{token: token, address: address, service: rules, setup: setup}
}

func (r *Runtime) Toggle() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.server.Shutdown(ctx); err != nil {
			return true, fmt.Errorf("stop web UI: %w", err)
		}
		r.server = nil
		r.listener = nil
		return false, nil
	}
	listener, err := r.listen()
	if err != nil {
		return false, err
	}
	server := &http.Server{Handler: Handler(r.token, r.service, r.setup), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	r.listener = listener
	r.server = server
	go func() {
		_ = server.Serve(listener)
	}()
	return true, nil
}

func (r *Runtime) Enabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.server != nil
}

func (r *Runtime) Address() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.address
}

func (r *Runtime) Token() string { return r.token }

func (r *Runtime) Close() error {
	if !r.Enabled() {
		return nil
	}
	_, err := r.Toggle()
	return err
}

func (r *Runtime) listen() (net.Listener, error) {
	host, _, err := net.SplitHostPort(r.address)
	if err != nil {
		return nil, fmt.Errorf("invalid web address: %w", err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, errors.New("web UI bind address must be an IP address, such as 127.0.0.1 or 0.0.0.0")
	}
	listener, err := net.Listen("tcp", r.address)
	if err != nil {
		return nil, fmt.Errorf("listen for web UI: %w", err)
	}
	r.address = listener.Addr().String()
	return listener, nil
}

func (r *Runtime) StatusText() string {
	bindHost, _, _ := net.SplitHostPort(r.Address())
	bindIP := net.ParseIP(bindHost)
	publicBind := bindIP != nil && (bindIP.IsUnspecified() || !bindIP.IsLoopback())
	if r.Enabled() {
		status := "ON at http://" + r.Address()
		if publicBind {
			status += " (public bind; plain HTTP)"
		}
		return status
	}
	status := "OFF; bind " + r.Address() + "; press W to start"
	if publicBind {
		status += " (public bind; restrict access)"
	}
	return status
}
