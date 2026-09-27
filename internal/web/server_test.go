package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
)

type testFirewall struct{}

func (testFirewall) Reconcile(context.Context, []store.Rule) error { return nil }

type testWireGuardSetup struct{}

func (testWireGuardSetup) Configure(_ context.Context, request wgsetup.SetupRequest) (wgsetup.SetupResult, error) {
	return wgsetup.SetupResult{ConfigPath: "/tmp/" + request.InterfaceName + ".conf", ServerPublicKey: "public", PeerConfig: "peer template"}, nil
}

func (testWireGuardSetup) LoadExisting(_ context.Context, interfaceName string) (wgsetup.ExistingConfig, error) {
	return wgsetup.ExistingConfig{InterfaceName: interfaceName, Address: "10.66.0.1/24", ListenPort: 51820, PeerPublicKey: "peer-public", AllowedIPs: "10.66.0.2/32", Active: true}, nil
}

func (testWireGuardSetup) UpdateExisting(_ context.Context, request wgsetup.EditConfigRequest) (wgsetup.EditConfigResult, error) {
	return wgsetup.EditConfigResult{Config: wgsetup.ExistingConfig{InterfaceName: request.InterfaceName}, Applied: true, Message: "synced"}, nil
}

func TestHandlerAuthenticatesAndManagesRules(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	handler := Handler("session-secret", app.Service{Store: database, Firewall: testFirewall{}}, testWireGuardSetup{})
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	pageHTML := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(pageHTML, "id=\"login\"") || !strings.Contains(pageHTML, "iptable-ui access") || !strings.Contains(pageHTML, "id=\"theme-toggle\"") || !strings.Contains(pageHTML, "data-theme=\"dark\"") || !strings.Contains(pageHTML, "Edit an existing interface") || !strings.Contains(pageHTML, "Forward path") || !strings.Contains(pageHTML, "id=\"existing-wg-form\"") || !strings.Contains(pageHTML, "sync with the terminal UI automatically") || !strings.Contains(pageHTML, "setInterval(() => void load(), 1000)") {
		t.Fatalf("login page was not served: %d", page.Code)
	}
	if page.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("expected anti-framing security header")
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request returned %d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewBufferString(`{"name":"service","publicPort":8443,"destIP":"10.0.0.8","destPort":443,"protocol":"tcp"}`))
	request.Header.Set("Authorization", "Bearer session-secret")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("authorized rule creation returned %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("API response should not be cached; the browser polls it for live updates")
	}
	var rule store.Rule
	if err := json.Unmarshal(response.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID == 0 || rule.PublicPort != 8443 || !rule.Enabled {
		t.Fatalf("unexpected API rule response: %+v", rule)
	}

	editRequest := httptest.NewRequest(http.MethodPatch, "/api/rules/"+strconv.FormatInt(rule.ID, 10), strings.NewReader(`{"name":"renamed","publicPort":9443,"destIP":"10.0.0.9","destPort":8444,"protocol":"udp"}`))
	editRequest.Header.Set("Authorization", "Bearer session-secret")
	editResponse := httptest.NewRecorder()
	handler.ServeHTTP(editResponse, editRequest)
	if editResponse.Code != http.StatusNoContent {
		t.Fatalf("rule edit returned %d: %s", editResponse.Code, editResponse.Body.String())
	}
	rules, err := database.List(context.Background())
	if err != nil || len(rules) != 1 || rules[0].Name != "renamed" || rules[0].DestIP != "10.0.0.9" || rules[0].PublicPort != 9443 {
		t.Fatalf("edited rule not stored: %+v, %v", rules, err)
	}

	setupRequest := httptest.NewRequest(http.MethodPost, "/api/wireguard/config", strings.NewReader(`{"interfaceName":"wg0"}`))
	setupRequest.Header.Set("Authorization", "Bearer session-secret")
	setupResponse := httptest.NewRecorder()
	handler.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusCreated || !strings.Contains(setupResponse.Body.String(), "peer template") {
		t.Fatalf("WireGuard config API returned %d: %s", setupResponse.Code, setupResponse.Body.String())
	}

	loadRequest := httptest.NewRequest(http.MethodGet, "/api/wireguard/config?interface=wg0", nil)
	loadRequest.Header.Set("Authorization", "Bearer session-secret")
	loadResponse := httptest.NewRecorder()
	handler.ServeHTTP(loadResponse, loadRequest)
	if loadResponse.Code != http.StatusOK || strings.Contains(loadResponse.Body.String(), "privateKey") || !strings.Contains(loadResponse.Body.String(), "peer-public") {
		t.Fatalf("WireGuard config load returned unsafe or unexpected data: %d %s", loadResponse.Code, loadResponse.Body.String())
	}

	updateRequest := httptest.NewRequest(http.MethodPut, "/api/wireguard/config", strings.NewReader(`{"interfaceName":"wg0","serverAddress":"10.66.0.1/24","listenPort":51821,"peerPublicKey":"new-peer","allowedIPs":"10.66.0.2/32"}`))
	updateRequest.Header.Set("Authorization", "Bearer session-secret")
	updateResponse := httptest.NewRecorder()
	handler.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK || !strings.Contains(updateResponse.Body.String(), "synced") {
		t.Fatalf("WireGuard config update returned %d: %s", updateResponse.Code, updateResponse.Body.String())
	}
}

func TestRuntimeToggleStartsAndStopsLoopbackServer(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	runtime := NewRuntime("session-secret", "0.0.0.0:0", app.Service{Store: database, Firewall: testFirewall{}}, testWireGuardSetup{})
	enabled, err := runtime.Toggle()
	if err != nil || !enabled || !runtime.Enabled() {
		t.Fatalf("start web UI: enabled=%v, err=%v", enabled, err)
	}
	if !strings.Contains(runtime.StatusText(), "public bind; plain HTTP") {
		t.Fatalf("public wildcard bind warning missing: %s", runtime.StatusText())
	}
	_, port, err := net.SplitHostPort(runtime.Address())
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get("http://127.0.0.1:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("web root returned %d", response.StatusCode)
	}
	enabled, err = runtime.Toggle()
	if err != nil || enabled || runtime.Enabled() {
		t.Fatalf("stop web UI: enabled=%v, err=%v", enabled, err)
	}
}
