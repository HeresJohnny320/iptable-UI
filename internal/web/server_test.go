package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/traffic"
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

type testSystem struct {
	status system.Status
	err    error
}

func (s *testSystem) Status(context.Context) system.Status { return s.status }

func (s *testSystem) SetForwarding(_ context.Context, enabled bool) error {
	if s.err != nil {
		return s.err
	}
	s.status.Forwarding = enabled
	return nil
}

func (s *testSystem) SetBootRestore(_ context.Context, enabled bool) error {
	if s.err != nil {
		return s.err
	}
	s.status.BootRestore = enabled
	return nil
}

func TestHandlerAuthenticatesAndManagesRules(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	handler := Handler("session-secret", Services{Rules: app.Service{Store: database, Firewall: testFirewall{}}, WireGuard: testWireGuardSetup{}, Host: &testSystem{}})
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	pageHTML := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(pageHTML, "id=\"login\"") || !strings.Contains(pageHTML, "iptable-ui access") || !strings.Contains(pageHTML, "id=\"theme-toggle\"") || !strings.Contains(pageHTML, "data-theme=\"midnight\"") || !strings.Contains(pageHTML, "id=\"backups-panel\"") || !strings.Contains(pageHTML, "Edit an existing interface") || !strings.Contains(pageHTML, "Forward path") || !strings.Contains(pageHTML, "id=\"existing-wg-form\"") || !strings.Contains(pageHTML, "syncs with the terminal UI") || !strings.Contains(pageHTML, "Re-apply rules") || !strings.Contains(pageHTML, "Apply rules on boot") || !strings.Contains(pageHTML, "id=\"search\"") || !strings.Contains(pageHTML, "re-applied automatically at startup") || !strings.Contains(pageHTML, "setInterval(() => void load(), 1000)") {
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
	if editResponse.Code != http.StatusOK {
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
	runtime := NewRuntime("session-secret", "0.0.0.0:0", Services{Rules: app.Service{Store: database, Firewall: testFirewall{}}, WireGuard: testWireGuardSetup{}})
	enabled, err := runtime.Toggle()
	if err != nil || !enabled || !runtime.Enabled() {
		t.Fatalf("start web UI: enabled=%v, err=%v", enabled, err)
	}
	if !strings.Contains(runtime.StatusText(), "(plain HTTP)") || !strings.Contains(runtime.StatusText(), "http://<this-server-ip>:") {
		t.Fatalf("status should warn and show an address to open: %s", runtime.StatusText())
	}
	runtime.SetLinkHost("203.0.113.5")
	if status := runtime.StatusText(); !strings.Contains(status, "ON at http://203.0.113.5:") || strings.Contains(status, "0.0.0.0") {
		t.Fatalf("status should show the real IP instead of 0.0.0.0: %s", status)
	}
	if link := runtime.SignInURL(); !strings.HasPrefix(link, "http://203.0.113.5:") || !strings.HasSuffix(link, "/#token=session-secret") {
		t.Fatalf("sign-in link: %s", link)
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

func TestSystemSettingsAPI(t *testing.T) {
	host := &testSystem{status: system.Status{VPNInterface: "wg0", VPNUp: true}}
	handler := Handler("session-secret", Services{Rules: app.Service{}, Host: host})
	send := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer session-secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	status := send(http.MethodGet, "/api/system", "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"vpnInterface":"wg0"`) || !strings.Contains(status.Body.String(), `"forwarding":false`) {
		t.Fatalf("status returned %d: %s", status.Code, status.Body.String())
	}
	forwarding := send(http.MethodPut, "/api/system/forwarding", `{"enabled":true}`)
	if forwarding.Code != http.StatusOK || !host.status.Forwarding || !strings.Contains(forwarding.Body.String(), `"forwarding":true`) {
		t.Fatalf("forwarding toggle returned %d: %s", forwarding.Code, forwarding.Body.String())
	}
	boot := send(http.MethodPut, "/api/system/boot-restore", `{"enabled":true}`)
	if boot.Code != http.StatusOK || !host.status.BootRestore {
		t.Fatalf("boot restore toggle returned %d: %s", boot.Code, boot.Body.String())
	}
	if missing := send(http.MethodPut, "/api/system/forwarding", `{}`); missing.Code != http.StatusBadRequest {
		t.Fatalf("missing enabled flag returned %d", missing.Code)
	}
	if unknown := send(http.MethodPut, "/api/system/unknown", `{"enabled":true}`); unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown setting returned %d", unknown.Code)
	}
	host.err = errors.New("sysctl override")
	if failed := send(http.MethodPut, "/api/system/forwarding", `{"enabled":false}`); failed.Code != http.StatusUnprocessableEntity || !strings.Contains(failed.Body.String(), "sysctl override") {
		t.Fatalf("failed toggle returned %d: %s", failed.Code, failed.Body.String())
	}
	unavailable := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	unavailable.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	Handler("session-secret", Services{Rules: app.Service{}}).ServeHTTP(response, unavailable)
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("missing host control returned %d", response.Code)
	}
}

func TestThemeIsSavedInTheDatabase(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	handler := Handler("session-secret", Services{Rules: app.Service{Store: database, Firewall: testFirewall{}}, Settings: database})
	send := func(method, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer session-secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if got := send(http.MethodGet, ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"theme":"system"`) || !strings.Contains(got.Body.String(), `"ocean"`) {
		t.Fatalf("default theme should be system: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodPut, `{"theme":"midnight"}`); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"theme":"midnight"`) {
		t.Fatalf("saving a theme returned %d %s", got.Code, got.Body.String())
	}
	if saved, _ := database.Setting(context.Background(), "web.theme"); saved != "midnight" {
		t.Fatalf("theme not stored in the database: %q", saved)
	}
	if got := send(http.MethodPut, `{"theme":"neon-pink"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("an unknown theme should be rejected, got %d", got.Code)
	}
}

func TestBackupAPI(t *testing.T) {
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := app.Service{Store: database, Firewall: testFirewall{}}
	manager := &backup.Manager{Store: database, Dir: filepath.Join(directory, "backups"),
		Apply: func(ctx context.Context, rules []store.Rule, settings map[string]string) error {
			if err := database.ReplaceAll(ctx, rules, settings); err != nil {
				return err
			}
			return service.Reconcile(ctx)
		}}
	handler := Handler("session-secret", Services{Rules: service, Backups: manager})
	send := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer session-secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if _, err := service.Add(context.Background(), store.Rule{PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	created := send(http.MethodPost, "/api/backups", "")
	var info backup.Info
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &info) != nil || info.Kind != "manual" || info.Rules != 1 {
		t.Fatalf("manual backup returned %d %s", created.Code, created.Body.String())
	}
	if _, err := service.Add(context.Background(), store.Rule{PublicPort: 443, DestIP: "10.0.0.3", DestPort: 443, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if listed := send(http.MethodGet, "/api/backups", ""); listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), info.Name) {
		t.Fatalf("list returned %d %s", listed.Code, listed.Body.String())
	}
	if restored := send(http.MethodPost, "/api/backups/restore", `{"name":"`+info.Name+`"}`); restored.Code != http.StatusOK {
		t.Fatalf("restore returned %d %s", restored.Code, restored.Body.String())
	}
	if rules, _ := database.List(context.Background()); len(rules) != 1 {
		t.Fatalf("restore should leave the backed-up single rule, got %d", len(rules))
	}
	if bad := send(http.MethodPost, "/api/backups/restore", `{"name":"../rules.db"}`); bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a bad name should be rejected, got %d", bad.Code)
	}
}

func newBackupServices(t *testing.T) (Services, *store.Store, *backup.Manager) {
	t.Helper()
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	service := app.Service{Store: database, Firewall: testFirewall{}}
	manager := &backup.Manager{Store: database, Dir: filepath.Join(directory, "backups"),
		SaveFolder: func(dir string) error { return database.SetSetting(context.Background(), backup.FolderSetting, dir) }}
	service.BeforeDeleteAll = func(ctx context.Context) error {
		_, _, err := manager.Create(ctx, backup.PreClear)
		return err
	}
	return Services{Rules: service, Backups: manager, Settings: database}, database, manager
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestBackupDownloads(t *testing.T) {
	services, _, manager := newBackupServices(t)
	info, _, err := manager.Create(context.Background(), backup.Manual)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime("session-secret", "127.0.0.1:0", services)
	if _, err := runtime.DownloadLink(info.Name); err == nil || !strings.Contains(err.Error(), "web UI is off") {
		t.Fatalf("a link needs the web UI running, got %v", err)
	}
	if _, err := runtime.Toggle(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	// Signed in: the web UI's Download button.
	request, _ := http.NewRequest(http.MethodGet, "http://"+runtime.Address()+"/api/backups/download?name="+info.Name, nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "SQLite format 3") || !strings.Contains(response.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download returned %d %q %q", response.StatusCode, response.Header.Get("Content-Disposition"), body[:min(20, len(body))])
	}

	// The TUI's link works without the session token.
	link, err := runtime.DownloadLink(info.Name)
	if err != nil || !strings.Contains(link, "/download/") {
		t.Fatalf("link %q, err %v", link, err)
	}
	response, err = http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "SQLite format 3") {
		t.Fatalf("link download returned %d", response.StatusCode)
	}
	for _, bad := range []string{"/download/not-a-real-link", "/api/backups/download?name=../rules.db"} {
		response, err := http.Get("http://" + runtime.Address() + bad)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Errorf("%s should be refused", bad)
		}
	}
	if _, err := runtime.DownloadLink("../rules.db"); err == nil {
		t.Fatal("links may only point at backups")
	}
}

func TestPortCanBeChangedWhileRunning(t *testing.T) {
	services, _, _ := newBackupServices(t)
	oldPort, newPort := freePort(t), freePort(t)
	runtime := NewRuntime("session-secret", fmt.Sprintf("127.0.0.1:%d", oldPort), services)
	saved := 0
	runtime.OnPortChange(func(port int) error {
		saved = port
		return nil
	})
	if _, err := runtime.Toggle(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	// Ask the old server to move; it must still answer this request.
	request, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://127.0.0.1:%d/api/settings/port", oldPort), strings.NewReader(fmt.Sprintf(`{"port":%d}`, newPort)))
	request.Header.Set("Authorization", "Bearer session-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), fmt.Sprintf(":%d", newPort)) {
		t.Fatalf("port change returned %d %s", response.StatusCode, body)
	}
	if saved != newPort || runtime.Port() != newPort {
		t.Fatalf("saved %d, runtime port %d, want %d", saved, runtime.Port(), newPort)
	}
	page, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", newPort))
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	time.Sleep(1500 * time.Millisecond)
	if response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", oldPort)); err == nil {
		response.Body.Close()
		t.Fatal("the old port should stop shortly after the move")
	}

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := runtime.SetPort(busy.Addr().(*net.TCPAddr).Port); err == nil || runtime.Port() != newPort {
		t.Fatalf("a busy port must be refused and the UI must stay put, got %v on %d", err, runtime.Port())
	}
	if _, err := runtime.SetPort(70000); err == nil {
		t.Fatal("ports above 65535 must be refused")
	}
}

func TestRemoveAllNeedsTypedConfirmation(t *testing.T) {
	services, database, manager := newBackupServices(t)
	ctx := context.Background()
	for _, port := range []uint16{80, 443} {
		if _, err := services.Rules.Add(ctx, store.Rule{PublicPort: port, DestIP: "10.0.0.2", DestPort: port, Protocol: "tcp"}); err != nil {
			t.Fatal(err)
		}
	}
	handler := Handler("session-secret", services)
	send := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/rules/remove-all", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer session-secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for _, body := range []string{`{}`, `{"confirm":"yes"}`, `{"confirm":"remove all"}`} {
		if got := send(body); got.Code != http.StatusBadRequest {
			t.Fatalf("%s should be refused, got %d", body, got.Code)
		}
	}
	if rules, _ := database.List(ctx); len(rules) != 2 {
		t.Fatal("rules must survive a refused request")
	}
	got := send(`{"confirm":"REMOVE ALL"}`)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"removed":2`) {
		t.Fatalf("confirmed remove-all returned %d %s", got.Code, got.Body.String())
	}
	if rules, _ := database.List(ctx); len(rules) != 0 {
		t.Fatal("every rule should be removed")
	}
	backups, _ := manager.List()
	if len(backups) != 1 || backups[0].Kind != backup.PreClear || backups[0].Rules != 2 {
		t.Fatalf("a backup with both rules should be taken first: %+v", backups)
	}
}

type liveFirewall struct{ testFirewall }

func (liveFirewall) LiveRules(context.Context) (string, error) {
	return "Chain IPTUI_DNAT (1 references)\nnum   pkts bytes target     prot opt in     out     source               destination\n1       42  2520 DNAT       6    --  ens3   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:25565 to:10.66.0.2:25565\n", nil
}

func TestUploadLiveRulesAndBackupFolder(t *testing.T) {
	services, database, manager := newBackupServices(t)
	services.Rules = app.Service{Store: database, Firewall: liveFirewall{}}
	handler := Handler("session-secret", services)
	send := func(method, path string, body io.Reader) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, body)
		request.Header.Set("Authorization", "Bearer session-secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	ctx := context.Background()
	if _, err := services.Rules.Add(ctx, store.Rule{PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(t.TempDir(), "exported.db")
	if err := database.Backup(ctx, exported); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Open(exported)
	uploaded := send(http.MethodPost, "/api/backups/upload", file)
	file.Close()
	if uploaded.Code != http.StatusCreated || !strings.Contains(uploaded.Body.String(), `"kind":"uploaded"`) {
		t.Fatalf("upload returned %d %s", uploaded.Code, uploaded.Body.String())
	}
	if rejected := send(http.MethodPost, "/api/backups/upload", strings.NewReader("not a database")); rejected.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a non-database upload should be refused, got %d", rejected.Code)
	}

	live := send(http.MethodGet, "/api/firewall/live", nil)
	if live.Code != http.StatusOK || !strings.Contains(live.Body.String(), "sudo iptables -t nat -L IPTUI_DNAT -n -v --line-numbers") || !strings.Contains(live.Body.String(), "to:10.66.0.2:25565") {
		t.Fatalf("live rules returned %d %s", live.Code, live.Body.String())
	}

	target := filepath.Join(t.TempDir(), "iptable-ui-backups")
	moved := send(http.MethodPut, "/api/settings/backup-dir", strings.NewReader(`{"dir":"`+target+`"}`))
	if moved.Code != http.StatusOK || manager.Folder() != target {
		t.Fatalf("folder change returned %d %s", moved.Code, moved.Body.String())
	}
	if saved, _ := database.Setting(ctx, "backup.dir"); saved != target {
		t.Fatalf("the folder should be saved, got %q", saved)
	}
	if backups, _ := manager.List(); len(backups) != 1 {
		t.Fatalf("the uploaded backup should move along: %+v", backups)
	}
	if settings := send(http.MethodGet, "/api/settings", nil); !strings.Contains(settings.Body.String(), target) {
		t.Fatalf("settings should report the folder: %s", settings.Body.String())
	}
	if bad := send(http.MethodPut, "/api/settings/backup-dir", strings.NewReader(`{"dir":"relative"}`)); bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a relative folder should be refused, got %d", bad.Code)
	}
}

func TestMasking(t *testing.T) {
	tests := map[string]string{
		"http://203.0.113.5:8787/":           "http://203.•••.•••.•••:8787/",
		"http://203.0.113.5:8787/#token=abc": "http://203.•••.•••.•••:8787/#token=abc",
		"http://127.0.0.1:8787/":             "http://127.0.0.1:8787/",
		"http://[2001:db8::5]:8787/":         "http://[2001:••••]:8787/",
		"http://<this-server-ip>:8787/":      "http://<this-server-ip>:8787/",
	}
	for link, want := range tests {
		if got := MaskURL(link); got != want {
			t.Errorf("MaskURL(%q) = %q, want %q", link, got, want)
		}
	}
	if got := MaskToken("3f9a0011223344"); got != "3f9a••••••••" {
		t.Errorf("MaskToken = %q", got)
	}
}

type fakeTraffic struct{}

func (fakeTraffic) Snapshot() traffic.Snapshot {
	return traffic.Snapshot{
		Adapters: []traffic.Adapter{{Name: "ens3", Rate: traffic.Rate{InPerSecond: 1_000_000, OutPerSecond: 250_000}}},
		Forwards: map[traffic.Forward]traffic.Rate{
			{PublicPort: 25565, Protocol: "tcp", DestIP: "10.66.0.2"}: {InPerSecond: 1000, OutPerSecond: 50_000},
			{PublicPort: 25565, Protocol: "udp", DestIP: "10.66.0.2"}: {InPerSecond: 500},
		},
	}
}

func TestTrafficAPI(t *testing.T) {
	services, database, _ := newBackupServices(t)
	services.Traffic = fakeTraffic{}
	added, err := services.Rules.Add(context.Background(), store.Rule{PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "both"})
	if err != nil {
		t.Fatal(err)
	}
	_ = database
	request := httptest.NewRequest(http.MethodGet, "/api/traffic", nil)
	request.Header.Set("Authorization", "Bearer session-secret")
	response := httptest.NewRecorder()
	Handler("session-secret", services).ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"name":"ens3"`) || !strings.Contains(body, fmt.Sprintf(`"id":%d`, added.ID)) || !strings.Contains(body, `"inPerSecond":1500`) {
		t.Fatalf("traffic returned %d %s", response.Code, body)
	}
}
