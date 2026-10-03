package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/traffic"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
)

//go:embed index.html
var assets embed.FS

type service interface {
	List(context.Context) ([]store.Rule, error)
	Add(context.Context, store.Rule) (store.Rule, error)
	Update(context.Context, store.Rule) (store.Rule, error)
	SetEnabled(context.Context, int64, bool) (string, error)
	Delete(context.Context, int64) (string, error)
	DeleteAll(context.Context) (int, string, error)
	LiveRules(context.Context) (string, error)
	Reconcile(context.Context) error
}

type WireGuardSetup interface {
	Configure(context.Context, wgsetup.SetupRequest) (wgsetup.SetupResult, error)
	LoadExisting(context.Context, string) (wgsetup.ExistingConfig, error)
	UpdateExisting(context.Context, wgsetup.EditConfigRequest) (wgsetup.EditConfigResult, error)
}

type SystemControl interface {
	Status(context.Context) system.Status
	SetForwarding(context.Context, bool) error
	SetBootRestore(context.Context, bool) error
}

// Settings stores web UI preferences such as the theme.
type Settings interface {
	Setting(context.Context, string) (string, error)
	SetSetting(context.Context, string, string) error
}

// Backups lists, creates and restores database backups.
type Backups interface {
	List() ([]backup.Info, error)
	Create(context.Context, string) (backup.Info, bool, error)
	Restore(context.Context, string) error
	Path(string) (string, error)
	Import(io.Reader) (backup.Info, error)
	MoveTo(string) error
	Folder() string
}

// Downloads resolves temporary backup download links.
type Downloads interface {
	Resolve(token string) (path, name string, ok bool)
}

// PortControl reads and changes the web UI port.
type PortControl interface {
	Port() int
	SetPort(int) (string, error)
}

// Traffic reports measured network speeds.
type Traffic interface {
	Snapshot() traffic.Snapshot
}

// RemoveAllConfirmation must be sent to remove every rule, so it can never
// happen by accident.
const RemoveAllConfirmation = "REMOVE ALL"

// Services are what the web UI manages. A nil field turns its feature off.
type Services struct {
	Rules     service
	WireGuard WireGuardSetup
	Host      SystemControl
	Backups   Backups
	Settings  Settings
	Traffic   Traffic
	// Downloads and Port are filled in by Runtime.
	Downloads Downloads
	Port      PortControl
}

// Themes the web UI offers; "system" follows the browser's light/dark mode.
var Themes = []string{"system", "light", "dark", "ocean", "midnight", "sunset", "contrast", "nord", "dracula", "solarized", "gruvbox", "rose"}

const themeSetting = "web.theme"

func Handler(token string, services Services) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		content, err := assets.ReadFile("index.html")
		if err != nil {
			http.Error(w, "web interface unavailable", http.StatusInternalServerError)
			return
		}
		w.Write(content)
	})
	// Temporary links from the TUI work without the session token; the
	// unguessable link itself is the secret, and it expires.
	mux.HandleFunc("GET /download/{token}", func(w http.ResponseWriter, r *http.Request) {
		if services.Downloads == nil {
			http.NotFound(w, r)
			return
		}
		path, name, ok := services.Downloads.Resolve(r.PathValue("token"))
		if !ok {
			http.Error(w, "This download link has expired or is not valid. Create a new one in iptable-ui.", http.StatusNotFound)
			return
		}
		serveBackup(w, r, path, name)
	})
	mux.Handle("/api/", authenticate(token, api{service: services.Rules, setup: services.WireGuard, system: services.Host, backups: services.Backups, settings: services.Settings, port: services.Port, traffic: services.Traffic}))
	return securityHeaders(mux)
}

type api struct {
	service  service
	setup    WireGuardSetup
	system   SystemControl
	backups  Backups
	settings Settings
	port     PortControl
	traffic  Traffic
}

func (a api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/rules":
		rules, err := a.service.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, rules)
	case r.Method == http.MethodPost && r.URL.Path == "/api/rules":
		var rule store.Rule
		if err := decodeJSON(w, r, &rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		added, err := a.service.Add(r.Context(), rule)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusCreated, added)
	case r.Method == http.MethodPost && r.URL.Path == "/api/reconcile":
		if err := a.service.Reconcile(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "reconciled"})
	case r.Method == http.MethodPost && r.URL.Path == "/api/wireguard/config":
		if a.setup == nil {
			writeError(w, http.StatusNotImplemented, errors.New("WireGuard setup is unavailable"))
			return
		}
		var request wgsetup.SetupRequest
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		result, err := a.setup.Configure(r.Context(), request)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusCreated, result)
	case r.Method == http.MethodGet && r.URL.Path == "/api/wireguard/config":
		if a.setup == nil {
			writeError(w, http.StatusNotImplemented, errors.New("WireGuard setup is unavailable"))
			return
		}
		config, err := a.setup.LoadExisting(r.Context(), r.URL.Query().Get("interface"))
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, config)
	case r.Method == http.MethodPut && r.URL.Path == "/api/wireguard/config":
		if a.setup == nil {
			writeError(w, http.StatusNotImplemented, errors.New("WireGuard setup is unavailable"))
			return
		}
		var request wgsetup.EditConfigRequest
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		result, err := a.setup.UpdateExisting(r.Context(), request)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case r.Method == http.MethodPost && r.URL.Path == "/api/rules/remove-all":
		a.removeAll(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/rules/"):
		a.ruleAction(w, r)
	case r.URL.Path == "/api/settings":
		a.settingsAction(w, r)
	case r.URL.Path == "/api/settings/port":
		a.portAction(w, r)
	case r.URL.Path == "/api/backups" || strings.HasPrefix(r.URL.Path, "/api/backups/"):
		a.backupAction(w, r)
	case r.URL.Path == "/api/settings/backup-dir":
		a.backupFolderAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/traffic":
		a.trafficAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/firewall/live":
		output, err := a.service.LiveRules(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		response := map[string]any{"command": "sudo " + strings.Join(firewall.LiveRulesCommand, " "), "output": output}
		if table, ok := firewall.ParseLiveRules(output); ok {
			response["table"] = table
		}
		writeJSON(w, http.StatusOK, response)
	case r.URL.Path == "/api/system" || strings.HasPrefix(r.URL.Path, "/api/system/"):
		a.systemAction(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a api) ruleAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/rules/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, errors.New("invalid rule id"))
		return
	}
	notice := ""
	if r.Method == http.MethodDelete && len(parts) == 1 {
		notice, err = a.service.Delete(r.Context(), id)
	} else if r.Method == http.MethodPatch && len(parts) == 1 {
		var rule store.Rule
		if err = decodeJSON(w, r, &rule); err == nil {
			rule.ID = id
			_, err = a.service.Update(r.Context(), rule)
		}
	} else if r.Method == http.MethodPatch && len(parts) == 2 && parts[1] == "enabled" {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err = decodeJSON(w, r, &body); err == nil {
			if body.Enabled == nil {
				err = errors.New("enabled is required")
			} else {
				notice, err = a.service.SetEnabled(r.Context(), id, *body.Enabled)
			}
		}
	} else {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"notice": notice})
}

func (a api) systemAction(w http.ResponseWriter, r *http.Request) {
	if a.system == nil {
		writeError(w, http.StatusNotImplemented, errors.New("host settings are unavailable"))
		return
	}
	var apply func(context.Context, bool) error
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/system":
		writeJSON(w, http.StatusOK, a.system.Status(r.Context()))
		return
	case r.Method == http.MethodPut && r.URL.Path == "/api/system/forwarding":
		apply = a.system.SetForwarding
	case r.Method == http.MethodPut && r.URL.Path == "/api/system/boot-restore":
		apply = a.system.SetBootRestore
	default:
		http.NotFound(w, r)
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, errors.New("enabled is required"))
		return
	}
	if err := apply(r.Context(), *body.Enabled); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, a.system.Status(r.Context()))
}

func (a api) settingsAction(w http.ResponseWriter, r *http.Request) {
	if a.settings == nil {
		writeError(w, http.StatusNotImplemented, errors.New("settings are unavailable"))
		return
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut:
		var body struct {
			Theme string `json:"theme"`
		}
		if err := decodeJSON(w, r, &body); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !slices.Contains(Themes, body.Theme) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("theme must be one of %s", strings.Join(Themes, ", ")))
			return
		}
		if err := a.settings.SetSetting(r.Context(), themeSetting, body.Theme); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	theme, err := a.settings.Setting(r.Context(), themeSetting)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !slices.Contains(Themes, theme) {
		theme = "system"
	}
	response := map[string]any{"theme": theme, "themes": Themes}
	if a.port != nil {
		response["port"] = a.port.Port()
	}
	if a.backups != nil {
		response["backupDir"] = a.backups.Folder()
	}
	writeJSON(w, http.StatusOK, response)
}

// trafficAction reports adapter speeds and each saved rule's speeds.
func (a api) trafficAction(w http.ResponseWriter, r *http.Request) {
	if a.traffic == nil {
		writeError(w, http.StatusNotImplemented, errors.New("traffic is unavailable"))
		return
	}
	snapshot := a.traffic.Snapshot()
	rules, err := a.service.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	type ruleTraffic struct {
		ID int64 `json:"id"`
		traffic.Rate
	}
	perRule := make([]ruleTraffic, 0, len(rules))
	for _, rule := range rules {
		if rate, ok := snapshot.ForwardRate(rule.PublicPort, rule.Protocol, rule.DestIP); ok {
			perRule = append(perRule, ruleTraffic{ID: rule.ID, Rate: rate})
		}
	}
	adapters := snapshot.Adapters
	if adapters == nil {
		adapters = []traffic.Adapter{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"adapters": adapters, "rules": perRule})
}

func (a api) backupFolderAction(w http.ResponseWriter, r *http.Request) {
	if a.backups == nil {
		writeError(w, http.StatusNotImplemented, errors.New("backups are unavailable"))
		return
	}
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Dir string `json:"dir"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.backups.MoveTo(strings.TrimSpace(body.Dir)); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"backupDir": a.backups.Folder()})
}

func (a api) portAction(w http.ResponseWriter, r *http.Request) {
	if a.port == nil {
		writeError(w, http.StatusNotImplemented, errors.New("changing the port is unavailable"))
		return
	}
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Port int `json:"port"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	url, err := a.port.SetPort(body.Port)
	if err != nil && url == "" {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	response := map[string]any{"port": body.Port, "url": url}
	if err != nil {
		response["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

func (a api) removeAll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Confirm != RemoveAllConfirmation {
		writeError(w, http.StatusBadRequest, fmt.Errorf("type %q to confirm removing every rule", RemoveAllConfirmation))
		return
	}
	removed, notice, err := a.service.DeleteAll(r.Context())
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed, "notice": notice})
}

// serveBackup sends a backup file as a download.
func serveBackup(w http.ResponseWriter, r *http.Request, path, name string) {
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "backup not readable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "iptable-ui-" + name}))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, stat.ModTime(), file)
}

func (a api) backupAction(w http.ResponseWriter, r *http.Request) {
	if a.backups == nil {
		writeError(w, http.StatusNotImplemented, errors.New("backups are unavailable"))
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/backups":
		backups, err := a.backups.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, backups)
	case r.Method == http.MethodPost && r.URL.Path == "/api/backups":
		info, _, err := a.backups.Create(r.Context(), backup.Manual)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, info)
	case r.Method == http.MethodPost && r.URL.Path == "/api/backups/upload":
		info, err := a.backups.Import(http.MaxBytesReader(w, r.Body, backup.MaxImportSize+1))
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusCreated, info)
	case r.Method == http.MethodGet && r.URL.Path == "/api/backups/download":
		name := r.URL.Query().Get("name")
		path, err := a.backups.Path(name)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		serveBackup(w, r, path, name)
	case r.Method == http.MethodPost && r.URL.Path == "/api/backups/restore":
		var body struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(w, r, &body); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := a.backups.Restore(r.Context(), body.Name); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
	default:
		http.NotFound(w, r)
	}
}

func authenticate(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain a single JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
