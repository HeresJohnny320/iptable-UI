package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
)

//go:embed index.html
var assets embed.FS

type service interface {
	List(context.Context) ([]store.Rule, error)
	Add(context.Context, store.Rule) (store.Rule, error)
	Update(context.Context, store.Rule) (store.Rule, error)
	SetEnabled(context.Context, int64, bool) error
	Delete(context.Context, int64) error
	Reconcile(context.Context) error
}

type WireGuardSetup interface {
	Configure(context.Context, wgsetup.SetupRequest) (wgsetup.SetupResult, error)
	LoadExisting(context.Context, string) (wgsetup.ExistingConfig, error)
	UpdateExisting(context.Context, wgsetup.EditConfigRequest) (wgsetup.EditConfigResult, error)
}

func Handler(token string, rules service, setup WireGuardSetup) http.Handler {
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
	mux.Handle("/api/", authenticate(token, api{service: rules, setup: setup}))
	return securityHeaders(mux)
}

type api struct {
	service service
	setup   WireGuardSetup
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
	case strings.HasPrefix(r.URL.Path, "/api/rules/"):
		a.ruleAction(w, r)
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
	if r.Method == http.MethodDelete && len(parts) == 1 {
		err = a.service.Delete(r.Context(), id)
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
				err = a.service.SetEnabled(r.Context(), id, *body.Enabled)
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
	w.WriteHeader(http.StatusNoContent)
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
