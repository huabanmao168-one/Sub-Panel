package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huabanmao168/SubPanel/internal/config"
)

func TestRuntimeSettingsSaveAndValidate(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	request := func(method, path string, input []byte, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(input))
		req.Header.Set("Content-Type", "application/json")
		if authenticated {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	const path = "/api/settings/runtime"
	if w := request("GET", path, nil, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request: %d", w.Code)
	}
	get := request("GET", path, nil, true)
	if get.Code != http.StatusOK || get.Header().Get("Cache-Control") != "no-store" ||
		strings.Contains(strings.ToLower(get.Body.String()), "password") || strings.Contains(get.Body.String(), srv.cfg.HMACSaltFile) {
		t.Fatal("settings response is not safe to return")
	}
	var result struct {
		Active          config.RuntimeSettings `json:"active"`
		Saved           config.RuntimeSettings `json:"saved"`
		RestartRequired bool                   `json:"restart_required"`
	}
	if err := json.NewDecoder(get.Body).Decode(&result); err != nil || result.RestartRequired {
		t.Fatalf("initial settings: %v, pending=%v", err, result.RestartRequired)
	}
	saved := result.Saved
	saved.EventRetention = "0s"
	payload, _ := json.Marshal(saved)
	if w := request("PUT", path, payload, true); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid retention was accepted: %d", w.Code)
	}
	saved.EventRetention = "48h"
	payload, _ = json.Marshal(saved)
	w := request("PUT", path, payload, true)
	if w.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", w.Code, w.Body.String())
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil || !result.RestartRequired || result.Saved.EventRetention != "48h0m0s" || result.Active.EventRetention == result.Saved.EventRetention {
		t.Fatalf("save must distinguish saved and active values: %v", err)
	}
	if cfg, err := st.RuntimeConfig(); err != nil || cfg.RuntimeSettings().EventRetention != "48h0m0s" {
		t.Fatal("settings write did not persist")
	}
	// A new process would take the saved configuration as its active snapshot.
	cfg, err := st.RuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	srv.cfg = cfg
	get = request("GET", path, nil, true)
	if err := json.NewDecoder(get.Body).Decode(&result); err != nil || result.RestartRequired {
		t.Fatalf("settings still pending after reload: %v", err)
	}
}

func TestSettingsRejectMissingToggleAndReportSecret(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	if err := st.SetMeta("passthrough_all", "true"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta("report_secret", "test-value"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/api/settings/passthrough", 400},
		{"GET", "/api/report-info/save", 405},
		{"POST", "/api/report-info/save", 400},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s %s: status=%d", tc.method, tc.path, w.Code)
		}
	}
	if v, _ := st.GetMeta("passthrough_all"); v != "true" {
		t.Fatal("missing field changed the toggle")
	}
	if v, _ := st.GetMeta("report_secret"); v != "test-value" {
		t.Fatal("missing field cleared the secret")
	}
}
