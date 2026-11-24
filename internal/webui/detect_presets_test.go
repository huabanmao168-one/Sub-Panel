package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/store"
)

func detectRequest(t *testing.T, h http.Handler) func(string, string, string) *httptest.ResponseRecorder {
	t.Helper()
	cookie := login(t, h)
	return func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
}

func TestDetectPresetImportIsDisabledIdempotentAndDoesNotOverwrite(t *testing.T) {
	srv, st, _ := setup(t)
	when, err := json.Marshal(detectPresets[0].When)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDetectRule("", store.DetectRuleRow{Name: "manual custom", Desc: "keep me", WhenJSON: string(when), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDetectRule("", store.DetectRuleRow{Name: "preset_ip_burst", Desc: "my different limits", WhenJSON: `{"IPFreq":{"Window":300000000000,"GTE":123}}`}); err != nil {
		t.Fatal(err)
	}
	call := detectRequest(t, srv.Handler())
	w := call("GET", "/api/detect_rules/presets", "")
	var catalog []presetView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &catalog) != nil || len(catalog) != len(detectPresets) || catalog[0].Existing != "manual custom" || catalog[2].Existing != "preset_ip_burst" {
		t.Fatalf("bad preset catalog: %s", w.Body.String())
	}
	if w := call("POST", "/api/detect_rules/presets/import", `{"ids":["preset_token_many_ips","unknown"]}`); w.Code != 400 {
		t.Fatalf("invalid input: %d", w.Code)
	}
	if n, err := st.CountDetectRules(); err != nil || n != 2 {
		t.Fatalf("invalid import changed DB: %d %v", n, err)
	}
	const payload = `{"ids":["preset_token_burst","preset_ip_burst","preset_token_many_ips","preset_cloud_ip"]}`
	for i := 0; i < 2; i++ {
		w := call("POST", "/api/detect_rules/presets/import", payload)
		var result struct{ Imported, Skipped []string }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("preview/import: %d %s", w.Code, w.Body.String())
		}
		want := 2
		if i == 1 {
			want = 0
		}
		if len(result.Imported) != want || len(result.Skipped) != 4-want {
			t.Fatalf("unexpected import result %+v", result)
		}
	}
	rows, err := st.ListDetectRules()
	if err != nil || len(rows) != 4 {
		t.Fatalf("rule count after import: %d %v", len(rows), err)
	}
	for _, r := range rows {
		if r.Name == "manual custom" && (!r.Enabled || r.Desc != "keep me" || r.WhenJSON != string(when)) {
			t.Fatal("manual rule was overwritten")
		}
		if r.Name == "preset_ip_burst" && r.Desc != "my different limits" {
			t.Fatal("same-name rule was overwritten")
		}
		if (r.Name == "preset_cloud_ip" || r.Name == "preset_token_many_ips") && r.Enabled {
			t.Fatal("imported rule was silently enabled")
		}
	}
}

func TestDetectStateDoesNotRewriteConditionsAndChecksWindow(t *testing.T) {
	srv, st, _ := setup(t)
	det, err := detector.New(&config.DetectorCfg{})
	if err != nil {
		t.Fatal(err)
	}
	srv.det = det
	const when = `{"TokenFreq":{"Window":300000000000,"GTE":2},"legacy_extra":true}`
	for _, row := range []store.DetectRuleRow{
		{Name: "threshold", WhenJSON: when, SortOrder: 12},
		{Name: "too long", WhenJSON: `{"IPFreq":{"Window":90000000000000,"GTE":1}}`},
		{Name: "geo only", WhenJSON: `{"FromCloudIP":true}`},
	} {
		if err := st.SaveDetectRule("", row); err != nil {
			t.Fatal(err)
		}
	}
	call := detectRequest(t, srv.Handler())
	for _, bad := range []string{`{"name":"threshold"}`, `{"name":"too long","enabled":true}`, `{"name":"geo only","enabled":true}`} {
		if w := call("POST", "/api/detect_rules/state", bad); w.Code != 400 {
			t.Errorf("invalid state change: %d %s", w.Code, w.Body.String())
		}
	}
	if w := call("POST", "/api/detect_rules/state", `{"name":"threshold","enabled":true}`); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	det.Observe("192.0.2.10", "fixture", "")
	det.Observe("192.0.2.10", "fixture", "")
	if !det.Evaluate("192.0.2.10", "fixture", "").Hit {
		t.Fatal("toggled rule did not reach the detector")
	}
	if w := call("POST", "/api/detect_rules/state", `{"name":"threshold","enabled":false}`); w.Code != 200 {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if det.Evaluate("192.0.2.10", "fixture", "").Hit {
		t.Fatal("last stopped rule still has runtime effect")
	}
	rows, err := st.ListDetectRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Name == "threshold" && (r.WhenJSON != when || r.SortOrder != 12 || r.Enabled) {
			t.Fatalf("status operation rewrote conditions: %+v", r)
		}
	}
	window := call("GET", "/api/detect_rules?view=editor", "")
	if window.Code != 200 || !strings.Contains(window.Body.String(), `"resolution_sec":60`) || !strings.Contains(window.Body.String(), `"max_window_sec":86400`) {
		t.Fatal("editor did not expose actual sliding window capacity")
	}
}

func TestDetectEditorRejectsConflictingMatchModes(t *testing.T) {
	for _, row := range []detectRuleAPI{
		{CountryIn: []string{"CN"}, CountryNotIn: []string{"US"}},
		{UsageTypeIn: []string{"IDC"}, UsageTypeNotIn: []string{"DYN"}},
		{TokenFreqWindowSec: int((5 * time.Minute).Seconds())},
	} {
		if _, err := apiToWhen(&row); err == nil {
			t.Fatalf("ambiguous/incomplete condition accepted: %+v", row)
		}
	}
	w, err := apiToWhen(&detectRuleAPI{ISPContains: []string{" Amazon Web Services "}})
	if err != nil || len(w.ISPContains) != 1 || w.ISPContains[0] != "Amazon Web Services" {
		t.Fatal("ISP phrase was not retained")
	}
}
