package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestDashboardExcludesTrafficBeforeVerifiedIngress(t *testing.T) {
	srv, st, _ := setup(t)
	now := time.Now()
	cutoff := now.Add(-time.Minute).Truncate(time.Millisecond)
	verifiedSince, err := st.VerifiedIngressSince(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if afterRestart, err := st.VerifiedIngressSince(now); err != nil || !afterRestart.Equal(cutoff) {
		t.Fatal("cutoff was not persisted")
	}
	srv.SetVerifiedIngressSince(verifiedSince)
	for _, item := range []struct {
		ts         time.Time
		ip, action string
	}{
		{cutoff.Add(-time.Second), "192.0.2.5", "fake"},
		{cutoff, "192.0.2.6", "deny"},
	} {
		st.SubmitEvent(store.Event{TS: item.ts, Tenant: "fixture", ClientIP: item.ip, Action: item.action, Status: 403})
		st.SubmitIncident(store.Incident{TS: item.ts, Tenant: "fixture", ClientIP: item.ip, Action: item.action})
	}
	for deadline := time.Now().Add(time.Second); ; {
		evs, evErr := st.QueryEvents(context.Background(), store.EventFilter{})
		incidents, inErr := st.QueryIncidents(context.Background(), store.IncidentFilter{})
		if evErr != nil || inErr != nil {
			t.Fatal(evErr, inErr)
		}
		if len(evs) == 2 && len(incidents) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("events did not flush")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h := srv.Handler()
	cookie := login(t, h)
	fetch := func(path string, out any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	var stats store.Stats
	fetch("/api/summary?window=168h", &stats)
	if stats.TotalEvents != 1 || stats.DenyCount != 1 || len(stats.TopIPs) != 1 || stats.TopIPs[0].Key != "192.0.2.6" {
		t.Fatal("historic traffic polluted dashboard")
	}
	var page struct {
		Items []store.Event `json:"items"`
	}
	fetch("/api/events?page=cursor&window=168h", &page)
	if len(page.Items) != 1 || page.Items[0].ClientIP != "192.0.2.6" {
		t.Fatal("historic traffic polluted request log")
	}
	var top []store.IncidentIPAgg
	fetch("/api/incidents/agg_ip?window=168h", &top)
	if len(top) != 1 || top[0].ClientIP != "192.0.2.6" {
		t.Fatal("historic traffic polluted incident ranking")
	}
}
