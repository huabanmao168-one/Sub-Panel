package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestEventPageSkipsWhitelistedAndUsesPrivateLookup(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	if err := st.AddIPWhitelist("192.0.2.1", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := srv.rules.Reload(); err != nil {
		t.Fatal(err)
	}
	const raw = "fixture raw/+ token"
	now := time.Now()
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.1", "192.0.2.3"} {
		st.SubmitEvent(store.Event{TS: now.Add(-time.Duration(i) * time.Second), Tenant: "fixture", ClientIP: ip, TokenHash: srv.hasher.Hash(raw), Action: "pass", Status: 200})
	}
	for until := time.Now().Add(2 * time.Second); ; {
		req := httptest.NewRequest(http.MethodGet, "/api/events?show_whitelist=1", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var items []store.Event
		if json.Unmarshal(w.Body.Bytes(), &items) == nil && len(items) == 4 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("test events did not flush")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fetch := func(cursor string) ([]store.Event, string) {
		path := "/api/events?page=cursor&limit=1&cursor=" + url.QueryEscape(cursor)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Subscription-Lookup", strings.ReplaceAll(url.QueryEscape(raw), "+", "%20"))
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var page struct {
			Items []store.Event `json:"items"`
			Next  string        `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || strings.Contains(w.Body.String(), raw) {
			t.Fatal("invalid or unredacted event response")
		}
		return page.Items, page.Next
	}
	items, next := fetch("")
	if len(items) != 1 || items[0].ClientIP != "192.0.2.2" || next == "" {
		t.Fatal("first visible row or cursor missing")
	}
	items, next = fetch(next)
	if len(items) != 1 || items[0].ClientIP != "192.0.2.3" || next != "" {
		t.Fatal("cursor did not advance across hidden events")
	}
}

func TestPurgeRejectsImplicitAll(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	for _, body := range []string{`{}`, `{"tenant":"fixture","all":true}`, `garbage`} {
		req := httptest.NewRequest(http.MethodPost, "/api/events/purge", strings.NewReader(body))
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous purge status: %d", w.Code)
		}
	}
}
