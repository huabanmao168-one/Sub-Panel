package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestBlacklistEmptyListAndBanValidation(t *testing.T) {
	srv, st, bans := setup(t)
	srv.bl = blacklist.New(st)
	h := srv.Handler()
	cookie := login(t, h)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := call(http.MethodGet, "/api/bans", ""); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("expected non-null empty array, got %d %s", w.Code, w.Body.String())
	}
	for _, invalid := range []string{
		`{"kind":"ip","target":"invalid.example","ttl":"2h"}`,
		`{"kind":"ip","target":"192.0.2.1/24","ttl":"2h"}`,
		`{"kind":"ip","target":"192.0.2.1","ttl":"-1h"}`,
		`{"kind":"ip","target":"192.0.2.1","ttl":"0s"}`,
	} {
		if w := call(http.MethodPost, "/api/bans/add", invalid); w.Code != 400 {
			t.Fatalf("invalid ban accepted: %d", w.Code)
		}
	}
	if w := call(http.MethodPost, "/api/bans/add", `{"kind":"ip","target":"2001:0DB8:0000:0000:0000:0000:0000:0001","ttl":"2h"}`); w.Code != 200 {
		t.Fatalf("valid IPv6: %d %s", w.Code, w.Body.String())
	}
	if blocked, _ := bans.CheckIP("2001:db8::1"); !blocked {
		t.Fatal("IPv6 normalization did not affect the live ban")
	}
	w := call(http.MethodGet, "/api/bans", "")
	var rows []store.Ban
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].Target != "2001:db8::1" || rows[0].ExpiresTS == nil {
		t.Fatal("expected one temporary IPv6 ban")
	}

	if err := srv.bl.Update(blacklist.Snapshot{BrowserEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if w := call(http.MethodPost, "/api/blacklist/save", `{"oversea_enabled":true}`); w.Code != 400 || !srv.bl.Get().BrowserEnabled {
		t.Fatal("partial save changed active blacklist policy")
	}
}
