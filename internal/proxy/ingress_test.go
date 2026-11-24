package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestIngressSkipsDirectAndUnknownPathWithoutCounting(t *testing.T) {
	gw, _, st, _, cleanup := newE2E(t, false)
	defer cleanup()
	const clientIP = "192.0.2.49"
	const credential = "test-subscription"
	for _, passthrough := range []bool{false, true} {
		gw.SetPassthroughAll(passthrough)
		for i := 0; i < 6; i++ {
			direct := mkSubReq("sub.example.com", "crawler", credential, "", clientIP)
			direct.RemoteAddr = "198.51.100.70:3456"
			direct.Header.Set("X-Forwarded-For", "127.0.0.1")
			direct.Header.Set("X-Real-IP", clientIP)
			direct.Header.Set("Forwarded", "for=127.0.0.1")
			w := httptest.NewRecorder()
			gw.ServeHTTP(w, direct)
			if w.Code != http.StatusNotFound {
				t.Fatalf("direct connection: got %d", w.Code)
			}
		}
		viaProxy := mkSubReq("sub.example.com", "crawler", credential, "", clientIP)
		viaProxy.URL.Path = "/robots.txt"
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, viaProxy)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unknown path: got %d", w.Code)
		}
	}
	gw.SetPassthroughAll(false)
	gw.SetIPWhitelist(func(ip string) bool { return false })
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "client", credential, "", clientIP))
	if w.Code != http.StatusOK || gw.Requests() != 1 {
		t.Fatalf("valid request: status=%d, count=%d", w.Code, gw.Requests())
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events, err := st.QueryEvents(context.Background(), store.EventFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 {
			if len(events) != 1 || events[0].ClientIP != clientIP || events[0].Action != "pass" {
				t.Fatalf("unexpected request events: %+v", events)
			}
			incidents, err := st.QueryIncidents(context.Background(), store.IncidentFilter{})
			if err != nil || len(incidents) != 0 {
				t.Fatal("excluded traffic polluted incident statistics")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admitted request was not written")
}

func TestReportIngressRequiresConfiguredPeer(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()
	gw.ingressPeers = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28"), netip.MustParsePrefix("2001:db8::/64")}
	next := gw.RequireIngress(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		addr   string
		status int
	}{
		{"192.0.2.4:1234", 204}, {"[::ffff:192.0.2.5]:1234", 204}, {"[2001:db8::2]:1234", 204},
		{"192.0.2.18:1234", 404}, {"127.0.0.1:1234", 404}, {"not-an-address", 404},
	} {
		r := httptest.NewRequest(http.MethodPost, "/r/test", nil)
		r.RemoteAddr = tc.addr
		r.Header.Set("X-Real-IP", "192.0.2.4")
		w := httptest.NewRecorder()
		next.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("peer %s: got %d want %d", tc.addr, w.Code, tc.status)
		}
	}
}
