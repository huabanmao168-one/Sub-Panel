package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/huabanmao168/SubPanel/internal/config"
)

func TestCloudflareChainRequiresBothHopsAndUsesVerifiedClientIP(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()
	const nginxIP, clientIP, cfIP = "192.0.2.7", "203.0.113.91", "173.245.48.5:4532"
	gw.cfg.IngressMode = config.IngressNginxCloudflare
	gw.cfg.NginxEgressIPs = []string{nginxIP}
	gw.cfg.NginxClientIP = true
	if err := gw.configureIngress(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, peer, cloudflareHeader, original string
		isDuplicate                            bool
		allow                                  bool
		wantIP                                 string
	}{
		{"valid chain", cfIP, nginxIP, clientIP, false, true, clientIP},
		{"IPv6 Cloudflare peer", "[2606:4700::1]:4532", nginxIP, clientIP, false, true, clientIP},
		{"no original IP", cfIP, nginxIP, "", false, true, nginxIP},
		{"invalid original IP", cfIP, nginxIP, clientIP + ", 203.0.113.95", false, true, nginxIP},
		{"direct CDN visitor", cfIP, "198.51.100.15", clientIP, false, false, ""},
		{"spoofed header without Cloudflare hop", "192.0.2.7:4532", nginxIP, clientIP, false, false, ""},
		{"duplicate identifying header", cfIP, nginxIP, clientIP, true, false, ""},
		{"missing identifying header", cfIP, "", clientIP, false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mkSubReq("sub.example.com", "client", "fixture", "", "198.51.100.120")
			r.RemoteAddr = tt.peer
			r.Header.Set("X-Forwarded-For", nginxIP)
			if tt.cloudflareHeader != "" {
				r.Header.Set("CF-Connecting-IP", tt.cloudflareHeader)
			}
			if tt.isDuplicate {
				r.Header.Add("CF-Connecting-IP", tt.cloudflareHeader)
			}
			if tt.original != "" {
				r.Header.Set(nginxClientIPHeader, tt.original)
			}
			if got, allowed := gw.ingressClient(r); got != tt.wantIP || allowed != tt.allow {
				t.Fatalf("admission: got (%s, %t), want (%s, %t)", got, allowed, tt.wantIP, tt.allow)
			}
			if !tt.allow {
				w := httptest.NewRecorder()
				gw.ServeHTTP(w, r)
				if w.Code != http.StatusNotFound || gw.Requests() != 0 {
					t.Fatal("untrusted request entered statistics")
				}
			}
		})
	}
	r := mkSubReq("sub.example.com", "client", "fixture", "", "198.51.100.120")
	r.RemoteAddr = cfIP
	r.Header.Set("CF-Connecting-IP", nginxIP)
	r.Header.Set(nginxClientIPHeader, clientIP)
	r.Header.Set("X-Forwarded-For", "198.51.100.120")
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), clientIP) || strings.Contains(w.Body.String(), "198.51.100.120") || gw.Requests() != 1 {
		t.Fatal("verified client IP was not used for the admitted request")
	}
}

func TestCloudflareRefreshKeepsLastSuccessfulList(t *testing.T) {
	gw, _, st, _, cleanup := newE2E(t, false)
	defer cleanup()
	gw.cfg.IngressMode = config.IngressNginxCloudflare
	gw.cfg.NginxEgressIPs = []string{"192.0.2.4"}
	if err := gw.configureIngress(); err != nil {
		t.Fatal(err)
	}
	const valid = `{"success":true,"result":{"ipv4_cidrs":["192.0.2.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid" {
			fmt.Fprint(w, valid)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":{"ipv4_cidrs":["0.0.0.0/0"],"ipv6_cidrs":[]}}`)
	}))
	defer server.Close()
	cached, err := gw.refreshCloudflareIPList(context.Background(), server.Client(), server.URL+"/valid", "")
	if err != nil || cached == "" {
		t.Fatalf("valid list was not saved: %v", err)
	}
	if v, err := st.GetMeta(cloudflareIngressCacheKey); err != nil || v != cached {
		t.Fatal("valid list not persisted")
	}
	current := gw.cloudflarePeers.Load()
	if next, err := gw.refreshCloudflareIPList(context.Background(), server.Client(), server.URL+"/bad", cached); err == nil || next != cached || gw.cloudflarePeers.Load() != current {
		t.Fatal("invalid response changed the trusted list")
	}
	if err := gw.configureIngress(); err != nil {
		t.Fatal(err)
	}
	if gw.loadCloudflareIPCache() != cached {
		t.Fatal("cached ranges were not restored")
	}
	r := httptest.NewRequest(http.MethodGet, "/sub/cat", nil)
	r.RemoteAddr = "192.0.2.19:2000"
	r.Header.Set("CF-Connecting-IP", "192.0.2.4")
	if _, ok := gw.ingressClient(r); !ok {
		t.Fatal("restored range was not applied")
	}
}
