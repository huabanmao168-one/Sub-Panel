package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/faker"
	"github.com/huabanmao168/SubPanel/internal/parser"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
)

const clashSample = `proxies:
  - name: 花瓣 香港 01
    type: ss
    server: hk1.example.com
    port: 443
    cipher: aes-128-gcm
    password: SecretPW123
proxy-groups:
  - name: 花瓣
    type: select
    proxies:
      - 花瓣 香港 01
rules:
  - MATCH,花瓣
`

// newDisplayE2E 起一个返回 Clash 订阅的上游 + 网关,可选 gzip。
func newDisplayE2E(t *testing.T, gzipped bool) (*Gateway, *store.Store, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="花瓣.yaml"`)
		w.Header().Set("profile-title", "花瓣 机场")
		body := []byte(clashSample)
		if gzipped && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(body)
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			body = buf.Bytes()
		}
		w.WriteHeader(200)
		_, _ = w.Write(body)
	}))

	upURL, _ := url.Parse(upstream.URL)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "display.db")
	saltPath := filepath.Join(dir, "salt")

	cfg := &config.Config{
		Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", HMACSaltFile: saltPath,
		Storage: config.Storage{
			SQLitePath: dbPath, BatchFlushInterval: config.Duration(20 * time.Millisecond), BatchFlushSize: 5,
			Retention: config.Retention{Events: config.Duration(time.Hour), Incidents: config.Duration(time.Hour)},
		},
		RealIP:   config.RealIP{TrustProxies: []string{"127.0.0.1"}, TrustHeaders: []string{"X-Real-IP"}},
		Tenants:  []config.Tenant{{Name: "default", Host: "sub.example.com", SubscribePath: "/sub/cat", Upstream: upURL.String()}},
		Detector: config.DetectorCfg{ObserveOnly: true},
		Faker:    config.FakerCfg{NodeCount: 3, BlackholeIPs: []string{"192.0.2.1"}},
	}

	salt, err := token.LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath, 20*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	bans := banlist.New(st)
	_ = bans.LoadFromStore(context.Background())
	det, err := detector.New(&cfg.Detector)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGateway(cfg, token.NewHasher(salt), st, bans, det,
		faker.New(cfg.Faker.BlackholeIPs, cfg.Faker.NodeCount), AutoBanCfg{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return gw, st, func() {
		upstream.Close()
		_ = st.Close()
	}
}

func seedUserEmail(t *testing.T, st *store.Store, tok, email string) {
	t.Helper()
	if err := st.UpsertUserReport(store.UserReport{Token: tok, Tenant: "default", Email: email}); err != nil {
		t.Fatal(err)
	}
}

func installRule(t *testing.T, gw *Gateway, st *store.Store, r store.DisplayRule) {
	t.Helper()
	if r.Tenant == "" {
		r.Tenant = "default"
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("规则不合法: %v", err)
	}
	r.ID = 0
	if _, err := st.UpsertDisplayRule(r); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	rules, err := st.ListDisplayRules()
	if err != nil {
		t.Fatal(err)
	}
	gw.SetDisplayRules(rules)
}

func TestDisplayRuleRewritesNormalClientBody(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, false)
	defer cleanup()
	seedUserEmail(t, st, "auto-token-123456", "someone@auto.com")
	installRule(t, gw, st, store.DisplayRule{
		Name: "auto品牌", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		Replacements: `[{"from":"香港","to":"HK"}]`,
		ScopeNode:    true, ScopeGroup: true, ScopeHeader: true, Enabled: true,
	})

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "auto-token-123456", "clash", "8.8.8.8"))

	if w.Code != 200 {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "花瓣") {
		t.Fatalf("旧名没清干净:\n%s", body)
	}
	if !strings.Contains(body, "云帆 HK 01") {
		t.Fatalf("节点名未改写:\n%s", body)
	}
	if !strings.Contains(body, "hk1.example.com") || !strings.Contains(body, "SecretPW123") {
		t.Fatalf("连接参数被误改:\n%s", body)
	}
	cd := w.Header().Get("Content-Disposition")
	if strings.Contains(cd, "花瓣") || !strings.Contains(cd, "云帆.yaml") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if pt := w.Header().Get("profile-title"); strings.Contains(pt, "花瓣") {
		t.Fatalf("profile-title = %q", pt)
	}
}

func TestDisplayRuleSkipsNonMatchingEmail(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, false)
	defer cleanup()
	seedUserEmail(t, st, "other-token-12345", "normal@gmail.com")
	installRule(t, gw, st, store.DisplayRule{
		Name: "auto品牌", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		ScopeNode: true, ScopeGroup: true, ScopeHeader: true, Enabled: true,
	})

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "other-token-12345", "clash", "8.8.8.8"))
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "花瓣 香港 01") {
		t.Fatalf("未命中邮箱不应改写:\n%s", w.Body.String())
	}
}

func TestDisplayRuleSkipsUnknownToken(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, false)
	defer cleanup()
	installRule(t, gw, st, store.DisplayRule{
		Name: "auto品牌", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		ScopeNode: true, ScopeGroup: true, ScopeHeader: true, Enabled: true,
	})

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "never-reported-tok", "clash", "8.8.8.8"))
	if !strings.Contains(w.Body.String(), "花瓣 香港 01") {
		t.Fatalf("查不到邮箱不该改写:\n%s", w.Body.String())
	}
}

func TestDisplayRuleRespectsTenantScope(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, false)
	defer cleanup()
	seedUserEmail(t, st, "auto-token-123456", "someone@auto.com")
	installRule(t, gw, st, store.DisplayRule{
		Name: "只对别的机场", Tenant: "another", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		ScopeNode: true, ScopeGroup: true, ScopeHeader: true, Enabled: true,
	})

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "auto-token-123456", "clash", "8.8.8.8"))
	if !strings.Contains(w.Body.String(), "花瓣 香港 01") {
		t.Fatalf("机场不匹配不该改写:\n%s", w.Body.String())
	}
}

func TestDisplayRuleGzipUpstreamRoundTrip(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, true)
	defer cleanup()
	seedUserEmail(t, st, "auto-token-123456", "someone@auto.com")
	installRule(t, gw, st, store.DisplayRule{
		Name: "auto品牌", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		ScopeNode: true, ScopeGroup: true, ScopeHeader: true, Enabled: true,
	})

	req := mkSubReq("sub.example.com", "ClashforWindows/0.20", "auto-token-123456", "clash", "8.8.8.8")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.Bytes()
	if strings.EqualFold(w.Header().Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("gzip 解压失败: %v", err)
		}
		body, err = io.ReadAll(zr)
		if err != nil {
			t.Fatalf("gzip 读取失败: %v", err)
		}
	}
	if strings.Contains(string(body), "花瓣") {
		t.Fatalf("压缩场景旧名未清:\n%s", body)
	}
	if !strings.Contains(string(body), "云帆 香港 01") {
		t.Fatalf("压缩场景未改写:\n%s", body)
	}
}

func TestDisplayRuleLumiRewritesBeforeEncrypt(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, false)
	defer cleanup()
	const tok = "lumi-auto-token-123456"
	seedUserEmail(t, st, tok, "someone@auto.com")
	installRule(t, gw, st, store.DisplayRule{
		Name: "auto品牌", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		Replacements: `[{"from":"香港","to":"HK"}]`,
		ScopeNode:    true, ScopeGroup: true, ScopeHeader: true, Enabled: true,
	})

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "lumi app", tok, "clash", "8.8.8.8"))
	if w.Code != 200 {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "花瓣") || strings.Contains(w.Body.String(), "云帆") {
		t.Fatalf("响应体应已加密,不应出现明文名: %q", w.Body.String())
	}
	plain, ok := decryptLumiSubscriptionForTest(&parser.Request{Token: tok}, w.Body.Bytes())
	if !ok {
		t.Fatal("解密失败")
	}
	s := string(plain)
	if strings.Contains(s, "花瓣") {
		t.Fatalf("加密前未改写:\n%s", s)
	}
	if !strings.Contains(s, "云帆 HK 01") || !strings.Contains(s, "hk1.example.com") {
		t.Fatalf("解密后内容不对:\n%s", s)
	}
}

func TestDisplayRuleFirstMatchWins(t *testing.T) {
	gw, st, cleanup := newDisplayE2E(t, false)
	defer cleanup()
	seedUserEmail(t, st, "auto-token-123456", "someone@auto.com")
	installRule(t, gw, st, store.DisplayRule{
		Name: "先命中", MatchType: "email_suffix", MatchValue: "auto.com",
		AirportFrom: "花瓣", AirportTo: "云帆",
		ScopeNode: true, ScopeGroup: true, ScopeHeader: true, Enabled: true, SortOrder: 0,
	})
	r2 := store.DisplayRule{
		Name: "后命中", Tenant: "default", MatchType: "all", AirportFrom: "花瓣", AirportTo: "不该生效",
		ScopeNode: true, ScopeGroup: true, ScopeHeader: true, Enabled: true, SortOrder: 10,
	}
	if err := r2.Validate(); err != nil {
		t.Fatal(err)
	}
	r2.ID = 0
	r2.Tenant = "default"
	if _, err := st.UpsertDisplayRule(r2); err != nil {
		t.Fatal(err)
	}
	rules, err := st.ListDisplayRules()
	if err != nil {
		t.Fatal(err)
	}
	gw.SetDisplayRules(rules)

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "auto-token-123456", "clash", "8.8.8.8"))
	body := w.Body.String()
	if !strings.Contains(body, "云帆") {
		t.Fatalf("应执行第一条规则:\n%s", body)
	}
	if strings.Contains(body, "不该生效") {
		t.Fatalf("不应叠加第二条规则:\n%s", body)
	}
}
