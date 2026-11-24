package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/parser"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
)

func newE2E(t *testing.T, observe bool, extraRules ...config.Rule) (*Gateway, *httptest.Server, *store.Store, *banlist.List, func()) {
	t.Helper()

	// fake upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "REAL-SUB-FROM-V2BOARD ip="+r.Header.Get("X-Forwarded-For"))
	}))

	upURL, _ := url.Parse(upstream.URL)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "e2e.db")
	saltPath := filepath.Join(dir, "salt")

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		AdminListen:  "127.0.0.1:0",
		HMACSaltFile: saltPath,
		Storage: config.Storage{
			SQLitePath:         dbPath,
			BatchFlushInterval: config.Duration(50 * time.Millisecond),
			BatchFlushSize:     5,
			Retention: config.Retention{
				Events:    config.Duration(time.Hour),
				Incidents: config.Duration(time.Hour),
			},
		},
		RealIP: config.RealIP{
			TrustProxies: []string{"127.0.0.1"},
			TrustHeaders: []string{"X-Real-IP"},
		},
		Paths: config.Paths{},
		Tenants: []config.Tenant{
			{Name: "default", Host: "sub.example.com", SubscribePath: "/sub/cat", Upstream: upURL.String()},
		},
		Detector: config.DetectorCfg{
			ObserveOnly: observe,
			Rules: append([]config.Rule{
				{
					Name: "tf_red", When: config.When{TokenFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 5}},
				},
				{
					Name: "ip_red", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 100}},
				},
			}, extraRules...),
		},
	}

	salt, err := token.LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	hasher := token.NewHasher(salt)
	st, err := store.Open(dbPath, 50*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	bans := banlist.New(st)
	_ = bans.LoadFromStore(context.Background())
	det, err := detector.New(&cfg.Detector)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw, err := NewGateway(cfg, hasher, st, bans, det, logger)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		upstream.Close()
		_ = st.Close()
		_ = os.RemoveAll(dir)
	}
	return gw, upstream, st, bans, cleanup
}

func mkSubReq(host, ua, tok, flag, realIP string) *http.Request {
	q := url.Values{}
	if tok != "" {
		q.Set("token", tok)
	}
	if flag != "" {
		q.Set("flag", flag)
	}
	r := httptest.NewRequest("GET", "http://"+host+"/sub/cat?"+q.Encode(), nil)
	r.Host = host
	r.RemoteAddr = "127.0.0.1:55555"
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	if realIP != "" {
		r.Header.Set("X-Real-IP", realIP)
	}
	return r
}

func TestE2EPassNormalRequest(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "user1", "clash", "8.8.8.8"))

	if w.Code != 200 {
		t.Errorf("status: %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Errorf("did not reach upstream: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "8.8.8.8") {
		t.Errorf("X-Forwarded-For not propagated: %q", w.Body.String())
	}
}

func TestE2EForwardsFlagToUpstreamAndKeepsEventFlag(t *testing.T) {
	var upstreamQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "forward-flag.db")
	saltPath := filepath.Join(dir, "salt")
	cfg := &config.Config{
		Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", HMACSaltFile: saltPath,
		Storage: config.Storage{
			SQLitePath: dbPath, BatchFlushInterval: config.Duration(50 * time.Millisecond), BatchFlushSize: 1,
			Retention: config.Retention{Events: config.Duration(time.Hour), Incidents: config.Duration(time.Hour)},
		},
		RealIP:   config.RealIP{TrustProxies: []string{"127.0.0.1"}, TrustHeaders: []string{"X-Real-IP"}},
		Tenants:  []config.Tenant{{Name: "default", Host: "sub.example.com", SubscribePath: "/sub/cat", Upstream: upURL.String()}},
		Detector: config.DetectorCfg{ObserveOnly: true},
	}
	salt, err := token.LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath, 50*time.Millisecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bans := banlist.New(st)
	det, err := detector.New(&cfg.Detector)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGateway(cfg, token.NewHasher(salt), st, bans, det, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://sub.example.com/sub/cat?token=user1&flag=general&foo=bar", nil)
	req.Host = "sub.example.com"
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set("User-Agent", "ClashforWindows/0.20")
	req.Header.Set("X-Real-IP", "8.8.8.8")
	gw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(upstreamQuery, "flag=general") || !strings.Contains(upstreamQuery, "token=user1") || !strings.Contains(upstreamQuery, "foo=bar") {
		t.Fatalf("upstream query mismatch: %q", upstreamQuery)
	}

	time.Sleep(100 * time.Millisecond)
	evs, err := st.QueryEvents(context.Background(), store.EventFilter{Tenant: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("event not persisted")
	}
	if evs[0].Flag != "general" {
		t.Fatalf("panel event should keep original flag, got %q", evs[0].Flag)
	}
}

func TestE2EUnknownTenantReturns404(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	// Host 头不再参与路由,unknown 应该改测"路径不匹配 → 404"
	w := httptest.NewRecorder()
	r := mkSubReq("sub.example.com", "ClashforWindows/0.20", "u", "clash", "")
	r.URL.Path = "/sub/nope" // 没配置的路径
	gw.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("expected 404 for unknown path, got %d", w.Code)
	}
}

func TestE2ELumiUAEncryptsSubscription(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	const tok = "user-lumi-token-12345"
	w := httptest.NewRecorder()
	// lumi 不要求在 UA 开头,只要任意位置包含 lumi 即触发。
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "Clash/1.0 lumi android", tok, "clash", "8.8.8.8"))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	body := strings.TrimSpace(w.Body.String())
	if _, err := base64.StdEncoding.DecodeString(body); err != nil {
		t.Fatalf("lumi response should be base64 ciphertext, err=%v body=%q", err, body)
	}
	if strings.Contains(body, "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("encrypted body leaked plaintext: %q", body)
	}
	plain, ok := decryptLumiSubscriptionForTest(&parser.Request{Token: tok}, w.Body.Bytes())
	if !ok {
		t.Fatal("failed to decrypt lumi response with same token")
	}
	if !strings.Contains(string(plain), "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("decrypted body mismatch: %q", string(plain))
	}
	if _, ok := decryptLumiSubscriptionForTest(&parser.Request{Token: "other-token-123456"}, w.Body.Bytes()); ok {
		t.Fatal("lumi response decrypted with wrong token; key must include token")
	}
}

func TestE2ELumiCompatibilityCanBeDisabled(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()
	gw.cfg.DisableLumi = true
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "lumi android", "user-lumi-token-12345", "clash", "8.8.8.8"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Fatal("disabling Lumi should return the normal subscription")
	}
}

func TestLumiEncryptsExistingBase64SubscriptionAsBytes(t *testing.T) {
	const tok = "base64-token-1234"
	// v2board 普通订阅常见形态:响应体本身就是 base64 节点列表。
	inner := base64.StdEncoding.EncodeToString([]byte("ss://aaaa@example.com:443#hk\n"))
	body, ok := encryptLumiSubscription(&parser.Request{Token: tok}, []byte(inner))
	if !ok {
		t.Fatal("encrypt failed")
	}
	if strings.Contains(string(body), inner) || strings.Contains(string(body), "ss://") {
		t.Fatalf("ciphertext leaked original subscription: %q", string(body))
	}
	plain, ok := decryptLumiSubscriptionForTest(&parser.Request{Token: tok}, body)
	if !ok {
		t.Fatal("decrypt failed")
	}
	if string(plain) != inner {
		t.Fatalf("AES layer should wrap original base64 body as-is, got %q want %q", string(plain), inner)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(plain))
	if err != nil || !strings.Contains(string(decoded), "ss://aaaa@example.com") {
		t.Fatalf("inner base64 subscription corrupted after decrypt: decoded=%q err=%v", string(decoded), err)
	}
}

func TestE2ELumiUsesPathTokenWhenQueryTokenMissing(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	const tok = "path-token-123456"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://sub.example.com/sub/cat/"+tok+"?flag=clash", nil)
	r.Host = "sub.example.com"
	r.RemoteAddr = "127.0.0.1:55555"
	r.Header.Set("User-Agent", "lumi app")
	r.Header.Set("X-Real-IP", "8.8.8.8")
	gw.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	plain, ok := decryptLumiSubscriptionForTest(&parser.Request{Token: tok}, w.Body.Bytes())
	if !ok {
		t.Fatal("failed to decrypt lumi response with token extracted from path")
	}
	if !strings.Contains(string(plain), "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("decrypted body mismatch: %q", string(plain))
	}
}

func TestE2EBadUARejected(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()
	gw.SetUABlacklist(func(ua string) bool { return strings.HasPrefix(ua, "curl/") })
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "curl/8.0", "user1", "ss", "9.9.9.9"))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Fatal("blocked UA must get 403 without the upstream body")
	}
}

func TestE2EHighTokenFreqRedDenyAndBan(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	// The fifth request reaches the frequency threshold.
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "samesubtoken", "clash", "10.0.0.1"))
	}
	time.Sleep(50 * time.Millisecond)
	// A rule hit rejects the subscription before contacting its upstream.
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "samesubtoken", "clash", "10.0.0.1"))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for rule hit, got %d", w.Code)
	}
	// banlist 不再被 SevRed 自动加入,bans 应当为空
	if banned, _ := bans.CheckIP("10.0.0.1"); banned {
		t.Errorf("banlist 不再自动封禁,但 10.0.0.1 被加入了")
	}
}

func TestE2EObserveOnly(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, true)
	defer cleanup()

	// A request with no configured matching rule passes.
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "curl/8.0", "tok", "ss", ""))
	if w.Code != 200 {
		t.Errorf("status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Errorf("observe_only should pass through, got %q", w.Body.String())
	}
}

func TestE2EManualBan(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	_ = bans.AddIP("7.7.7.7", "manual", time.Hour, nil, "test")

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "t", "clash", "7.7.7.7"))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for banned IP, got %d", w.Code)
	}
}

func TestE2EEventsPersisted(t *testing.T) {
	gw, _, st, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "tttt", "clash", "8.8.8.8"))

	// 等 batch flush
	time.Sleep(200 * time.Millisecond)
	evs, err := st.QueryEvents(context.Background(), store.EventFilter{Tenant: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("event not persisted")
	}
	e := evs[0]
	if e.ClientIP != "8.8.8.8" || e.Action != "pass" || e.Flag != "clash" {
		t.Errorf("unexpected event: %+v", e)
	}
	if e.TokenHash != gw.hasher.Hash("tttt") || strings.Contains(e.Path, "tttt") {
		t.Fatal("event leaked the raw subscription credential or lost its identifier")
	}
}

func TestDeniedSubscriptionNeverContactsUpstream(t *testing.T) {
	gw, upstream, st, _, cleanup := newE2E(t, false)
	defer cleanup()
	// If an upstream request occurs at all, it would fail (and must not become a 502).
	upstream.Close()
	gw.SetUABlacklist(func(string) bool { return true })
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "lumi android", "fixture-token", "", "192.0.2.9"))
	if w.Code != http.StatusForbidden || w.Body.String() != "Forbidden\n" {
		t.Fatalf("expected direct 403, got %d", w.Code)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		incidents, err := st.AggIncidentsByIP(context.Background(), store.IncidentFilter{Action: "deny"})
		if err != nil {
			t.Fatal(err)
		}
		if len(incidents) == 1 && incidents[0].Count == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("denial incident was not written")
}
