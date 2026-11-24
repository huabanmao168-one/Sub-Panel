// Package webui 是管理面 HTTP server,内嵌 HTML/JS,登录后访问。
package webui

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/cloudip"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/geoip"
	"github.com/huabanmao168/SubPanel/internal/proxy"
	"github.com/huabanmao168/SubPanel/internal/rules"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	cfg           *config.Config
	st            *store.Store
	bans          *banlist.List
	hasher        *token.Hasher
	cloud         *cloudip.Matcher
	fetcher       *cloudip.Fetcher
	rules         *rules.Manager
	gw            *proxy.Gateway
	det           *detector.Detector
	bl            *blacklist.Manager
	settingsMu    sync.Mutex
	policyMu      sync.Mutex
	verifiedSince time.Time
	sessionMu     sync.RWMutex
	sessions      map[string]session
	logger        *slog.Logger
}

type session struct {
	user    string
	expires time.Time
}

func NewServer(cfg *config.Config, st *store.Store, bans *banlist.List, hasher *token.Hasher,
	cloud *cloudip.Matcher, fetcher *cloudip.Fetcher,
	rulesMgr *rules.Manager, gw *proxy.Gateway, det *detector.Detector,
	bl *blacklist.Manager, logger *slog.Logger) *Server {
	return &Server{
		cfg:      cfg,
		st:       st,
		bans:     bans,
		hasher:   hasher,
		cloud:    cloud,
		fetcher:  fetcher,
		rules:    rulesMgr,
		gw:       gw,
		det:      det,
		bl:       bl,
		sessions: map[string]session{},
		logger:   logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 静态资源
	sub, _ := fs.Sub(assets, "assets")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))

	// 公开
	mux.HandleFunc("/login", s.loginPage)
	mux.HandleFunc("/api/login", s.apiLogin)
	mux.HandleFunc("/api/logout", s.apiLogout)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })

	// 需要登录
	mux.Handle("/", s.auth(http.HandlerFunc(s.indexPage)))
	mux.Handle("/api/session", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]string{"username": s.cfg.Admin.Username})
	})))
	mux.Handle("/api/summary", s.auth(http.HandlerFunc(s.apiSummary)))
	mux.Handle("/api/events", s.auth(http.HandlerFunc(s.apiEvents)))
	mux.Handle("/api/events/purge", s.auth(http.HandlerFunc(s.apiEventsPurge)))
	mux.Handle("/api/resolved", s.auth(http.HandlerFunc(s.apiResolvedList)))
	mux.Handle("/api/resolved/add", s.auth(http.HandlerFunc(s.apiResolvedAdd)))
	mux.Handle("/api/resolved/remove", s.auth(http.HandlerFunc(s.apiResolvedRemove)))
	mux.Handle("/api/resolved/clear", s.auth(http.HandlerFunc(s.apiResolvedClear)))
	mux.Handle("/api/incidents", s.auth(http.HandlerFunc(s.apiIncidents)))
	mux.Handle("/api/incidents/agg_ip", s.auth(http.HandlerFunc(s.apiIncidentsAggIP)))
	mux.Handle("/api/bans", s.auth(http.HandlerFunc(s.apiBans)))
	mux.Handle("/api/bans/add", s.auth(http.HandlerFunc(s.apiBanAdd)))
	mux.Handle("/api/bans/remove", s.auth(http.HandlerFunc(s.apiBanRemove)))
	mux.Handle("/api/blacklist", s.auth(http.HandlerFunc(s.apiBlacklist)))
	mux.Handle("/api/blacklist/save", s.auth(http.HandlerFunc(s.apiBlacklistSave)))
	mux.Handle("/api/tenants", s.auth(http.HandlerFunc(s.apiTenants)))
	mux.Handle("/api/tenants/save", s.auth(http.HandlerFunc(s.apiTenantSave)))
	mux.Handle("/api/tenants/remove", s.auth(http.HandlerFunc(s.apiTenantRemove)))

	mux.Handle("/api/detect_rules", s.auth(http.HandlerFunc(s.apiDetectRules)))
	mux.Handle("/api/detect_rules/save", s.auth(http.HandlerFunc(s.apiDetectRuleSave)))
	mux.Handle("/api/detect_rules/remove", s.auth(http.HandlerFunc(s.apiDetectRuleRemove)))
	mux.Handle("/api/settings/runtime", s.auth(http.HandlerFunc(s.apiRuntimeSettings)))
	mux.Handle("/api/notifier", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 410, map[string]any{"error": "notifier removed"})
	})))
	mux.Handle("/api/notifier/update", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 410, map[string]any{"error": "notifier removed"})
	})))
	mux.Handle("/api/test-notify", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 410, map[string]any{"error": "notifier removed"})
	})))
	mux.Handle("/api/auth/change_password", s.auth(http.HandlerFunc(s.apiChangePassword)))
	mux.Handle("/api/settings/passthrough", s.auth(http.HandlerFunc(s.apiPassthrough)))

	// IP 白名单
	mux.Handle("/api/ip-whitelist", s.auth(http.HandlerFunc(s.apiIPWhitelistList)))
	mux.Handle("/api/ip-whitelist/add", s.auth(http.HandlerFunc(s.apiIPWhitelistAdd)))
	mux.Handle("/api/ip-whitelist/update", s.auth(http.HandlerFunc(s.apiIPWhitelistUpdate)))
	mux.Handle("/api/ip-whitelist/remove", s.auth(http.HandlerFunc(s.apiIPWhitelistRemove)))

	// UA 黑名单
	mux.Handle("/api/ua-blacklist", s.auth(http.HandlerFunc(s.apiUABlacklistList)))
	mux.Handle("/api/ua-blacklist/add", s.auth(http.HandlerFunc(s.apiUABlacklistAdd)))
	mux.Handle("/api/ua-blacklist/remove", s.auth(http.HandlerFunc(s.apiUABlacklistRemove)))

	// 触发规则运维:清掉某 token 在滑窗里的累计,把误判 token "拉出来"。
	// 下次再触发规则仍会正常拒绝；重置不等于免疫。
	mux.Handle("/api/detector/reset-token", s.auth(http.HandlerFunc(s.apiDetectorResetToken)))

	// 云 IP 库(底层走 GeoIP xdb,保留旧路径兼容)
	mux.Handle("/api/cloud-ip", s.auth(http.HandlerFunc(s.apiCloudIP)))
	mux.Handle("/api/cloud-ip/refresh", s.auth(http.HandlerFunc(s.apiCloudIPRefresh)))
	mux.Handle("/api/cloud-ip/check", s.auth(http.HandlerFunc(s.apiCloudIPCheck)))

	// GeoIP 查询(返回完整地理 + ISP + usage_type)
	mux.Handle("/api/geoip", s.auth(http.HandlerFunc(s.apiGeoIPInfo)))
	mux.Handle("/api/geoip/lookup", s.auth(http.HandlerFunc(s.apiGeoIPLookup)))

	// 用户上报(v2board 外部调用,不走登录,用 secret key)
	// 上报接口已移到订阅网关(80端口) /r/{report_id},不再挂管理面
	// 嫌疑用户分析(需登录)
	mux.Handle("/api/suspects", s.auth(http.HandlerFunc(s.apiSuspects)))
	mux.Handle("/api/suspect-detail", s.auth(http.HandlerFunc(s.apiSuspectDetail)))
	mux.Handle("/api/user-reports", s.auth(http.HandlerFunc(s.apiUserReports)))
	mux.Handle("/api/report-info", s.auth(http.HandlerFunc(s.apiReportInfo)))
	mux.Handle("/api/report-info/save", s.auth(http.HandlerFunc(s.apiReportInfoSave)))

	// 订阅展示定制
	mux.Handle("/api/display-rules", s.auth(http.HandlerFunc(s.apiDisplayRules)))
	mux.Handle("/api/display-rules/save", s.auth(http.HandlerFunc(s.apiDisplayRuleSave)))
	mux.Handle("/api/display-rules/remove", s.auth(http.HandlerFunc(s.apiDisplayRuleRemove)))
	mux.Handle("/api/display-rules/preview", s.auth(http.HandlerFunc(s.apiDisplayPreview)))

	return mux
}

// ---------- 认证 ----------

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil || c.Value == "" {
			s.redirectLogin(w, r)
			return
		}
		s.sessionMu.RLock()
		sess, ok := s.sessions[c.Value]
		s.sessionMu.RUnlock()
		if !ok || time.Now().After(sess.expires) {
			s.redirectLogin(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Username != s.cfg.Admin.Username {
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	pwHash, err := s.st.GetMeta("admin_password_hash")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "读取管理员凭据失败"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(body.Password)); err != nil {
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	// 生成 session id
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	ttl := s.cfg.Admin.SessionTTL.Std()
	s.sessionMu.Lock()
	s.sessions[id] = session{user: body.Username, expires: time.Now().Add(ttl)}
	// gc 过期
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sid")
	if err == nil {
		s.sessionMu.Lock()
		delete(s.sessions, c.Value)
		s.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- API ----------

// SetVerifiedIngressSince is called during startup, before serving requests.
func (s *Server) SetVerifiedIngressSince(since time.Time) { s.verifiedSince = since }

func (s *Server) statsSince(window time.Duration) time.Time {
	since := time.Now().Add(-window)
	if since.Before(s.verifiedSince) {
		return s.verifiedSince
	}
	return since
}

func (s *Server) apiSummary(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	winStr := r.URL.Query().Get("window")
	dur, err := time.ParseDuration(winStr)
	if err != nil || dur <= 0 {
		dur = 24 * time.Hour
	}
	st, err := s.st.Summary(r.Context(), tenant, s.statsSince(dur))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// Top IPs 富化:加地区 + ISP(xdb mmap 查询很轻,Top 10 无压力)
	gi := geoip.Global()
	for i := range st.TopIPs {
		ip := st.TopIPs[i].Key
		if ip == "" {
			continue
		}
		if info := gi.Lookup(ip); info != nil {
			region := ""
			parts := []string{info.Country, info.Province, info.City}
			for _, p := range parts {
				if p != "" && p != "0" {
					if region != "" {
						region += " · "
					}
					region += p
				}
			}
			st.TopIPs[i].Region = region
			if info.ISP != "" && info.ISP != "0" {
				st.TopIPs[i].ISP = info.ISP
			}
		}
	}
	writeJSON(w, 200, st)
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	lookup := q.Get("token") // backward-compatible API; the UI uses the header
	if header := r.Header.Get("X-Subscription-Lookup"); header != "" {
		decoded, err := url.PathUnescape(header)
		if err != nil || len(decoded) > 4096 {
			writeJSON(w, 400, map[string]any{"error": "无效的订阅查询值"})
			return
		}
		lookup = decoded
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	winStr := q.Get("window")
	dur, _ := time.ParseDuration(winStr)
	if dur <= 0 {
		dur = 24 * time.Hour
	}
	f := store.EventFilter{
		Tenant:    q.Get("tenant"),
		ClientIP:  q.Get("ip"),
		TokenHash: s.hasher.Lookup(lookup),
		Action:    q.Get("action"),
		Usage:     strings.ToUpper(strings.TrimSpace(q.Get("usage"))),
		UA:        q.Get("ua"),
		Since:     s.statsSince(dur),
		Limit:     limit,
		Offset:    offset,
	}
	// 默认隐藏白名单 IP 的请求(走 rules.IPWhitelisted,支持 CIDR)。
	// show_whitelist=1 时显示。单 IP 精确查询时也跳过过滤(用户显式要看)。
	hideWL := q.Get("show_whitelist") != "1" && f.ClientIP == ""
	visible := func(e store.Event) bool {
		return !hideWL || e.ClientIP == "" || s.rules == nil || !s.rules.IPWhitelisted(e.ClientIP)
	}
	paged := q.Get("page") == "cursor"
	var next string
	var evs []store.Event
	var err error
	if paged {
		if f.Limit < 1 || f.Limit > 100 {
			f.Limit = 50
		}
		f.Offset = 0
		if cursor := q.Get("cursor"); cursor != "" {
			if f.BeforeTS, f.BeforeID, err = parseEventCursor(cursor); err != nil {
				writeJSON(w, 400, map[string]any{"error": "无效的日志分页游标"})
				return
			}
		}
		evs, next, err = s.eventPage(r.Context(), f, visible)
	} else {
		evs, err = s.st.QueryEvents(r.Context(), f)
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 补省市区 + 国家中文名(DB 里只存了 ISO2,这里实时 lookup)
	type eventOut struct {
		store.Event
		CountryName string `json:"CountryName"`
		Province    string `json:"Province"`
		City        string `json:"City"`
		ASN         string `json:"ASN"`
		Usage       string `json:"Usage"`
	}
	gi := geoip.Global()
	out := make([]eventOut, 0, len(evs))
	for _, e := range evs {
		if !paged && !visible(e) {
			continue
		}
		row := eventOut{Event: e}
		if e.ClientIP != "" {
			if info := gi.Lookup(e.ClientIP); info != nil {
				row.CountryName = info.Country
				row.Province = info.Province
				row.City = info.City
				row.ASN = info.ASN
				row.Usage = info.UsageType
				// 覆盖嵌入 Event.ISP / Event.Country / Event.UsageType
				// (DB 里写入时可能为空,以 xdb 实时为准)
				if info.ISP != "" {
					row.Event.ISP = info.ISP
				}
				if info.ISOCode != "" && row.Event.Country == "" {
					row.Event.Country = info.ISOCode
				}
				if info.UsageType != "" && row.Event.UsageType == "" {
					row.Event.UsageType = info.UsageType
				}
			}
		}
		out = append(out, row)
	}
	if paged {
		writeJSON(w, 200, map[string]any{"items": out, "next_cursor": next})
	} else {
		writeJSON(w, 200, out)
	}
}

// apiEventsPurge 清空请求事件 + 异常事件。
// body: {"tenant":"<name>"} 只清该租户;{"tenant":""} 或 {"all":true} 全清。
// 必须 POST(防误触)。
func (s *Server) apiEventsPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		Tenant string `json:"tenant"`
		All    bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Tenant == "") != body.All {
		writeJSON(w, 400, map[string]any{"error": "请选择指定机场，或显式确认清空全部"})
		return
	}
	tenant := body.Tenant
	evN, inN, err := s.st.PurgeEvents(r.Context(), tenant)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 清日志的同时,把 detector 滑窗状态也归零。
	// 全清(tenant=="")才清滑窗——单租户清不影响其他租户的风控累计。
	if tenant == "" && s.det != nil {
		s.det.ResetAll()
	}
	writeJSON(w, 200, map[string]any{
		"ok":                true,
		"events_deleted":    evN,
		"incidents_deleted": inN,
		"tenant":            tenant,
	})
}

// apiResolvedList GET /api/resolved?tenant=xxx
func (s *Server) apiResolvedList(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	rows, err := s.st.ListResolvedTokens(r.Context(), tenant)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []store.ResolvedToken{}
	}
	writeJSON(w, 200, rows)
}

// apiResolvedAdd POST /api/resolved/add  body:{token, tenant, note}
func (s *Server) apiResolvedAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		Token  string `json:"token"`
		Tenant string `json:"tenant"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Token == "" {
		writeJSON(w, 400, map[string]any{"error": "token is empty"})
		return
	}
	if err := s.st.AddResolvedToken(r.Context(), s.hasher.Lookup(body.Token), body.Tenant, body.Note); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiResolvedRemove POST /api/resolved/remove  body:{token}
func (s *Server) apiResolvedRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.st.RemoveResolvedToken(r.Context(), s.hasher.Lookup(body.Token)); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiResolvedClear POST /api/resolved/clear — 清空全部已处理 token
func (s *Server) apiResolvedClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	if err := s.st.ClearResolvedTokens(r.Context()); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	winStr := q.Get("window")
	dur, _ := time.ParseDuration(winStr)
	if dur <= 0 {
		dur = 7 * 24 * time.Hour
	}
	f := store.IncidentFilter{
		Tenant:    q.Get("tenant"),
		Severity:  q.Get("severity"),
		IP:        q.Get("ip"),
		TokenHash: s.hasher.Lookup(q.Get("token")),
		Action:    q.Get("action"),
		Tag:       q.Get("tag"),
		Keyword:   q.Get("keyword"),
		Since:     s.statsSince(dur),
		Limit:     limit,
		Offset:    offset,
	}
	ins, err := s.st.QueryIncidents(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, ins)
}

// apiIncidentsAggIP 异常事件按 IP 聚合 Top N。
func (s *Server) apiIncidentsAggIP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	winStr := q.Get("window")
	dur, _ := time.ParseDuration(winStr)
	if dur <= 0 {
		dur = 7 * 24 * time.Hour
	}
	f := store.IncidentFilter{
		Tenant:   q.Get("tenant"),
		Severity: q.Get("severity"),
		Action:   q.Get("action"),
		Tag:      q.Get("tag"),
		Keyword:  q.Get("keyword"),
		Since:    s.statsSince(dur),
		Limit:    limit,
	}
	out, err := s.st.AggIncidentsByIP(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if out == nil {
		out = []store.IncidentIPAgg{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiBans(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	bs, err := s.st.ListActiveBans(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, bs)
}

func (s *Server) apiBanAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Reason string `json:"reason"`
		TTL    string `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Target == "" {
		writeJSON(w, 400, map[string]any{"error": "target is required"})
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		t, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad ttl: " + err.Error()})
			return
		}
		ttl = t
	}
	var err error
	switch body.Kind {
	case "ip":
		err = s.bans.AddIP(body.Target, body.Reason, ttl, nil, "manual")
	default:
		writeJSON(w, 400, map[string]any{"error": "kind must be ip(token 黑名单已废弃)"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiBanRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Kind, Target string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var err error
	switch body.Kind {
	case "ip":
		err = s.bans.RemoveIP(body.Target)
	case "token":
		// 老数据兼容:store 里可能还有 token 行,允许直接删 store
		err = s.st.RemoveBan("token", body.Target)
	default:
		writeJSON(w, 400, map[string]any{"error": "kind must be ip|token"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiTenants(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListTenants()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, t := range rows {
		out = append(out, map[string]any{
			"name":           t.Name,
			"subscribe_path": t.SubscribePath,
			"upstream":       t.Upstream,
			"upstream_path":  t.UpstreamPath,
			"report_id":      t.ReportID,
			"enabled":        t.Enabled,
			"updated_ts":     t.UpdatedTS.Unix(),
		})
	}
	writeJSON(w, 200, out)
}

// apiTenantSave: 新增或修改。body 字段:
//   - name (必填,主键)
//   - subscribe_path (必填,以 / 开头,全局唯一)
//   - upstream (必填,合法 URL)
//   - upstream_path (可选)
//   - enabled (默认 true)
//   - original_name (可选,改名时传旧 name)
func (s *Server) apiTenantSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Name          string `json:"name"`
		SubscribePath string `json:"subscribe_path"`
		Upstream      string `json:"upstream"`
		UpstreamPath  string `json:"upstream_path"`
		Enabled       *bool  `json:"enabled"`
		OriginalName  string `json:"original_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.SubscribePath = strings.TrimSpace(body.SubscribePath)
	body.Upstream = strings.TrimSpace(body.Upstream)
	body.UpstreamPath = strings.TrimSpace(body.UpstreamPath)
	if body.Name == "" || body.SubscribePath == "" || body.Upstream == "" {
		writeJSON(w, 400, map[string]any{"error": "机场名、订阅路径、上游地址都必填"})
		return
	}
	if !strings.HasPrefix(body.SubscribePath, "/") || strings.ContainsAny(body.SubscribePath, "?# \t\r\n") {
		writeJSON(w, 400, map[string]any{"error": "订阅路径必须以 / 开头，不能包含空白、查询或片段"})
		return
	}
	if body.UpstreamPath != "" && (!strings.HasPrefix(body.UpstreamPath, "/") || strings.ContainsAny(body.UpstreamPath, "?# \t\r\n")) {
		writeJSON(w, 400, map[string]any{"error": "上游路径必须以 / 开头，不能包含空白、查询或片段"})
		return
	}
	u, err := url.Parse(body.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		writeJSON(w, 400, map[string]any{"error": "上游地址必须为有效的 HTTP(S) URL，不含账号、查询或片段"})
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if err := s.st.SaveTenant(strings.TrimSpace(body.OriginalName), store.TenantRow{
		Name: body.Name, SubscribePath: body.SubscribePath, Upstream: body.Upstream,
		UpstreamPath: body.UpstreamPath, Enabled: enabled,
	}); err != nil {
		writePolicyError(w, err)
		return
	}
	if err := s.reloadGatewayTenants(); err != nil {
		writeJSON(w, 500, map[string]any{"error": "已保存，但网关刷新失败: " + err.Error()})
		return
	}
	if body.OriginalName != "" && body.OriginalName != body.Name && s.gw != nil {
		if err := s.reloadDisplayRules(); err != nil {
			writeJSON(w, 500, map[string]any{"error": "已保存，但展示规则刷新失败"})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func writePolicyError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrRecordNotFound) {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	if errors.Is(err, store.ErrNameConflict) || errors.Is(err, store.ErrTenantPathConflict) {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 500, map[string]any{"error": "数据库保存失败，未提交修改"})
}

func (s *Server) apiTenantRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Name == "" {
		writeJSON(w, 400, map[string]any{"error": "name is required"})
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if err := s.st.DeleteTenant(body.Name); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.reloadGatewayTenants(); err != nil {
		writeJSON(w, 500, map[string]any{"error": "热生效失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// reloadGatewayTenants 从 DB 拉启用的 tenants → 调 gateway.Reload。
func (s *Server) reloadGatewayTenants() error {
	rows, err := s.st.ListTenants()
	if err != nil {
		return err
	}
	out := make([]config.Tenant, 0, len(rows))
	for _, t := range rows {
		if !t.Enabled {
			continue
		}
		out = append(out, config.Tenant{
			Name:          t.Name,
			SubscribePath: t.SubscribePath,
			Upstream:      t.Upstream,
			UpstreamPath:  t.UpstreamPath,
		})
	}
	return s.gw.Reload(out)
}

// -------- IP 白名单 --------

func (s *Server) apiIPWhitelistList(w http.ResponseWriter, r *http.Request) {
	es, err := s.st.ListIPWhitelist()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, es)
}

func (s *Server) apiIPWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Target, Note string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.AddIPWhitelist(body.Target, body.Note); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiIPWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ ID int64 }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.DeleteIPWhitelist(body.ID); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiDetectorResetToken POST body:{token} 清掉该 token 在 detector 滑窗里的累计计数
// + 它触达过的所有 IP 的 ipFreq / ipTokenSet,等于"把这次拉黑的因素全清"。
// 不是免疫：下次触发规则仍会被拒绝。
func (s *Server) apiDetectorResetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Token == "" {
		writeJSON(w, 400, map[string]any{"error": "token required"})
		return
	}
	s.det.ResetToken(s.hasher.Lookup(body.Token))
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiIPWhitelistUpdate POST body:{id,target,note}
func (s *Server) apiIPWhitelistUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		ID     int64  `json:"id"`
		Target string `json:"target"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.ID == 0 || body.Target == "" {
		writeJSON(w, 400, map[string]any{"error": "id and target required"})
		return
	}
	if err := s.rules.UpdateIPWhitelist(body.ID, body.Target, body.Note); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// -------- UA 黑名单 --------

func (s *Server) apiUABlacklistList(w http.ResponseWriter, r *http.Request) {
	rs, err := s.rules.ListUABlacklist()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) apiUABlacklistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Pattern, Note string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.AddUABlacklist(body.Pattern, body.Note); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiUABlacklistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ ID int64 }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.DeleteUABlacklist(body.ID); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// -------- 云 IP 库 --------

func (s *Server) apiCloudIP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cloud.Snapshot())
}

func (s *Server) apiCloudIPRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	if s.fetcher == nil {
		writeJSON(w, 503, map[string]any{"error": "fetcher unavailable"})
		return
	}
	// 异步触发,避免 UI 等太久
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := s.fetcher.RunOnce(ctx); err != nil {
			s.logger.Warn("云 IP 库手动刷新失败", "err", err)
		}
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "started": true})
}

// apiCloudIPCheck:给定 IP,查它是否在云 IP 库里
func (s *Server) apiCloudIPCheck(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	hit, prov := s.cloud.Match(ip)
	writeJSON(w, 200, map[string]any{"ip": ip, "hit": hit, "provider": prov})
}

// -------- GeoIP --------

// apiGeoIPInfo:返回 xdb 加载状态(给 UI 顶栏标"已加载"+版本)
func (s *Server) apiGeoIPInfo(w http.ResponseWriter, r *http.Request) {
	snap := geoip.Global().Snapshot()
	writeJSON(w, 200, map[string]any{
		"loaded":  snap.Loaded,
		"path":    snap.Path,
		"version": snap.Version,
	})
}

// apiGeoIPLookup:GET ?ip=X.X.X.X 返回完整 GeoIP 信息
func (s *Server) apiGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, 400, map[string]any{"error": "缺少 ip 参数"})
		return
	}
	info := geoip.Global().Lookup(ip)
	if info == nil {
		writeJSON(w, 200, map[string]any{"ip": ip, "found": false})
		return
	}
	writeJSON(w, 200, map[string]any{"ip": ip, "found": true, "info": info})
}

// ---------- 页面 ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/login.html")
	if err != nil {
		http.Error(w, "登录页缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/static/") && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "首页缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// 用于将来的 cookie 签名(目前未启用)
func signCookie(key []byte, val string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(val))
	return val + "." + hex.EncodeToString(mac.Sum(nil))
}

// avoid unused warning
var _ = fmt.Sprintf

// apiBlacklist 读取当前黑名单配置。
func (s *Server) apiBlacklist(w http.ResponseWriter, r *http.Request) {
	if s.bl == nil {
		writeJSON(w, 200, map[string]any{
			"oversea_enabled": false,
			"cloud_enabled":   false,
			"browser_enabled": false,
			"cn_idc_enabled":  false,
			"isp_keywords":    []string{},
		})
		return
	}
	sn := s.bl.Get()
	kw := sn.ISPKeywords
	if kw == nil {
		kw = []string{}
	}
	writeJSON(w, 200, map[string]any{
		"oversea_enabled": sn.OverseaEnabled,
		"cloud_enabled":   sn.CloudEnabled,
		"browser_enabled": sn.BrowserEnabled,
		"cn_idc_enabled":  sn.CNIDCEnabled,
		"isp_keywords":    kw,
	})
}

// apiBlacklistSave 保存黑名单配置(整体覆盖)。
func (s *Server) apiBlacklistSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.bl == nil {
		writeJSON(w, 503, map[string]any{"ok": false, "msg": "黑名单未初始化"})
		return
	}
	var body struct {
		OverseaEnabled bool     `json:"oversea_enabled"`
		CloudEnabled   bool     `json:"cloud_enabled"`
		BrowserEnabled bool     `json:"browser_enabled"`
		CNIDCEnabled   bool     `json:"cn_idc_enabled"`
		ISPKeywords    []string `json:"isp_keywords"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "msg": "无效 JSON"})
		return
	}
	if err := s.bl.Update(blacklist.Snapshot{
		OverseaEnabled: body.OverseaEnabled,
		CloudEnabled:   body.CloudEnabled,
		BrowserEnabled: body.BrowserEnabled,
		CNIDCEnabled:   body.CNIDCEnabled,
		ISPKeywords:    body.ISPKeywords,
	}); err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
