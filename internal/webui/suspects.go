package webui

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/geoip"
	"github.com/huabanmao168/SubPanel/internal/store"
)

// POST /r/{report_id} — v2board 上报接口(不走登录,用 secret key 鉴权)
// 挂在订阅网关(80端口),路径不暴露机场名,用随机 report_id。
func (s *Server) apiReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}

	// 鉴权: X-Report-Key header (secret 存在 meta 表)
	secret, err := s.st.GetMeta("report_secret")
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "report settings unavailable"})
		return
	}
	if secret != "" {
		key := r.Header.Get("X-Report-Key")
		if subtle.ConstantTimeCompare([]byte(key), []byte(secret)) != 1 {
			writeJSON(w, 403, map[string]any{"error": "invalid report key"})
			return
		}
	}

	// 从路径提取 report_id: /r/{report_id}
	reportID := strings.TrimPrefix(r.URL.Path, "/r/")
	if reportID == "" || reportID == r.URL.Path {
		writeJSON(w, 400, map[string]any{"error": "missing report_id in path"})
		return
	}

	// 通过 report_id 查 tenant
	tenant, err := s.st.GetTenantByReportID(reportID)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "unknown report_id"})
		return
	}

	var body struct {
		Token             string `json:"token"`
		UUID              string `json:"uuid"`
		Email             string `json:"email"`
		TrafficUsed       int64  `json:"traffic_used"`
		TrafficTotal      int64  `json:"traffic_total"`
		WalletBalance     int64  `json:"wallet_balance"`
		CommissionBalance int64  `json:"commission_balance"`
		UserCreatedAt     string `json:"user_created_at"`
		IP                string `json:"ip"`
		UserAgent         string `json:"user_agent"`
		SiteDomain        string `json:"site_domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "无效的上报数据"})
		return
	}
	if body.Token == "" {
		writeJSON(w, 400, map[string]any{"error": "token required"})
		return
	}

	report := store.UserReport{
		Token:             s.hasher.Hash(body.Token),
		Tenant:            tenant.Name,
		UUID:              body.UUID,
		Email:             body.Email,
		TrafficUsed:       body.TrafficUsed,
		TrafficTotal:      body.TrafficTotal,
		WalletBalance:     body.WalletBalance,
		CommissionBalance: body.CommissionBalance,
		UserCreatedAt:     body.UserCreatedAt,
		LastIP:            body.IP,
		LastUA:            body.UserAgent,
		SiteDomain:        body.SiteDomain,
	}
	if err := s.st.UpsertUserReport(report); err != nil {
		s.logger.Error("upsert user report", "err", err)
		writeJSON(w, 500, map[string]any{"error": "store error"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ReportHandler 返回挂在订阅网关(80端口)的上报路由 handler。
func (s *Server) ReportHandler() http.Handler {
	return http.HandlerFunc(s.apiReport)
}

// GET /api/suspects?tenant=xxx&window=24h — 嫌疑用户列表(需登录)
func (s *Server) apiSuspects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if q.Get("view") != "review" {
		limit = 100
	}
	term := strings.TrimSpace(q.Get("search"))
	if len(term) > 256 {
		writeJSON(w, 400, map[string]any{"error": "搜索条件过长"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	page, err := s.st.QuerySuspects(ctx, store.SuspectFilter{
		Tenant: q.Get("tenant"), Since: s.statsSince(suspectWindow(q.Get("window"))), Search: term,
		Sort: q.Get("sort"), Signal: q.Get("signal"), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.logger.Error("query suspects", "err", err)
		writeJSON(w, 500, map[string]any{"error": "查询用户行为失败，请稍后重试"})
		return
	}
	if q.Get("view") == "review" {
		writeJSON(w, 200, page)
		return
	}
	writeJSON(w, 200, page.Items)
}

func suspectWindow(raw string) time.Duration {
	dur, err := time.ParseDuration(raw)
	if err != nil || dur <= 0 {
		return 168 * time.Hour
	}
	return min(dur, 30*24*time.Hour)
}

// GET /api/user-reports?tenant=xxx — 原始上报列表(需登录)
func (s *Server) apiUserReports(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	reports, err := s.st.ListUserReports(tenant)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "query error"})
		return
	}
	if reports == nil {
		reports = []store.UserReport{}
	}
	writeJSON(w, 200, reports)
}

// GET /api/report-info — 返回上报接入信息(secret + 订阅网关监听地址),供机场管理页展示
func (s *Server) apiReportInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	secret, err := s.st.GetMeta("report_secret")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "读取上报设置失败"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"report_secret":   secret,
		"sub_listen":      s.cfg.Listen,
		"report_base_url": s.cfg.ReportBaseURL,
	})
}

// GET /api/suspect-detail?token=xxx&tenant=xxx&window=168h — 单用户详情(所有IP+UA)
func (s *Server) apiSuspectDetail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	tenant := r.URL.Query().Get("tenant")
	if token == "" {
		writeJSON(w, 400, map[string]any{"error": "token required"})
		return
	}
	since := s.statsSince(suspectWindow(r.URL.Query().Get("window")))
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	detail, err := s.st.QuerySuspectDetail(ctx, s.hasher.Lookup(token), tenant, since)
	if err != nil {
		s.logger.Error("query suspect detail", "err", err)
		writeJSON(w, 500, map[string]any{"error": "query error"})
		return
	}
	// 实时 geoip 富化:补省市 + ASN + UsageType
	gi := geoip.Global()
	enrich := func(d *store.IPDetail) {
		info := gi.Lookup(d.IP)
		if info == nil {
			return
		}
		parts := []string{}
		for _, p := range []string{info.Country, info.Province, info.City} {
			if p != "" && p != "0" {
				parts = append(parts, p)
			}
		}
		d.Country = strings.Join(parts, " · ")
		if info.ISP != "" && info.ISP != "0" {
			d.ISP = info.ISP
		}
		d.ASN = info.ASN
		d.UsageType = info.UsageType
	}
	for i := range detail.IPs {
		enrich(&detail.IPs[i])
	}
	writeJSON(w, 200, detail)
}

// POST /api/report-info/save — 保存上报密钥；显式传空字符串才清除。
func (s *Server) apiReportInfoSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		ReportSecret *string `json:"report_secret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil || body.ReportSecret == nil {
		writeJSON(w, 400, map[string]any{"error": "必须提供 report_secret"})
		return
	}
	var err error
	if *body.ReportSecret == "" {
		err = s.st.DeleteMeta("report_secret")
	} else {
		err = s.st.SetMeta("report_secret", *body.ReportSecret)
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "保存上报设置失败"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
