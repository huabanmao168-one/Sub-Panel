// 触发规则管理 API:增删改启停 + DB 反序列化 + 推到 detector 热生效。
//
// 字段层(JSON):
//   - name / desc:             字符串
//   - enabled:                 bool
//   - sort_order:              int(列表展示顺序)
//   - 条件:                   4 个 *Cond + 高级 GeoIP/云 IP 字段
//
// 校验:
//   - name 必填 + 唯一
//   - 至少一个条件不为空(否则规则等于死规则,不允许保存)
//   - 任何 Cond 的 window/gte 不能为 0
package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/geoip"
	"github.com/huabanmao168/SubPanel/internal/store"
)

// detectRuleAPI:对外 JSON 形态,字段平铺,前端表单填起来方便。
// 时长统一用秒数(yaml 用 Duration 字符串,这里 API 端用整数秒便于前端处理)。
type detectRuleAPI struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
	// Severity 已废弃,API 不再返回也不再接收;命中规则统一拒绝请求。
	Enabled   bool `json:"enabled"`
	SortOrder int  `json:"sort_order"`

	// 计数条件：窗口与阈值都大于零才启用，两项均为零则忽略。
	TokenFreqWindowSec        int `json:"token_freq_window_sec"`
	TokenFreqGTE              int `json:"token_freq_gte"`
	IPFreqWindowSec           int `json:"ip_freq_window_sec"`
	IPFreqGTE                 int `json:"ip_freq_gte"`
	TokenDistinctIPsWindowSec int `json:"token_distinct_ips_window_sec"`
	TokenDistinctIPsGTE       int `json:"token_distinct_ips_gte"`
	IPDistinctTokensWindowSec int `json:"ip_distinct_tokens_window_sec"`
	IPDistinctTokensGTE       int `json:"ip_distinct_tokens_gte"`

	// 云 IP / GeoIP / ISP(高级,可选)
	FromCloudIP    bool     `json:"from_cloud_ip"`
	CountryIn      []string `json:"country_in"`
	CountryNotIn   []string `json:"country_not_in"`
	UsageTypeIn    []string `json:"usage_type_in"`
	UsageTypeNotIn []string `json:"usage_type_not_in"`
	ISPContains    []string `json:"isp_contains"`

	UpdatedTS int64  `json:"updated_ts"`
	Issue     string `json:"issue,omitempty"`
}

// rowToAPI 把 DB 行转成 API 对外格式。
func rowToAPI(r store.DetectRuleRow) (*detectRuleAPI, error) {
	var w config.When
	if err := json.Unmarshal([]byte(r.WhenJSON), &w); err != nil {
		return nil, err
	}
	a := &detectRuleAPI{
		Name:           r.Name,
		Desc:           r.Desc,
		Enabled:        r.Enabled,
		SortOrder:      r.SortOrder,
		FromCloudIP:    w.FromCloudIP,
		CountryIn:      w.CountryIn,
		CountryNotIn:   w.CountryNotIn,
		UsageTypeIn:    w.UsageTypeIn,
		UsageTypeNotIn: w.UsageTypeNotIn,
		ISPContains:    w.ISPContains,
		UpdatedTS:      r.UpdatedTS.Unix(),
	}
	if w.TokenFreq != nil {
		a.TokenFreqWindowSec = int(w.TokenFreq.Window.Std().Seconds())
		a.TokenFreqGTE = w.TokenFreq.GTE
	}
	if w.IPFreq != nil {
		a.IPFreqWindowSec = int(w.IPFreq.Window.Std().Seconds())
		a.IPFreqGTE = w.IPFreq.GTE
	}
	if w.TokenDistinctIPs != nil {
		a.TokenDistinctIPsWindowSec = int(w.TokenDistinctIPs.Window.Std().Seconds())
		a.TokenDistinctIPsGTE = w.TokenDistinctIPs.GTE
	}
	if w.IPDistinctTokens != nil {
		a.IPDistinctTokensWindowSec = int(w.IPDistinctTokens.Window.Std().Seconds())
		a.IPDistinctTokensGTE = w.IPDistinctTokens.GTE
	}
	return a, nil
}

// apiToWhen 把对外平铺字段还原成 config.When。
func apiToWhen(a *detectRuleAPI) (config.When, error) {
	w := config.When{
		FromCloudIP:    a.FromCloudIP,
		CountryIn:      trimList(a.CountryIn),
		CountryNotIn:   trimList(a.CountryNotIn),
		UsageTypeIn:    trimList(a.UsageTypeIn),
		UsageTypeNotIn: trimList(a.UsageTypeNotIn),
		ISPContains:    trimList(a.ISPContains),
	}
	if len(w.CountryIn) > 0 && len(w.CountryNotIn) > 0 {
		return w, fmt.Errorf("国家条件只能选择「在名单内」或「不在名单内」，不能同时配置")
	}
	if len(w.UsageTypeIn) > 0 && len(w.UsageTypeNotIn) > 0 {
		return w, fmt.Errorf("IP 用途条件只能选择「在名单内」或「不在名单内」，不能同时配置")
	}
	// 计数条件:窗口和阈值必须同时给,否则视为关闭该条件
	mkCond := func(winSec, gte int, name string) (*config.Cond, error) {
		if winSec == 0 && gte == 0 {
			return nil, nil
		}
		if winSec <= 0 || gte <= 0 || int64(winSec) > int64(365*24*time.Hour/time.Second) {
			return nil, fmt.Errorf("%s: 窗口和阈值必须同时大于 0，窗口最长 365 天", name)
		}
		return &config.Cond{
			Window: config.Duration(time.Duration(winSec) * time.Second),
			GTE:    gte,
		}, nil
	}
	var err error
	if w.TokenFreq, err = mkCond(a.TokenFreqWindowSec, a.TokenFreqGTE, "单 token 频次"); err != nil {
		return w, err
	}
	if w.IPFreq, err = mkCond(a.IPFreqWindowSec, a.IPFreqGTE, "单 IP 频次"); err != nil {
		return w, err
	}
	if w.TokenDistinctIPs, err = mkCond(a.TokenDistinctIPsWindowSec, a.TokenDistinctIPsGTE, "单 token 多 IP"); err != nil {
		return w, err
	}
	if w.IPDistinctTokens, err = mkCond(a.IPDistinctTokensWindowSec, a.IPDistinctTokensGTE, "单 IP 多 token"); err != nil {
		return w, err
	}
	// 至少一个条件不为空
	if w.TokenFreq == nil && w.IPFreq == nil && w.TokenDistinctIPs == nil && w.IPDistinctTokens == nil &&
		!w.FromCloudIP && len(w.CountryIn) == 0 && len(w.CountryNotIn) == 0 &&
		len(w.UsageTypeIn) == 0 && len(w.UsageTypeNotIn) == 0 && len(w.ISPContains) == 0 {
		return w, fmt.Errorf("至少配置一个触发条件")
	}
	return w, nil
}

func trimList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Server) detectWindowCapacity() time.Duration {
	if s.det != nil {
		return s.det.MaxWindow()
	}
	return detector.DefaultMaxWindow
}

func (s *Server) validateRuleActivation(when config.When, enabled bool) error {
	if when.MaxWindow() > s.detectWindowCapacity() {
		return fmt.Errorf("规则窗口超过当前容量 %s，未应用修改", s.detectWindowCapacity())
	}
	if enabled && when.MaxWindow() == 0 && !geoip.Global().Loaded() {
		return fmt.Errorf("这条规则只有 GeoIP 条件。GeoIP 数据库未加载，请先配置 GeoIP，或保存为停用")
	}
	return nil
}

func (s *Server) apiDetectRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rows, err := s.st.ListDetectRules()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	out := make([]*detectRuleAPI, 0, len(rows))
	for _, row := range rows {
		a, err := rowToAPI(row)
		if err != nil {
			a = &detectRuleAPI{Name: row.Name, Desc: row.Desc, Enabled: row.Enabled, SortOrder: row.SortOrder, UpdatedTS: row.UpdatedTS.Unix(), Issue: "现有条件无法读取，请检查或重新编辑"}
		} else if _, err := apiToWhen(a); err != nil {
			a.Issue = err.Error()
		}
		out = append(out, a)
	}
	if r.URL.Query().Get("view") == "editor" {
		writeJSON(w, 200, map[string]any{"rules": out, "geoip_ready": geoip.Global().Loaded(),
			"max_window_sec": int(s.detectWindowCapacity().Seconds()), "resolution_sec": int(detector.WindowResolution.Seconds())})
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiDetectRuleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		detectRuleAPI
		OriginalName string `json:"original_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "规则内容无效"})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Desc = strings.TrimSpace(body.Desc)
	if body.Name == "" {
		writeJSON(w, 400, map[string]any{"error": "规则名必填"})
		return
	}
	when, err := apiToWhen(&body.detectRuleAPI)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.validateRuleActivation(when, body.Enabled); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	buf, err := json.Marshal(when)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "序列化条件失败: " + err.Error()})
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if err := s.st.SaveDetectRule(strings.TrimSpace(body.OriginalName), store.DetectRuleRow{
		Name:      body.Name,
		Desc:      body.Desc,
		Severity:  "", // 已废弃,DB 列保留兼容
		WhenJSON:  string(buf),
		Enabled:   body.Enabled,
		SortOrder: body.SortOrder,
	}); err != nil {
		writePolicyError(w, err)
		return
	}
	if err := s.reloadDetectRules(); err != nil {
		writeJSON(w, 500, map[string]any{"error": "热生效失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiDetectRuleState changes only the enabled bit, preserving the original rule.
func (s *Server) apiDetectRuleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Name    string `json:"name"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" || body.Enabled == nil {
		writeJSON(w, 400, map[string]any{"error": "必须提供规则名称和启用状态"})
		return
	}
	name := strings.TrimSpace(body.Name)
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if *body.Enabled {
		rows, err := s.st.ListDetectRules()
		if err != nil {
			writePolicyError(w, err)
			return
		}
		found := false
		for _, row := range rows {
			if row.Name != name {
				continue
			}
			found = true
			a, err := rowToAPI(row)
			if err != nil {
				writeJSON(w, 400, map[string]any{"error": "无法读取规则条件，请先编辑修正"})
				return
			}
			when, err := apiToWhen(a)
			if err == nil {
				err = s.validateRuleActivation(when, true)
			}
			if err != nil {
				writeJSON(w, 400, map[string]any{"error": err.Error()})
				return
			}
			break
		}
		if !found {
			writePolicyError(w, store.ErrRecordNotFound)
			return
		}
	}
	if err := s.st.SetDetectRuleEnabled(name, *body.Enabled); err != nil {
		writePolicyError(w, err)
		return
	}
	if err := s.reloadDetectRules(); err != nil {
		s.logger.Error("reload toggled detect rule", "err", err)
		writeJSON(w, 500, map[string]any{"error": "状态已保存，但运行时规则刷新失败"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": *body.Enabled})
}

func (s *Server) apiDetectRuleRemove(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, 400, map[string]any{"error": "name 必填"})
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if err := s.st.DeleteDetectRule(body.Name); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.reloadDetectRules(); err != nil {
		writeJSON(w, 500, map[string]any{"error": "热生效失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// reloadDetectRules 从 DB 读启用的规则,推到 detector 热生效。
func (s *Server) reloadDetectRules() error {
	if s.det == nil {
		return nil
	}
	rows, err := s.st.ListDetectRules()
	if err != nil {
		return err
	}
	out := make([]config.Rule, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		var w config.When
		if err := json.Unmarshal([]byte(r.WhenJSON), &w); err != nil {
			return fmt.Errorf("规则 %s 反序列化失败: %w", r.Name, err)
		}
		out = append(out, config.Rule{
			Name: r.Name,
			Desc: r.Desc,
			When: w,
		})
	}
	s.det.SetRules(out)
	return nil
}
