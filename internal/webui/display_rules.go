package webui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/huabanmao168/SubPanel/internal/rewrite"
	"github.com/huabanmao168/SubPanel/internal/store"
)

// GET  /api/display-rules        列表
// POST /api/display-rules/save   {id?, name, tenant, match_type, match_value, airport_from, airport_to,
//
//	replacements, scope_node, scope_group, scope_header, enabled, sort_order}
//
// POST /api/display-rules/remove {id}
// POST /api/display-rules/preview {email, sample, ...规则字段} 返回改写前后
func (s *Server) apiDisplayRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.st.ListDisplayRules()
	if err != nil {
		s.logger.Error("list display rules", "err", err)
		writeJSON(w, 500, map[string]any{"error": "查询失败"})
		return
	}
	if rules == nil {
		rules = []store.DisplayRule{}
	}
	writeJSON(w, 200, rules)
}

func (s *Server) apiDisplayRuleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "只接受 POST"})
		return
	}
	var body struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		Tenant       string `json:"tenant"`
		MatchType    string `json:"match_type"`
		MatchValue   string `json:"match_value"`
		AirportFrom  string `json:"airport_from"`
		AirportTo    string `json:"airport_to"`
		Replacements string `json:"replacements"`
		ScopeNode    bool   `json:"scope_node"`
		ScopeGroup   bool   `json:"scope_group"`
		ScopeHeader  bool   `json:"scope_header"`
		Enabled      bool   `json:"enabled"`
		SortOrder    int    `json:"sort_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误"})
		return
	}
	rule := store.DisplayRule{
		ID: body.ID, Name: strings.TrimSpace(body.Name), Tenant: strings.TrimSpace(body.Tenant),
		MatchType: body.MatchType, MatchValue: strings.TrimSpace(body.MatchValue),
		AirportFrom: strings.TrimSpace(body.AirportFrom), AirportTo: strings.TrimSpace(body.AirportTo),
		Replacements: body.Replacements,
		ScopeNode:    body.ScopeNode, ScopeGroup: body.ScopeGroup, ScopeHeader: body.ScopeHeader,
		Enabled: body.Enabled, SortOrder: body.SortOrder,
	}
	if rule.Replacements == "" {
		rule.Replacements = "[]"
	}
	if err := rule.Validate(); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	id, err := s.st.UpsertDisplayRule(rule)
	if err != nil {
		s.logger.Error("save display rule", "err", err)
		writeJSON(w, 500, map[string]any{"error": "保存失败"})
		return
	}
	s.reloadDisplayRules()
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (s *Server) apiDisplayRuleRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "只接受 POST"})
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 {
		writeJSON(w, 400, map[string]any{"error": "缺少 id"})
		return
	}
	if err := s.st.DeleteDisplayRule(body.ID); err != nil {
		writeJSON(w, 500, map[string]any{"error": "删除失败"})
		return
	}
	s.reloadDisplayRules()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// reloadDisplayRules 把最新规则推给网关,热生效。
func (s *Server) reloadDisplayRules() {
	if s.gw == nil {
		return
	}
	rules, err := s.st.ListDisplayRules()
	if err != nil {
		s.logger.Error("reload display rules", "err", err)
		return
	}
	s.gw.SetDisplayRules(rules)
}

// apiDisplayPreview 用给定规则对样例正文做一次改写,返回前后对比。
// body: {title, filename, sample, airport_from, airport_to, replacements, scope_*}
func (s *Server) apiDisplayPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "只接受 POST"})
		return
	}
	var body struct {
		Title        string `json:"title"`
		Filename     string `json:"filename"`
		Sample       string `json:"sample"`
		AirportFrom  string `json:"airport_from"`
		AirportTo    string `json:"airport_to"`
		Replacements string `json:"replacements"`
		ScopeNode    bool   `json:"scope_node"`
		ScopeGroup   bool   `json:"scope_group"`
		ScopeHeader  bool   `json:"scope_header"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误"})
		return
	}
	if body.Replacements == "" {
		body.Replacements = "[]"
	}
	var reps []rewrite.Replacement
	if err := json.Unmarshal([]byte(body.Replacements), &reps); err != nil {
		writeJSON(w, 400, map[string]any{"error": "关键词替换必须是合法 JSON 数组"})
		return
	}
	opts := &rewrite.Options{
		AirportFrom:  strings.TrimSpace(body.AirportFrom),
		AirportTo:    strings.TrimSpace(body.AirportTo),
		Replacements: reps,
		Scope:        rewrite.Scope{Node: body.ScopeNode, Group: body.ScopeGroup, Header: body.ScopeHeader},
	}
	after, format := body.Sample, "none"
	if opts.Active() {
		res := rewrite.Apply([]byte(body.Sample), "", opts)
		after, format = string(res.Body), res.Format
	}
	resp := map[string]any{
		"ok":     true,
		"before": body.Sample,
		"after":  after,
		"format": format,
	}
	if body.ScopeHeader {
		t, f := body.Title, body.Filename
		if opts.Active() {
			h := http.Header{}
			if t != "" {
				h.Set("profile-title", t)
			}
			if f != "" {
				h.Set("Content-Disposition", `attachment; filename="`+f+`"`)
			}
			if rewrite.ApplyHeaders(h, opts) {
				if v := h.Get("profile-title"); v != "" {
					t = v
				}
				if v := h.Get("Content-Disposition"); v != "" {
					// 只回传文件名部分,前端展示用
					if m := dispFilename(v); m != "" {
						f = m
					} else {
						f = v
					}
				}
			}
		}
		resp["title_before"] = body.Title
		resp["title_after"] = t
		resp["filename_before"] = body.Filename
		resp["filename_after"] = f
	}
	writeJSON(w, 200, resp)
}

// dispFilename 从 Content-Disposition 里取文件名部分(去掉 attachment; 前缀)。
func dispFilename(v string) string {
	if i := strings.Index(v, `filename*=UTF-8''`); i >= 0 {
		rest := v[i+len(`filename*=UTF-8''`):]
		if j := strings.Index(rest, ";"); j >= 0 {
			rest = rest[:j]
		}
		if u, err := url.PathUnescape(strings.TrimSpace(rest)); err == nil {
			return u
		}
		return strings.TrimSpace(rest)
	}
	if i := strings.Index(v, `filename="`); i >= 0 {
		rest := v[i+len(`filename="`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j]
		}
	}
	if i := strings.Index(v, `filename=`); i >= 0 {
		rest := strings.TrimSpace(v[i+len(`filename=`):])
		if j := strings.Index(rest, ";"); j >= 0 {
			rest = rest[:j]
		}
		return strings.Trim(strings.TrimSpace(rest), `"`)
	}
	return ""
}
