package webui

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/store"
)

type detectPreset struct {
	ID          string
	Title       string
	Description string
	Caution     string
	When        config.When
}

func presetCount(window time.Duration, threshold int) *config.Cond {
	return &config.Cond{Window: config.Duration(window), GTE: threshold}
}

var detectPresets = []detectPreset{
	{"preset_token_burst", "订阅高频拉取", "同一订阅 5 分钟内拉取 60 次及以上。", "适合先排查短时重复抓取；客户端异常重试也可能命中。", config.When{TokenFreq: presetCount(5*time.Minute, 60)}},
	{"preset_token_many_ips", "订阅短时多来源", "同一订阅 1 小时内出现 15 个及以上的独立 IP。", "移动网络和动态拨号也可能产生多 IP，不等同于共享账号。", config.When{TokenDistinctIPs: presetCount(time.Hour, 15)}},
	{"preset_ip_burst", "单 IP 高频拉取", "同一 IP 在 5 分钟内拉取 240 次及以上。", "公司、校园和运营商 NAT 出口可能聚合大量正常用户。", config.When{IPFreq: presetCount(5*time.Minute, 240)}},
	{"preset_ip_many_tokens", "单 IP 访问多个订阅", "同一 IP 在 15 分钟内访问 60 个及以上的不同订阅。", "代理、NAT 和企业网络可能共用出口。", config.When{IPDistinctTokens: presetCount(15*time.Minute, 60)}},
	{"preset_cloud_ip", "云厂商来源", "GeoIP 将来源识别为云厂商 IP 时触发。", "依赖 GeoIP；如果用户通过云服务器或代理拉取，不建议直接启用。", config.When{FromCloudIP: true}},
}

type presetView struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Caution     string         `json:"caution"`
	Existing    string         `json:"existing,omitempty"`
	Rule        *detectRuleAPI `json:"rule"`
}

// conditionKey compares effective values without changing the stored spelling
// or list order of an existing policy.
func conditionKey(raw string) string {
	var w config.When
	if json.Unmarshal([]byte(raw), &w) != nil {
		return ""
	}
	for _, field := range []*[]string{&w.CountryIn, &w.CountryNotIn, &w.UsageTypeIn, &w.UsageTypeNotIn, &w.ISPContains} {
		if len(*field) == 0 {
			*field = nil
			continue
		}
		for i, word := range *field {
			(*field)[i] = strings.ToLower(strings.TrimSpace(word))
		}
		slices.Sort(*field)
		*field = slices.Compact(*field)
	}
	data, _ := json.Marshal(w)
	return string(data)
}

func (s *Server) detectPresetCatalog() ([]presetView, []store.DetectRuleRow, error) {
	old, err := s.st.ListDetectRules()
	if err != nil {
		return nil, nil, err
	}
	names, conditions := map[string]bool{}, map[string]string{}
	for _, row := range old {
		names[row.Name] = true
		if key := conditionKey(row.WhenJSON); key != "" && conditions[key] == "" {
			conditions[key] = row.Name
		}
	}
	out := make([]presetView, 0, len(detectPresets))
	rows := make([]store.DetectRuleRow, 0, len(detectPresets))
	for _, p := range detectPresets {
		b, err := json.Marshal(p.When)
		if err != nil {
			return nil, nil, err
		}
		row := store.DetectRuleRow{Name: p.ID, Desc: p.Title + "：" + p.Description, WhenJSON: string(b)}
		api, err := rowToAPI(row)
		if err != nil {
			return nil, nil, err
		}
		existing := conditions[conditionKey(row.WhenJSON)]
		if names[p.ID] {
			existing = p.ID
		}
		out = append(out, presetView{ID: p.ID, Title: p.Title, Description: p.Description, Caution: p.Caution, Existing: existing, Rule: api})
		rows = append(rows, row)
	}
	return out, rows, nil
}

func (s *Server) apiDetectPresets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	views, _, err := s.detectPresetCatalog()
	if err != nil {
		s.logger.Error("load detect presets", "err", err)
		writeJSON(w, 500, map[string]any{"error": "无法读取预设规则"})
		return
	}
	writeJSON(w, 200, views)
}

func (s *Server) apiDetectPresetImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil || len(body.IDs) == 0 || len(body.IDs) > len(detectPresets) {
		writeJSON(w, 400, map[string]any{"error": "请选择要导入的预设规则"})
		return
	}
	requested := map[string]bool{}
	for _, id := range body.IDs {
		requested[id] = true
	}
	for _, preset := range detectPresets {
		delete(requested, preset.ID)
	}
	if len(requested) > 0 {
		writeJSON(w, 400, map[string]any{"error": "包含未知的规则预设，未导入"})
		return
	}

	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	views, rows, err := s.detectPresetCatalog()
	if err != nil {
		s.logger.Error("load presets for import", "err", err)
		writeJSON(w, 500, map[string]any{"error": "无法读取现有规则，未导入"})
		return
	}
	chosen := make([]store.DetectRuleRow, 0, len(body.IDs))
	skipped := make([]string, 0, len(body.IDs))
	for i, v := range views {
		if !slices.Contains(body.IDs, v.ID) {
			continue
		}
		if v.Existing != "" {
			skipped = append(skipped, v.ID)
			continue
		}
		chosen = append(chosen, rows[i])
	}
	added, err := s.st.InsertDetectRulePresets(chosen)
	if err != nil {
		s.logger.Error("import detect presets", "err", err)
		writeJSON(w, 500, map[string]any{"error": "预设导入失败，未修改现有规则"})
		return
	}
	for _, row := range chosen {
		if !slices.Contains(added, row.Name) {
			skipped = append(skipped, row.Name)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "imported": added, "skipped": skipped})
}
