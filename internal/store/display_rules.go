package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ----- display_rules: 订阅展示定制规则 -----
//
// 一组规则按 sort_order 排序,同一订阅请求命中的第一条生效(不叠加)。
// match_type:
//   - email_suffix  邮箱后缀,如 auto.com(匹配 xxx@auto.com)
//   - email_exact   邮箱全等
//   - email_keyword 邮箱包含
//   - all           该机场全部用户
type DisplayRule struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`         // 规则名,仅管理面展示
	Tenant       string    `json:"tenant"`       // 机场名,空=全部机场
	MatchType    string    `json:"match_type"`   // email_suffix|email_exact|email_keyword|all
	MatchValue   string    `json:"match_value"`  // 匹配值,all 时忽略
	AirportFrom  string    `json:"airport_from"` // 原机场名(可空)
	AirportTo    string    `json:"airport_to"`   // 新机场名(空=不改)
	Replacements string    `json:"replacements"` // JSON: [{"from","to","regex"}]
	ScopeNode    bool      `json:"scope_node"`   // 改节点名
	ScopeGroup   bool      `json:"scope_group"`  // 改分组名与引用
	ScopeHeader  bool      `json:"scope_header"` // 改响应头文件名/标题
	Enabled      bool      `json:"enabled"`
	SortOrder    int       `json:"sort_order"`
	CreatedTS    time.Time `json:"created_ts"`
	UpdatedTS    time.Time `json:"updated_ts"`
}

// Validate 校验规则字段合法性。
func (r *DisplayRule) Validate() error {
	if r.Name == "" {
		return errors.New("规则名不能为空")
	}
	switch r.MatchType {
	case "email_suffix", "email_exact", "email_keyword":
		if r.MatchValue == "" {
			return errors.New("匹配值不能为空")
		}
	case "all":
	default:
		return errors.New("匹配方式非法")
	}
	if r.AirportTo == "" && r.Replacements == "" {
		return errors.New("至少配置一项:新机场名或关键词替换")
	}
	if r.Replacements != "" {
		var reps []map[string]any
		if err := json.Unmarshal([]byte(r.Replacements), &reps); err != nil {
			return errors.New("关键词替换格式错误")
		}
	}
	if !r.ScopeNode && !r.ScopeGroup && !r.ScopeHeader {
		return errors.New("至少勾选一个作用范围")
	}
	return nil
}

// Matches 判断邮箱是否命中本规则。tenant 不匹配直接 false。
func (r *DisplayRule) Matches(tenant, email string) bool {
	if !r.Enabled {
		return false
	}
	if r.Tenant != "" && r.Tenant != tenant {
		return false
	}
	if r.MatchType == "all" {
		return true
	}
	if email == "" {
		return false
	}
	at := lastIndexByte(email, '@')
	domain := ""
	if at >= 0 && at+1 < len(email) {
		domain = email[at+1:]
	}
	switch r.MatchType {
	case "email_suffix":
		return domain == r.MatchValue || hasSuffixFold(domain, r.MatchValue)
	case "email_exact":
		return eqFold(email, r.MatchValue)
	case "email_keyword":
		return containsFold(email, r.MatchValue)
	}
	return false
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func eqFold(a, b string) bool { return lower(a) == lower(b) }

func hasSuffixFold(s, suffix string) bool {
	if len(suffix) > len(s) {
		return false
	}
	return lower(s[len(s)-len(suffix):]) == lower(suffix)
}

func containsFold(s, sub string) bool {
	if sub == "" {
		return true
	}
	ls, lsub := lower(s), lower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// ----- CRUD -----

func (s *Store) UpsertDisplayRule(r DisplayRule) (int64, error) {
	now := time.Now().UnixMilli()
	scopeN, scopeG, scopeH := b2i(r.ScopeNode), b2i(r.ScopeGroup), b2i(r.ScopeHeader)
	if r.ID > 0 {
		_, err := s.db.Exec(`UPDATE display_rules SET
			name=?, tenant=?, match_type=?, match_value=?,
			airport_from=?, airport_to=?, replacements=?,
			scope_node=?, scope_group=?, scope_header=?,
			enabled=?, sort_order=?, updated_ts=?
			WHERE id=?`,
			r.Name, r.Tenant, r.MatchType, r.MatchValue,
			r.AirportFrom, r.AirportTo, r.Replacements,
			scopeN, scopeG, scopeH, b2i(r.Enabled), r.SortOrder, now, r.ID)
		return r.ID, err
	}
	res, err := s.db.Exec(`INSERT INTO display_rules
		(name, tenant, match_type, match_value, airport_from, airport_to, replacements,
		 scope_node, scope_group, scope_header, enabled, sort_order, created_ts, updated_ts)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Name, r.Tenant, r.MatchType, r.MatchValue,
		r.AirportFrom, r.AirportTo, r.Replacements,
		scopeN, scopeG, scopeH, b2i(r.Enabled), r.SortOrder, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteDisplayRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM display_rules WHERE id=?`, id)
	return err
}

func (s *Store) ListDisplayRules() ([]DisplayRule, error) {
	rows, err := s.db.Query(`SELECT id, name, COALESCE(tenant,''), match_type, COALESCE(match_value,''),
		COALESCE(airport_from,''), COALESCE(airport_to,''), COALESCE(replacements,'[]'),
		scope_node, scope_group, scope_header, enabled, sort_order, created_ts, updated_ts
		FROM display_rules ORDER BY sort_order, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DisplayRule
	for rows.Next() {
		var r DisplayRule
		var sn, sg, sh, en int
		var cts, uts int64
		if err := rows.Scan(&r.ID, &r.Name, &r.Tenant, &r.MatchType, &r.MatchValue,
			&r.AirportFrom, &r.AirportTo, &r.Replacements,
			&sn, &sg, &sh, &en, &r.SortOrder, &cts, &uts); err != nil {
			return nil, err
		}
		r.ScopeNode, r.ScopeGroup, r.ScopeHeader = sn == 1, sg == 1, sh == 1
		r.Enabled = en == 1
		r.CreatedTS = time.UnixMilli(cts)
		r.UpdatedTS = time.UnixMilli(uts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetUserReportByToken 按 token(可限定机场)取上报信息,用于取邮箱。
func (s *Store) GetUserReportByToken(token, tenant string) (*UserReport, error) {
	q := `SELECT token, tenant, COALESCE(uuid,''), COALESCE(email,''),
		traffic_used, traffic_total, wallet_balance, commission_balance,
		COALESCE(user_created_at,''), COALESCE(last_ip,''), COALESCE(last_ua,''),
		COALESCE(site_domain,''), report_count, first_seen, last_seen
		FROM user_reports WHERE token=?`
	args := []any{token}
	if tenant != "" {
		q += ` AND tenant=?`
		args = append(args, tenant)
	}
	q += ` ORDER BY last_seen DESC LIMIT 1`
	var r UserReport
	err := s.db.QueryRow(q, args...).Scan(&r.Token, &r.Tenant, &r.UUID, &r.Email,
		&r.TrafficUsed, &r.TrafficTotal, &r.WalletBalance, &r.CommissionBalance,
		&r.UserCreatedAt, &r.LastIP, &r.LastUA, &r.SiteDomain,
		&r.ReportCount, &r.FirstSeen, &r.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
