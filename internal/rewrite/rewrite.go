// Package rewrite 按规则改写订阅下发的「展示名称」,不触碰任何连接参数。
//
// 支持三种结构:
//   - Clash / mihomo YAML:只改 proxies[].name、proxy-groups[].name 与分组内的节点引用
//   - Base64 / 明文 URI 列表:只改 #备注 与 vmess 的 ps 字段
//   - sing-box JSON:只改 outbounds[].tag 及相关引用
//
// 识别不了的格式退化为全文替换(替换表已由管理员限定为品牌名/地区名等词,
// 不会包含 server / uuid / password 这类连接参数)。
package rewrite

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Replacement 一条关键词替换。
type Replacement struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Regex bool   `json:"regex"`
}

// Scope 作用范围开关。
type Scope struct {
	Node   bool `json:"node"`   // 节点名
	Group  bool `json:"group"`  // 分组名与分组内引用
	Header bool `json:"header"` // 文件名 / profile-title 等响应头
}

// Options 一次改写使用的参数。
type Options struct {
	AirportFrom  string        `json:"airport_from"` // 原机场名,可空
	AirportTo    string        `json:"airport_to"`   // 新机场名,空=不改名
	Replacements []Replacement `json:"replacements"`
	Scope        Scope         `json:"scope"`
}

// Active 是否配置了任何改写动作。
func (o *Options) Active() bool {
	if o == nil {
		return false
	}
	if o.AirportTo != "" {
		return true
	}
	for _, r := range o.Replacements {
		if r.From != "" {
			return true
		}
	}
	return false
}

// compiled 预编译后的替换器。
type compiled struct {
	plain []Replacement
	res   []struct {
		re *regexp.Regexp
		to string
	}
	airportFrom string
	airportTo   string
}

func (o *Options) compile() *compiled {
	c := &compiled{airportFrom: o.AirportFrom, airportTo: o.AirportTo}
	for _, r := range o.Replacements {
		if r.From == "" {
			continue
		}
		if r.Regex {
			re, err := regexp.Compile(r.From)
			if err != nil {
				// 正则写错就当作普通字符串处理,不让整次下发失败
				c.plain = append(c.plain, Replacement{From: r.From, To: r.To})
				continue
			}
			c.res = append(c.res, struct {
				re *regexp.Regexp
				to string
			}{re, r.To})
			continue
		}
		c.plain = append(c.plain, r)
	}
	return c
}

// rename 对单个名称字符串套用全部替换。
func (c *compiled) rename(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, r := range c.plain {
		out = strings.ReplaceAll(out, r.From, r.To)
	}
	for _, r := range c.res {
		out = r.re.ReplaceAllString(out, r.to)
	}
	return out
}

// renameAirport 只处理「原机场名 → 新机场名」这一条。
func (c *compiled) renameAirport(s string) string {
	if c.airportTo == "" || s == "" {
		return s
	}
	if c.airportFrom == "" {
		return s
	}
	return strings.ReplaceAll(s, c.airportFrom, c.airportTo)
}

// all 名称字段的完整改写:先机场名,再关键词。
func (c *compiled) all(s string) string {
	return c.rename(c.renameAirport(s))
}

// body 改写后的结果。
type Result struct {
	Body   []byte
	Format string // clash | uri | singbox | text | none
}

// Apply 按格式识别结果改写订阅正文。
// 任何一步失败都返回原始正文,保证下发不中断。
func Apply(body []byte, contentType string, o *Options) Result {
	if o == nil || !o.Active() || len(body) == 0 {
		return Result{Body: body, Format: "none"}
	}
	c := o.compile()
	out, format, ok := apply(body, contentType, c, o.Scope, 0)
	if !ok || len(out) == 0 {
		return Result{Body: body, Format: "none"}
	}
	return Result{Body: out, Format: format}
}

func apply(body []byte, contentType string, c *compiled, sc Scope, depth int) ([]byte, string, bool) {
	if depth > 2 {
		return nil, "", false
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, "", false
	}

	// 1) JSON:sing-box / 单节点 JSON
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if out, ok := rewriteJSON(trimmed, c, sc); ok {
			return append(out, trailingOf(body)...), "singbox", true
		}
	}

	// 2) Clash / mihomo YAML
	lowCT := strings.ToLower(contentType)
	if looksLikeClash(trimmed) || strings.Contains(lowCT, "yaml") {
		if out, ok := rewriteClash(trimmed, c, sc); ok {
			return append(out, trailingOf(body)...), "clash", true
		}
	}

	// 3) Base64 包裹的正文:解出来再判一次
	if dec, ok := b64Decode(trimmed); ok {
		if inner, format, ok2 := apply(dec, "", c, sc, depth+1); ok2 {
			return wrapBase64(trimmed, inner), format, true
		}
	}

	// 4) 明文 URI 列表
	if looksLikeURIList(trimmed) {
		if out, ok := rewriteURIList(trimmed, c, sc); ok {
			return append(out, trailingOf(body)...), "uri", true
		}
	}

	// 5) 兜底:全文替换(只含展示词,不含连接参数)
	return fullText(trimmed, c), "text", true
}

func trailingOf(body []byte) []byte {
	t := bytes.TrimRight(body, " 	")
	if n := len(t); n > 0 && t[n-1] == '\n' {
		return []byte("\n")
	}
	return nil
}

// ---------------------------------------------------------------- Clash YAML

func looksLikeClash(b []byte) bool {
	return bytes.Contains(b, []byte("proxies:")) &&
		(bytes.Contains(b, []byte("proxy-groups:")) || bytes.Contains(b, []byte("rules:")))
}

func rewriteClash(body []byte, c *compiled, sc Scope) ([]byte, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		return nil, false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, false
	}

	renamed := map[string]string{}
	groupRenamed := map[string]string{}
	changed := false

	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		if val.Kind != yaml.SequenceNode {
			continue
		}
		switch key.Value {
		case "proxies":
			if !sc.Node {
				continue
			}
			for _, item := range val.Content {
				if item.Kind != yaml.MappingNode {
					continue
				}
				old := fieldString(item, "name")
				if nv, ok := renameField(item, "name", c); ok && nv != old {
					renamed[old] = nv
					changed = true
				}
			}
		}
	}

	// 分组名 + 分组里的节点引用(需要 proxies 先跑完才能建映射)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		if key.Value != "proxy-groups" || val.Kind != yaml.SequenceNode || (!sc.Group && !sc.Node) {
			continue
		}
		for _, g := range val.Content {
			if g.Kind != yaml.MappingNode {
				continue
			}
			if sc.Group {
				old := fieldString(g, "name")
				if nv, ok := renameField(g, "name", c); ok && nv != old {
					groupRenamed[old] = nv
					changed = true
				}
			}
			// proxies / use 列表里的节点名引用
			for j := 0; j+1 < len(g.Content); j += 2 {
				fk, fv := g.Content[j], g.Content[j+1]
				if fk.Value != "proxies" || fv.Kind != yaml.SequenceNode {
					continue
				}
				for _, s := range fv.Content {
					if s.Kind != yaml.ScalarNode {
						continue
					}
					if nv, ok := renamed[s.Value]; ok {
						s.Value = nv
						changed = true
					}
				}
			}
		}
	}

	if len(groupRenamed) > 0 {
		for i := 0; i+1 < len(root.Content); i += 2 {
			key, val := root.Content[i], root.Content[i+1]
			if val.Kind != yaml.SequenceNode {
				continue
			}
			switch key.Value {
			case "proxy-groups":
				for _, g := range val.Content {
					if g.Kind != yaml.MappingNode {
						continue
					}
					for j := 0; j+1 < len(g.Content); j += 2 {
						fk, fv := g.Content[j], g.Content[j+1]
						if fk.Value != "proxies" || fv.Kind != yaml.SequenceNode {
							continue
						}
						for _, s := range fv.Content {
							if s.Kind != yaml.ScalarNode {
								continue
							}
							if nv, ok := groupRenamed[s.Value]; ok {
								s.Value = nv
								changed = true
							}
						}
					}
				}
			case "rules":
				for _, it := range val.Content {
					if it.Kind != yaml.ScalarNode {
						continue
					}
					parts := strings.Split(it.Value, ",")
					if len(parts) < 2 {
						continue
					}
					idx := 2
					if strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
						idx = 1
					}
					if idx >= len(parts) {
						continue
					}
					if nv, ok := groupRenamed[strings.TrimSpace(parts[idx])]; ok {
						parts[idx] = nv
						it.Value = strings.Join(parts, ",")
						changed = true
					}
				}
			}
		}
	}

	if !changed {
		return nil, false
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false
	}
	_ = enc.Close()
	return buf.Bytes(), true
}

func fieldString(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i+1].Kind == yaml.ScalarNode {
			return m.Content[i+1].Value
		}
	}
	return ""
}

func renameField(m *yaml.Node, key string, c *compiled) (string, bool) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		v := m.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return "", false
		}
		nv := c.all(v.Value)
		v.Value = nv
		return nv, true
	}
	return "", false
}

// ---------------------------------------------------------------- sing-box JSON

func rewriteJSON(body []byte, c *compiled, sc Scope) ([]byte, bool) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, false
	}
	outbounds, ok := root["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return nil, false
	}
	renamed := map[string]string{}
	changed := false

	if sc.Node || sc.Group {
		for _, ob := range outbounds {
			m, ok := ob.(map[string]any)
			if !ok {
				continue
			}
			tag, ok := m["tag"].(string)
			if !ok || tag == "" {
				continue
			}
			nt := c.all(tag)
			if nt != tag {
				m["tag"] = nt
				renamed[tag] = nt
				changed = true
			}
		}
	}
	// 引用:selector / urltest 的 outbounds 数组、route.rules[].outbound
	if sc.Group && len(renamed) > 0 {
		for _, ob := range outbounds {
			m, ok := ob.(map[string]any)
			if !ok {
				continue
			}
			if arr, ok := m["outbounds"].([]any); ok {
				for i, v := range arr {
					if s, ok := v.(string); ok {
						if nv, hit := renamed[s]; hit {
							arr[i] = nv
							changed = true
						}
					}
				}
			}
		}
		if route, ok := root["route"].(map[string]any); ok {
			if rs, ok := route["rules"].([]any); ok {
				for _, rr := range rs {
					m, ok := rr.(map[string]any)
					if !ok {
						continue
					}
					if s, ok := m["outbound"].(string); ok {
						if nv, hit := renamed[s]; hit {
							m["outbound"] = nv
							changed = true
						}
					}
				}
			}
		}
	}
	if !changed {
		return nil, false
	}
	buf, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// ---------------------------------------------------------------- URI 列表

func looksLikeURIList(b []byte) bool {
	return bytes.Contains(b, []byte("://"))
}

func rewriteURIList(body []byte, c *compiled, sc Scope) ([]byte, bool) {
	if !sc.Node {
		return nil, false
	}
	lines := strings.Split(string(body), "\n")
	changed := false
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if nl, ok := rewriteURILine(line, c); ok {
			lines[i] = nl
			changed = true
		}
	}
	if !changed {
		return nil, false
	}
	return []byte(strings.Join(lines, "\n")), true
}

func rewriteURILine(line string, c *compiled) (string, bool) {
	scheme := ""
	if i := strings.Index(line, "://"); i > 0 {
		scheme = strings.ToLower(line[:i])
	}
	switch scheme {
	case "vmess":
		payload := strings.TrimSpace(line[len("vmess://"):])
		raw, ok := b64Decode([]byte(payload))
		if !ok {
			return line, false
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return line, false
		}
		ps, _ := m["ps"].(string)
		if ps == "" {
			return line, false
		}
		np := c.all(ps)
		if np == ps {
			return line, false
		}
		m["ps"] = np
		nb, err := json.Marshal(m)
		if err != nil {
			return line, false
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(nb), true
	case "":
		return line, false
	}

	// 其余协议:名字在 # 之后
	hash := strings.Index(line, "#")
	if hash < 0 {
		return line, false
	}
	frag := line[hash+1:]
	name, err := url.PathUnescape(frag)
	if err != nil {
		name = frag
	}
	nn := c.all(name)
	if nn == name {
		return line, false
	}
	esc := url.QueryEscape(nn)
	esc = strings.ReplaceAll(esc, "+", "%20")
	return line[:hash+1] + esc, true
}

// ---------------------------------------------------------------- 兜底

func fullText(body []byte, c *compiled) []byte {
	out := body
	if c.airportFrom != "" && c.airportTo != "" {
		out = bytes.ReplaceAll(out, []byte(c.airportFrom), []byte(c.airportTo))
	}
	for _, r := range c.plain {
		out = bytes.ReplaceAll(out, []byte(r.From), []byte(r.To))
	}
	for _, r := range c.res {
		out = r.re.ReplaceAll(out, []byte(r.to))
	}
	return out
}

// ---------------------------------------------------------------- base64

func b64Decode(b []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// wrapBase64 保持上游原有的换行/包裹风格,只替换内容。
func wrapBase64(outer, inner []byte) []byte {
	s := strings.TrimSpace(string(outer))
	switch {
	case strings.ContainsAny(s, "\r\n"):
		return []byte(base64.StdEncoding.EncodeToString(inner) + "\n")
	default:
		return []byte(base64.StdEncoding.EncodeToString(inner))
	}
}

// ---------------------------------------------------------------- 响应头

// ApplyHeaders 改写 Content-Disposition 文件名与 profile-title。
func ApplyHeaders(h http.Header, o *Options) bool {
	if h == nil || o == nil || !o.Active() || !o.Scope.Header {
		return false
	}
	c := o.compile()
	changed := false

	if v := h.Get("profile-title"); v != "" {
		if nv := rewriteTitle(v, c); nv != v {
			h.Set("profile-title", nv)
			changed = true
		}
	}
	if v := h.Get("Content-Disposition"); v != "" {
		if nv := rewriteDisposition(v, c); nv != v {
			h.Set("Content-Disposition", nv)
			changed = true
		}
	}
	return changed
}

func rewriteTitle(v string, c *compiled) string {
	const p = "base64:"
	if strings.HasPrefix(strings.ToLower(v), p) {
		raw := v[len(p):]
		dec, ok := b64Decode([]byte(raw))
		if !ok {
			return v
		}
		nd := c.all(string(dec))
		if nd == string(dec) {
			return v
		}
		return p + base64.StdEncoding.EncodeToString([]byte(nd))
	}
	return c.all(v)
}

var (
	reDispStar  = regexp.MustCompile(`filename\*=UTF-8''([^;]+)`)
	reDispPlain = regexp.MustCompile(`(^|[;\s])filename="?([^";]+)"?`)
)

func rewriteDisposition(v string, c *compiled) string {
	out := v
	// filename*=UTF-8''xxx(RFC 5987)
	out = reDispStar.ReplaceAllStringFunc(out, func(seg string) string {
		m := reDispStar.FindStringSubmatch(seg)
		if m == nil {
			return seg
		}
		name, err := url.PathUnescape(m[1])
		if err != nil {
			name = m[1]
		}
		nn := renameFileName(name, c)
		if nn == name {
			return seg
		}
		return fmt.Sprintf("filename*=UTF-8''%s", url.PathEscape(nn))
	})
	// 普通 filename="xxx"(用负向前瞻的替代写法:只匹配前面不是 * 的 filename=)
	out = reDispPlain.ReplaceAllStringFunc(out, func(seg string) string {
		m := reDispPlain.FindStringSubmatch(seg)
		if m == nil {
			return seg
		}
		name := m[2]
		nn := renameFileName(name, c)
		if nn == name {
			return seg
		}
		return fmt.Sprintf(`%sfilename="%s"`, m[1], nn)
	})
	return out
}

// renameFileName 改文件名,保留扩展名。原机场名留空时整名替换为新机场名。
func renameFileName(name string, c *compiled) string {
	if c.airportTo == "" && len(c.plain) == 0 && len(c.res) == 0 {
		return name
	}
	base, ext := name, ""
	if i := strings.LastIndex(name, "."); i > 0 {
		base, ext = name[:i], name[i:]
	}
	out := base
	if c.airportFrom == "" && c.airportTo != "" {
		// 没给原机场名 → 文件名直接改成新机场名
		out = c.airportTo
	} else {
		out = c.all(base)
	}
	out = c.all(out)
	if out == "" {
		out = base
	}
	return out + ext
}
