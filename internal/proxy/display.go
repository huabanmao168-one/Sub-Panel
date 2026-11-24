package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/parser"
	"github.com/huabanmao168/SubPanel/internal/rewrite"
	"github.com/huabanmao168/SubPanel/internal/store"
)

// displayRuleSet 是规则快照,读多写少,整体原子替换。
type displayRuleSet struct {
	rules []store.DisplayRule
}

// SetDisplayRules 原子替换规则快照(管理面保存后调用,热生效)。
func (g *Gateway) SetDisplayRules(rules []store.DisplayRule) {
	cp := make([]store.DisplayRule, len(rules))
	copy(cp, rules)
	g.displayRules.Store(&displayRuleSet{rules: cp})
}

// DisplayRules 返回当前规则数量(给管理面/日志用)。
func (g *Gateway) DisplayRuleCount() int {
	s := g.displayRules.Load()
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// hasDisplayRule 该机场是否有启用的规则;没有就完全走原有直通路径,不缓冲、不查库。
func (g *Gateway) hasDisplayRule(tenant, ua string) bool {
	s := g.displayRules.Load()
	if s == nil {
		return false
	}
	for i := range s.rules {
		r := &s.rules[i]
		if r.Enabled && r.Tenant == tenant && (!r.UsesUserAgent() || r.Matches(tenant, "", ua)) {
			return true
		}
	}
	return false
}

// UA rules use the current request. Email data is loaded lazily only when an
// enabled email-based rule could match, preserving the first-match priority.
func (g *Gateway) matchDisplayRule(tenant, token, ua string) *rewrite.Options {
	s := g.displayRules.Load()
	if s == nil {
		return nil
	}
	var email string
	lookedUp := false
	for i := range s.rules {
		r := &s.rules[i]
		if !r.Enabled || (r.Tenant != "" && r.Tenant != tenant) {
			continue
		}
		if !r.UsesUserAgent() && !lookedUp {
			lookedUp = true
			if token != "" {
				if rep, err := g.st.GetUserReportByToken(g.hasher.Hash(token), tenant); err == nil && rep != nil {
					email = rep.Email
				}
			}
		}
		if !r.Matches(tenant, email, ua) {
			continue
		}
		return optionsOf(r)
	}
	return nil
}

func optionsOf(r *store.DisplayRule) *rewrite.Options {
	o := &rewrite.Options{
		AirportFrom: strings.TrimSpace(r.AirportFrom),
		AirportTo:   strings.TrimSpace(r.AirportTo),
		Scope: rewrite.Scope{
			Node:   r.ScopeNode,
			Group:  r.ScopeGroup,
			Header: r.ScopeHeader,
		},
	}
	if r.Replacements != "" {
		var reps []rewrite.Replacement
		if err := json.Unmarshal([]byte(r.Replacements), &reps); err == nil {
			o.Replacements = reps
		}
	}
	if !o.Active() {
		return nil
	}
	return o
}

// transparentProxyDisplay 命中展示定制规则时走这条路:
// 剥掉 Accept-Encoding → 缓冲上游响应 → 解压 → 改写名称与响应头 → 按原编码压回。
// Unsupported encoding is forwarded unchanged; oversized responses are rejected.
func (g *Gateway) transparentProxyDisplay(
	w http.ResponseWriter, r *http.Request, pr *parser.Request,
	tokenHash string, tags []string, start time.Time,
) {
	rp := g.snap.Load().proxies[pr.Tenant.Name]
	if rp == nil {
		http.Error(w, "无可用上游", http.StatusBadGateway)
		g.logEvent(pr, tokenHash, "display_failed", http.StatusBadGateway, append(tags, "no_proxy"), 0, 0, start)
		return
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		r.Header.Set("X-Forwarded-For", pr.ClientIP)
	} else {
		r.Header.Set("X-Forwarded-For", xff+", "+pr.ClientIP)
	}
	// 需要改正文,先让上游返回明文,避免对压缩字节流做替换。
	r.Header.Del("Accept-Encoding")

	bw := &bufferingWriter{header: http.Header{}, status: 200, body: &bytes.Buffer{}}
	rp.ServeHTTP(bw, r)
	if bw.overflow {
		g.subscriptionTransformError(w, pr, tokenHash, "display_failed", "body_too_large", tags, start)
		return
	}

	// 上游非 2xx:原样透传(错误体不参与改写)
	if bw.status < 200 || bw.status >= 300 {
		for k, vs := range bw.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(bw.status)
		_, _ = w.Write(bw.body.Bytes())
		g.logEvent(pr, tokenHash, "display_failed", bw.status, append(tags, "upstream_bad"),
			time.Since(start).Milliseconds(), int64(bw.body.Len()), start)
		return
	}

	// 先转发后查邮箱:上游处理订阅时已同步上报,此时邮箱通常已落库,首次拉取也能命中。
	opts := g.matchDisplayRule(pr.Tenant.Name, pr.Token, pr.UA)
	if opts == nil {
		for k, vs := range bw.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(bw.status)
		_, _ = w.Write(bw.body.Bytes())
		g.logEvent(pr, tokenHash, "pass", bw.status, append(tags, "display_nomatch"),
			time.Since(start).Milliseconds(), int64(bw.body.Len()), start)
		return
	}
	tags = append(tags, "display_rewrite")

	rawBody := bw.body.Bytes()
	enc := strings.ToLower(strings.TrimSpace(bw.header.Get("Content-Encoding")))
	decoded, decErr := decodeBody(rawBody, enc)
	if decErr != nil {
		for k, vs := range bw.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(bw.status)
		_, _ = w.Write(rawBody)
		g.logEvent(pr, tokenHash, "pass", bw.status, append(tags, "decode_failed"), time.Since(start).Milliseconds(), int64(len(rawBody)), start)
		return
	}

	res := rewrite.Apply(decoded, bw.header.Get("Content-Type"), opts)
	out := res.Body
	rewrite.ApplyHeaders(bw.header, opts)
	if res.Format != "none" {
		tags = append(tags, "fmt_"+res.Format)
	}

	// 按原编码压回;压回失败则明文下发并去掉编码头
	if enc != "" {
		if reEncoded, err := encodeBody(out, enc); err == nil {
			out = reEncoded
		} else {
			bw.header.Del("Content-Encoding")
		}
	}

	for k, vs := range bw.header {
		if isBodyHeader(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)

	country, usageType, isp := g.geoFor(pr.ClientIP)
	g.st.SubmitEvent(store.Event{
		TS:         start,
		Tenant:     pr.Tenant.Name,
		ClientIP:   pr.ClientIP,
		UA:         pr.UA,
		TokenHash:  tokenHash,
		Flag:       pr.Flag,
		Path:       logPath(pr),
		Status:     200,
		Action:     "display",
		RuleTags:   tags,
		UpstreamMS: time.Since(start).Milliseconds(),
		RespSize:   int64(len(out)),
		Country:    country,
		UsageType:  usageType,
		ISP:        isp,
	})
}
