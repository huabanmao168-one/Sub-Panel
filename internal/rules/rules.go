// Package rules 维护 DB 来源的可热更新规则:IP 白名单 + UA 黑名单。
//
// 设计:
//   - 启动时从 store 加载,在内存里构建快速匹配结构
//   - CRUD 后立即 Reload
//   - 提供给 detector 的查询函数线程安全
package rules

import (
	"net"
	"strings"
	"sync"

	"github.com/huabanmao168/SubPanel/internal/store"
)

type Manager struct {
	mu sync.RWMutex
	st *store.Store

	// IP 白名单:支持单 IP 和 CIDR
	ipWhitelistSingle map[string]struct{}
	ipWhitelistNets   []*net.IPNet

	// UA 黑名单:子串匹配(小写)
	uaBlacklistPatterns []string
}

func NewManager(st *store.Store) *Manager {
	return &Manager{
		st:                st,
		ipWhitelistSingle: map[string]struct{}{},
	}
}

// Reload 全量重读 DB。失败时保留旧数据。
func (m *Manager) Reload() error {
	ipEntries, err := m.st.ListIPWhitelist()
	if err != nil {
		return err
	}
	uaRules, err := m.st.ListUARules("blacklist")
	if err != nil {
		return err
	}

	singles := map[string]struct{}{}
	var nets []*net.IPNet
	for _, e := range ipEntries {
		t := strings.TrimSpace(e.Target)
		if strings.Contains(t, "/") {
			_, n, err := net.ParseCIDR(t)
			if err == nil {
				nets = append(nets, n)
			}
		} else {
			singles[t] = struct{}{}
		}
	}

	var uaPatterns []string
	for _, r := range uaRules {
		p := strings.ToLower(strings.TrimSpace(r.Pattern))
		if p != "" {
			uaPatterns = append(uaPatterns, p)
		}
	}

	m.mu.Lock()
	m.ipWhitelistSingle = singles
	m.ipWhitelistNets = nets
	m.uaBlacklistPatterns = uaPatterns
	m.mu.Unlock()
	return nil
}

// IPWhitelisted 检查 IP 是否在白名单(支持精确和 CIDR)。
func (m *Manager) IPWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.ipWhitelistSingle[ip]; ok {
		return true
	}
	if len(m.ipWhitelistNets) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range m.ipWhitelistNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsUABlacklisted 检查 UA 是否命中黑名单(子串匹配,忽略大小写)。空 UA 不命中。
func (m *Manager) IsUABlacklisted(ua string) bool {
	if ua == "" {
		return false
	}
	low := strings.ToLower(ua)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.uaBlacklistPatterns {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// ---------- CRUD wrappers(写完触发 Reload) ----------

func (m *Manager) AddIPWhitelist(target, note string) error {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err != nil {
			return err
		}
	} else if net.ParseIP(t) == nil {
		return errIPInvalid
	}
	if err := m.st.AddIPWhitelist(t, note); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteIPWhitelist(id int64) error {
	if err := m.st.DeleteIPWhitelist(id); err != nil {
		return err
	}
	return m.Reload()
}

// UpdateIPWhitelist 校验 target 合法性 + 写库 + 触发热加载。
func (m *Manager) UpdateIPWhitelist(id int64, target, note string) error {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err != nil {
			return err
		}
	} else if net.ParseIP(t) == nil {
		return errIPInvalid
	}
	if err := m.st.UpdateIPWhitelist(id, t, note); err != nil {
		return err
	}
	return m.Reload()
}

// errIPInvalid 用于 IP 校验失败。
var errIPInvalid = &simpleErr{"target must be valid IP or CIDR"}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

// ---------- UA 黑名单 CRUD ----------

func (m *Manager) AddUABlacklist(pattern, note string) error {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return &simpleErr{"pattern cannot be empty"}
	}
	if err := m.st.AddUARule(store.UARule{
		Kind:    "blacklist",
		Pattern: p,
		Note:    note,
	}); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteUABlacklist(id int64) error {
	if err := m.st.DeleteUARule(id); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) ListUABlacklist() ([]store.UARule, error) {
	return m.st.ListUARules("blacklist")
}
