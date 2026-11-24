package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultDBPath = "/opt/Sub-Panel/data/sub-panel.db"
const LegacyConfigPath = "/opt/Sub-Panel/config.yml"

func InitialPasswordPath(dbPath string) string { return dbPath + ".initial-password" }

// Defaults creates the initial configuration for a new database.
func Defaults(dbPath string) *Config {
	c := &Config{
		Listen: "127.0.0.1:18443", AdminListen: "127.0.0.1:19090",
		HMACSaltFile: filepath.Join(filepath.Dir(dbPath), "salt"),
		Storage: Storage{SQLitePath: dbPath, Retention: Retention{
			Events: Duration(7 * 24 * time.Hour), Incidents: Duration(30 * 24 * time.Hour),
		}},
		RealIP: RealIP{TrustHeaders: []string{"X-Real-IP", "X-Forwarded-For"}, TrustProxies: []string{"127.0.0.1", "::1"}},
		GeoIP:  GeoIPCfg{XDBPath: "/opt/Sub-Panel/ip2region.xdb"},
		Admin:  AdminCfg{Username: "admin"},
		Detector: DetectorCfg{Rules: []Rule{
			{Name: "token_freq_extreme", Desc: "单 token 5 分钟内 ≥30 次", When: When{TokenFreq: &Cond{Window: Duration(5 * time.Minute), GTE: 30}}},
			{Name: "token_multi_ip", Desc: "单 token 5 分钟内 ≥5 个 IP", When: When{TokenDistinctIPs: &Cond{Window: Duration(5 * time.Minute), GTE: 5}}},
		}},
	}
	c.applyDefaults()
	return c
}

// RuntimeSettings is the editable, non-secret part of Config.
type RuntimeSettings struct {
	Listen             string   `json:"listen"`
	AdminListen        string   `json:"admin_listen"`
	IngressProxies     []string `json:"ingress_proxies"`
	TrustHeaders       []string `json:"trust_headers"`
	TrustProxies       []string `json:"trust_proxies"`
	Cloudflare         bool     `json:"cloudflare"`
	GeoIPPath          string   `json:"geoip_path"`
	EventRetention     string   `json:"event_retention"`
	IncidentRetention  string   `json:"incident_retention"`
	BatchFlushInterval string   `json:"batch_flush_interval"`
	BatchFlushSize     int      `json:"batch_flush_size"`
	AdminUsername      string   `json:"admin_username"`
	SessionTTL         string   `json:"session_ttl"`
	ReportBaseURL      string   `json:"report_base_url"`
	DisableLumi        bool     `json:"disable_lumi"`
	DetectionOnlyIPs   []string `json:"detection_only_ips"`
}

func (c *Config) RuntimeSettings() RuntimeSettings {
	return RuntimeSettings{
		Listen: c.Listen, AdminListen: c.AdminListen, IngressProxies: c.AllowedIngressPeers(),
		TrustHeaders: append([]string{}, c.RealIP.TrustHeaders...), TrustProxies: append([]string{}, c.RealIP.TrustProxies...), Cloudflare: c.RealIP.Cloudflare, GeoIPPath: c.GeoIP.XDBPath,
		EventRetention: c.Storage.Retention.Events.Std().String(), IncidentRetention: c.Storage.Retention.Incidents.Std().String(),
		BatchFlushInterval: c.Storage.BatchFlushInterval.Std().String(), BatchFlushSize: c.Storage.BatchFlushSize,
		AdminUsername: c.Admin.Username, SessionTTL: c.Admin.SessionTTL.Std().String(),
		ReportBaseURL: c.ReportBaseURL, DisableLumi: c.DisableLumi, DetectionOnlyIPs: append([]string{}, c.Detector.Whitelist.IPs...),
	}
}

func (c Config) WithRuntimeSettings(s RuntimeSettings) (*Config, error) {
	var hosts [2]string
	var ports [2]int
	for i, item := range []struct{ label, value string }{{"订阅监听地址", s.Listen}, {"管理监听地址", s.AdminListen}} {
		host, port, err := net.SplitHostPort(item.value)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 1 || n > 65535 || strings.TrimSpace(item.value) != item.value {
			return nil, fmt.Errorf("%s必须包含有效端口，例如 127.0.0.1:19090", item.label)
		}
		hosts[i], ports[i] = strings.ToLower(host), n
	}
	wildcard := func(host string) bool {
		ip, err := netip.ParseAddr(host)
		return host == "" || (err == nil && ip.IsUnspecified())
	}
	if ports[0] == ports[1] && (hosts[0] == hosts[1] || wildcard(hosts[0]) || wildcard(hosts[1])) {
		return nil, fmt.Errorf("订阅和管理监听地址的端口冲突")
	}
	for _, item := range []struct {
		label, value string
		target       *Duration
	}{
		{"请求日志保留时间", s.EventRetention, &c.Storage.Retention.Events},
		{"异常事件保留时间", s.IncidentRetention, &c.Storage.Retention.Incidents},
		{"日志写入间隔", s.BatchFlushInterval, &c.Storage.BatchFlushInterval},
		{"登录会话有效期", s.SessionTTL, &c.Admin.SessionTTL},
	} {
		d, err := time.ParseDuration(item.value)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("%s必须为正数时长，例如 168h 或 1s", item.label)
		}
		*item.target = Duration(d)
	}
	// Missing fields from older UI/API clients leave the current ingress policy intact.
	if s.IngressProxies == nil {
		s.IngressProxies = c.AllowedIngressPeers()
	}
	if len(s.IngressProxies) == 0 {
		return nil, fmt.Errorf("至少填写一个前置 Nginx 来源 IP 或网段")
	}
	if _, err := ParseIngressPeers(s.IngressProxies); err != nil {
		return nil, err
	}
	c.IngressProxies = append([]string(nil), s.IngressProxies...)
	for _, p := range s.TrustProxies {
		if _, addrErr := netip.ParseAddr(p); addrErr != nil {
			if _, prefixErr := netip.ParsePrefix(p); prefixErr != nil {
				return nil, fmt.Errorf("可信代理必须是 IP 或 CIDR：%q", p)
			}
		}
	}
	for _, h := range s.TrustHeaders {
		if h == "" || strings.ContainsAny(h, " \t\r\n:") {
			return nil, fmt.Errorf("无效的真实 IP 请求头：%q", h)
		}
	}
	for _, ip := range s.DetectionOnlyIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, fmt.Errorf("无效的 IP 地址：%q", ip)
		}
	}
	if s.BatchFlushSize < 1 || s.BatchFlushSize > 10000 {
		return nil, fmt.Errorf("日志写入批量须为 1–10000")
	}
	if s.AdminUsername == "" || strings.TrimSpace(s.AdminUsername) != s.AdminUsername {
		return nil, fmt.Errorf("管理员账号不能为空或以空白开头、结尾")
	}
	c.Listen, c.AdminListen = s.Listen, s.AdminListen
	c.RealIP = RealIP{TrustHeaders: s.TrustHeaders, TrustProxies: s.TrustProxies, Cloudflare: s.Cloudflare}
	c.GeoIP.XDBPath, c.Storage.BatchFlushSize, c.Admin.Username = s.GeoIPPath, s.BatchFlushSize, s.AdminUsername
	if s.ReportBaseURL != "" {
		u, err := url.Parse(s.ReportBaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, fmt.Errorf("外部上报基址必须是 HTTP(S) URL，且不含账号、查询或片段")
		}
		s.ReportBaseURL = strings.TrimRight(u.String(), "/")
	}
	c.ReportBaseURL, c.DisableLumi = s.ReportBaseURL, s.DisableLumi
	c.Detector.Whitelist.IPs = s.DetectionOnlyIPs
	return &c, nil
}

// ForRuntime expands derived settings without persisting them as user input.
func (c Config) ForRuntime() *Config {
	c.RealIP.TrustHeaders = append([]string(nil), c.RealIP.TrustHeaders...)
	c.RealIP.TrustProxies = append([]string(nil), c.RealIP.TrustProxies...)
	applyCloudflare(&c)
	return &c
}
