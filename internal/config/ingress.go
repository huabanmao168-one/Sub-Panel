package config

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	IngressDirect          = "direct"
	IngressNginxCloudflare = "nginx_cloudflare"
)

func (c Config) IngressProfile() string {
	if c.IngressMode == "" {
		return IngressDirect
	}
	return c.IngressMode
}

// CloudflareIngressPeers is independent of the legacy RealIP header checkbox.
func CloudflareIngressPeers() []string {
	return append(append([]string(nil), CloudflareIPv4...), CloudflareIPv6...)
}

func ParseNginxEgressIPs(values []string) ([]netip.Addr, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("串联模式至少填写一个国内 Nginx 公网出口 IP")
	}
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return nil, fmt.Errorf("国内 Nginx 出口必须是单个公网 IP，不能使用域名或 CIDR：%q", value)
		}
		out = append(out, ip.Unmap())
	}
	return out, nil
}

func (c Config) AllowedIngressPeers() []string {
	if c.IngressProxies == nil {
		return []string{"127.0.0.1", "::1"}
	}
	return append([]string{}, c.IngressProxies...)
}

func ParseIngressPeers(values []string) ([]netip.Prefix, error) {
	var peers []netip.Prefix
	for _, value := range values {
		value = strings.TrimSpace(value)
		if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" && !ip.IsUnspecified() {
			ip = ip.Unmap()
			peers = append(peers, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() > 0 && !prefix.Addr().Is4In6() {
			peers = append(peers, prefix.Masked())
			continue
		}
		return nil, fmt.Errorf("前置 Nginx 地址必须为具体 IP 或网段，不允许全部地址：%q", value)
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("至少填写一个前置 Nginx 来源 IP 或网段")
	}
	return peers, nil
}
