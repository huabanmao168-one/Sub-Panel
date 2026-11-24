package config

import (
	"fmt"
	"net/netip"
	"strings"
)

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
