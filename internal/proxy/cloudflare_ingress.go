package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

const cloudflareIPsURL = "https://api.cloudflare.com/client/v4/ips"
const cloudflareIngressCacheKey = "cloudflare_ingress_cidrs_v1"
const cloudflareRefreshInterval = 6 * time.Hour

// cloudflareIPList is the public Cloudflare IP ranges response's result.
type cloudflareIPList struct {
	IPv4 []string `json:"ipv4_cidrs"`
	IPv6 []string `json:"ipv6_cidrs"`
}

func (list cloudflareIPList) prefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, family := range []struct {
		bits   int
		ranges []string
	}{{32, list.IPv4}, {128, list.IPv6}} {
		if len(family.ranges) == 0 || len(family.ranges) > 1024 {
			return nil, fmt.Errorf("Cloudflare IPv4/IPv6 list is incomplete or too large")
		}
		for _, raw := range family.ranges {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p.Addr().BitLen() != family.bits || p.Addr().Is4In6() || p.Bits() == 0 || !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() || p.Masked() != p {
				return nil, fmt.Errorf("invalid Cloudflare prefix")
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func fetchCloudflareIPList(ctx context.Context, client *http.Client, endpoint string) (cloudflareIPList, error) {
	var data struct {
		Success bool             `json:"success"`
		Result  cloudflareIPList `json:"result"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return data.Result, err
	}
	res, err := client.Do(req)
	if err != nil {
		return data.Result, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return data.Result, fmt.Errorf("Cloudflare returned HTTP %d", res.StatusCode)
	}
	const maxBytes = 128 << 10
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return data.Result, err
	}
	if len(body) > maxBytes || json.Unmarshal(body, &data) != nil || !data.Success {
		return data.Result, fmt.Errorf("invalid Cloudflare IP ranges response")
	}
	return data.Result, nil
}

func (g *Gateway) loadCloudflareIPCache() string {
	raw, err := g.st.GetMeta(cloudflareIngressCacheKey)
	if err != nil {
		g.logger.Warn("无法读取 Cloudflare 回源网段缓存，暂用内置名单", "err", err)
		return ""
	}
	if raw == "" {
		return ""
	}
	var list cloudflareIPList
	if json.Unmarshal([]byte(raw), &list) == nil {
		if peers, err := list.prefixes(); err == nil {
			g.cloudflarePeers.Store(&peers)
			return raw
		}
	}
	g.logger.Warn("Cloudflare 回源网段缓存无效，暂用内置名单")
	return ""
}

func (g *Gateway) refreshCloudflareIPList(ctx context.Context, client *http.Client, endpoint, cached string) (string, error) {
	list, err := fetchCloudflareIPList(ctx, client, endpoint)
	if err != nil {
		return cached, err
	}
	peers, err := list.prefixes()
	if err != nil {
		return cached, err
	}
	g.cloudflarePeers.Store(&peers)
	g.logger.Info("已同步 Cloudflare 官方回源网段", "ipv4", len(list.IPv4), "ipv6", len(list.IPv6))
	data, err := json.Marshal(list)
	if err != nil {
		return cached, err
	}
	if string(data) != cached {
		if err := g.st.SetMeta(cloudflareIngressCacheKey, string(data)); err != nil {
			return cached, fmt.Errorf("保存 Cloudflare 回源网段缓存: %w", err)
		}
	}
	return string(data), nil
}

// RunCloudflareIngressRefresh restores the last known list before listening,
// then refreshes it asynchronously without making startup depend on the API.
func (g *Gateway) RunCloudflareIngressRefresh(ctx context.Context) {
	if g.cloudflarePeers.Load() == nil {
		return
	}
	cached := g.loadCloudflareIPCache()
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go func() {
		ticker := time.NewTicker(cloudflareRefreshInterval)
		defer ticker.Stop()
		for {
			var err error
			cached, err = g.refreshCloudflareIPList(ctx, client, cloudflareIPsURL, cached)
			if err != nil && ctx.Err() == nil {
				g.logger.Warn("Cloudflare 回源网段同步异常，保留当前有效名单", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
