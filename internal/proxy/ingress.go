package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/huabanmao168/SubPanel/internal/config"
)

const nginxClientIPHeader = "X-Sub-Panel-Client-IP"

func (g *Gateway) configureIngress() error {
	var err error
	switch g.cfg.IngressProfile() {
	case config.IngressDirect:
		g.ingressPeers, err = config.ParseIngressPeers(g.cfg.AllowedIngressPeers())
	case config.IngressNginxCloudflare:
		var peers []netip.Prefix
		peers, err = config.ParseIngressPeers(config.CloudflareIngressPeers())
		if err == nil {
			g.cloudflarePeers.Store(&peers)
			g.nginxEgress, err = config.ParseNginxEgressIPs(g.cfg.NginxEgressIPs)
		}
	default:
		return fmt.Errorf("未知的订阅入口模式")
	}
	return err
}

func singleHeaderIP(h http.Header, name string) (netip.Addr, bool) {
	values := h.Values(name)
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(values[0]))
	return ip.Unmap(), err == nil && ip.Zone() == "" && !ip.IsUnspecified()
}

// ingressClient authenticates the connection peer first. Only the explicit
// chain profile trusts Cloudflare's identifying header after peer verification.
// A non-empty returned IP overrides the legacy RealIP header selection.
func (g *Gateway) ingressClient(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	peer := ip.WithZone("").Unmap()
	peers := g.ingressPeers
	cloudflare := g.cloudflarePeers.Load()
	if cloudflare != nil {
		peers = *cloudflare
	}
	if !slices.ContainsFunc(peers, func(p netip.Prefix) bool { return p.Contains(peer) }) {
		return "", false
	}
	if cloudflare == nil {
		return "", true
	}
	edgeClient, ok := singleHeaderIP(r.Header, "CF-Connecting-IP")
	if !ok || !slices.Contains(g.nginxEgress, edgeClient) {
		return "", false
	}
	if g.cfg.NginxClientIP {
		if original, ok := singleHeaderIP(r.Header, nginxClientIPHeader); ok {
			return original.String(), true
		}
	}
	return edgeClient.String(), true
}

// RequireIngress protects non-subscription routes such as the reporting endpoint.
func (g *Gateway) RequireIngress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := g.ingressClient(r); !ok {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// chainRequest does not relay unverified forwarding headers to the upstream.
func chainRequest(r *http.Request, clientIP string) *http.Request {
	r = r.Clone(r.Context())
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Client-IP", "CF-Connecting-IP", "CF-Connecting-IPv6", "True-Client-IP", nginxClientIPHeader} {
		r.Header.Del(h)
	}
	r.Header.Set("X-Real-IP", clientIP)
	return r
}
