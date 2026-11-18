package rewrite

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func opts(airportFrom, airportTo string, reps ...Replacement) *Options {
	return &Options{
		AirportFrom:  airportFrom,
		AirportTo:    airportTo,
		Replacements: reps,
		Scope:        Scope{Node: true, Group: true, Header: true},
	}
}

func TestClashRenameNodesGroupsAndRefs(t *testing.T) {
	in := `proxies:
  - name: 花瓣 香港 01
    type: ss
    server: hk1.example.com
    port: 443
    cipher: aes-128-gcm
    password: Huaban168HK
  - name: 花瓣 日本 01
    type: ss
    server: jp1.example.com
    port: 443
    cipher: aes-128-gcm
    password: Huaban168JP
proxy-groups:
  - name: 花瓣
    type: select
    proxies:
      - 花瓣 香港 01
      - 花瓣 日本 01
rules:
  - MATCH,花瓣
`
	r := Apply([]byte(in), "text/yaml", opts("花瓣", "云帆"))
	if r.Format != "clash" {
		t.Fatalf("format = %q, want clash", r.Format)
	}
	out := string(r.Body)
	if strings.Contains(out, "花瓣") {
		t.Fatalf("旧机场名未清干净:\n%s", out)
	}
	for _, want := range []string{"云帆 香港 01", "云帆 日本 01", "name: 云帆"} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少 %q:\n%s", want, out)
		}
	}
	// 连接参数必须原样保留
	for _, keep := range []string{"hk1.example.com", "jp1.example.com", "Huaban168HK", "Huaban168JP"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("连接参数被误改 %q:\n%s", keep, out)
		}
	}
}

func TestClashKeywordReplacement(t *testing.T) {
	in := `proxies:
  - name: 云帆 香港 01
    type: ss
    server: hk1.example.com
    port: 443
proxy-groups:
  - name: 自动选择
    type: url-test
    proxies: [云帆 香港 01]
rules:
  - MATCH,自动选择
`
	o := opts("", "", Replacement{From: "香港", To: "HK"}, Replacement{From: "日本", To: "JP"})
	r := Apply([]byte(in), "", o)
	out := string(r.Body)
	if !strings.Contains(out, "云帆 HK 01") {
		t.Fatalf("关键词没替换:\n%s", out)
	}
	if !strings.Contains(out, "hk1.example.com") {
		t.Fatalf("server 被误改:\n%s", out)
	}
}

func TestURIListRenamesFragment(t *testing.T) {
	in := "ss://YWVzLTEyOC1nY206cGFzcw@hk1.example.com:443#%E8%8A%B1%E7%93%A3%20%E9%A6%99%E6%B8%AF%2001\n" +
		"trojan://pw@jp1.example.com:443?sni=jp1.example.com#%E8%8A%B1%E7%93%A3%20%E6%97%A5%E6%9C%AC%2001\n"
	r := Apply([]byte(in), "", opts("花瓣", "云帆"))
	if r.Format != "uri" {
		t.Fatalf("format = %q, want uri", r.Format)
	}
	out := string(r.Body)
	if strings.Contains(out, "%E8%8A%B1%E7%93%A3") {
		t.Fatalf("旧名未清:\n%s", out)
	}
	if !strings.Contains(out, "hk1.example.com:443") || !strings.Contains(out, "sni=jp1.example.com") {
		t.Fatalf("连接参数被误改:\n%s", out)
	}
}

func TestVmessRenamesPS(t *testing.T) {
	payload := map[string]any{
		"v": "2", "ps": "花瓣 香港 01", "add": "hk1.example.com", "port": "443",
		"id": "uuid-here", "aid": "0", "net": "ws", "type": "none", "host": "",
		"path": "/ray", "tls": "tls",
	}
	raw, _ := json.Marshal(payload)
	in := "vmess://" + base64.StdEncoding.EncodeToString(raw) + "\n"

	r := Apply([]byte(in), "", opts("花瓣", "云帆"))
	out := strings.TrimSpace(string(r.Body))
	dec, ok := b64Decode([]byte(strings.TrimPrefix(out, "vmess://")))
	if !ok {
		t.Fatalf("vmess 输出不是合法 base64: %q", out)
	}
	var got map[string]any
	if err := json.Unmarshal(dec, &got); err != nil {
		t.Fatalf("vmess 输出不是合法 json: %v", err)
	}
	if got["ps"] != "云帆 香港 01" {
		t.Fatalf("ps = %v", got["ps"])
	}
	if got["add"] != "hk1.example.com" || got["id"] != "uuid-here" || got["path"] != "/ray" {
		t.Fatalf("连接参数被误改: %v", got)
	}
}

func TestBase64WrappedClash(t *testing.T) {
	clash := `proxies:
  - name: 花瓣 香港 01
    type: ss
    server: hk1.example.com
    port: 443
proxy-groups:
  - name: 花瓣
    type: select
    proxies: [花瓣 香港 01]
rules:
  - MATCH,花瓣
`
	inner := base64.StdEncoding.EncodeToString([]byte(clash))
	r := Apply([]byte(inner), "", opts("花瓣", "云帆"))
	out := strings.TrimSpace(string(r.Body))
	dec, ok := b64Decode([]byte(out))
	if !ok {
		t.Fatalf("输出不是 base64")
	}
	s := string(dec)
	if strings.Contains(s, "花瓣") {
		t.Fatalf("base64 内部旧名未清:\n%s", s)
	}
	if !strings.Contains(s, "云帆 香港 01") || !strings.Contains(s, "hk1.example.com") {
		t.Fatalf("改写结果不对:\n%s", s)
	}
}

func TestSingBoxTags(t *testing.T) {
	in := `{
  "outbounds": [
    {"type": "selector", "tag": "花瓣", "outbounds": ["花瓣 香港 01"]},
    {"type": "shadowsocks", "tag": "花瓣 香港 01", "server": "hk1.example.com", "server_port": 443, "method": "aes-128-gcm", "password": "pw"}
  ]
}`
	r := Apply([]byte(in), "application/json", opts("花瓣", "云帆"))
	if r.Format != "singbox" {
		t.Fatalf("format = %q", r.Format)
	}
	var got struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatalf("输出不是合法 json: %v", err)
	}
	if got.Outbounds[0]["tag"] != "云帆" {
		t.Fatalf("selector tag = %v", got.Outbounds[0]["tag"])
	}
	if got.Outbounds[1]["tag"] != "云帆 香港 01" {
		t.Fatalf("节点 tag = %v", got.Outbounds[1]["tag"])
	}
	refs, _ := got.Outbounds[0]["outbounds"].([]any)
	if len(refs) != 1 || refs[0] != "云帆 香港 01" {
		t.Fatalf("分组引用未同步: %v", refs)
	}
	if got.Outbounds[1]["server"] != "hk1.example.com" || got.Outbounds[1]["password"] != "pw" {
		t.Fatalf("连接参数被误改: %v", got.Outbounds[1])
	}
}

func TestUnknownFormatFallsBackToFullText(t *testing.T) {
	in := "random text 花瓣 something\n"
	r := Apply([]byte(in), "application/octet-stream", opts("花瓣", "云帆"))
	if r.Format != "text" {
		t.Fatalf("format = %q, want text", r.Format)
	}
	if !strings.Contains(string(r.Body), "云帆") {
		t.Fatalf("兜底没替换: %s", r.Body)
	}
}

func TestInactiveOptionsPassThrough(t *testing.T) {
	in := []byte("anything")
	r := Apply(in, "", &Options{})
	if string(r.Body) != "anything" || r.Format != "none" {
		t.Fatalf("空规则不该改动内容")
	}
}

func TestApplyHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Disposition", `attachment; filename="花瓣.yaml"; filename*=UTF-8''%E8%8A%B1%E7%93%A3.yaml`)
	h.Set("profile-title", "花瓣 机场")
	ApplyHeaders(h, opts("花瓣", "云帆"))
	cd := h.Get("Content-Disposition")
	if strings.Contains(cd, "%E8%8A%B1%E7%93%A3") || strings.Contains(cd, "花瓣") {
		t.Fatalf("文件名未改: %s", cd)
	}
	if !strings.Contains(cd, "云帆.yaml") {
		t.Fatalf("文件名 %s", cd)
	}
	if pt := h.Get("profile-title"); !strings.Contains(pt, "云帆") {
		t.Fatalf("profile-title = %s", pt)
	}
}

func TestApplyHeadersBase64Title(t *testing.T) {
	h := http.Header{}
	h.Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte("花瓣 机场")))
	ApplyHeaders(h, opts("花瓣", "云帆"))
	dec, ok := b64Decode([]byte(strings.TrimPrefix(h.Get("profile-title"), "base64:")))
	if !ok || !strings.Contains(string(dec), "云帆") {
		t.Fatalf("profile-title = %s", h.Get("profile-title"))
	}
}

func TestRegexReplacement(t *testing.T) {
	in := "node 花瓣-01 and 花瓣-02\n"
	o := opts("", "", Replacement{From: `花瓣-(\d+)`, To: `YF-$1`, Regex: true})
	r := Apply([]byte(in), "text/plain", o)
	if !strings.Contains(string(r.Body), "YF-01") || !strings.Contains(string(r.Body), "YF-02") {
		t.Fatalf("正则替换失败: %s", r.Body)
	}
}

func TestInvalidRegexTreatedAsLiteral(t *testing.T) {
	in := "x( unmatched\n"
	o := opts("", "", Replacement{From: "x(", To: "y", Regex: true})
	r := Apply([]byte(in), "text/plain", o)
	if !strings.Contains(string(r.Body), "y") {
		t.Fatalf("非法正则应退化为字面量: %s", r.Body)
	}
}
