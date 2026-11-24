// admin_settings.go: 改密码 + 一键透传
package webui

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// apiChangePassword 改密。
// body: {old_password, new_password}
// 校验旧密码 → bcrypt 新密码 → 写入 store.meta admin_password_hash
// 不重启即生效(apiLogin 会优先读 meta)
func (s *Server) apiChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if len(body.NewPassword) < 8 || len(body.NewPassword) > 72 {
		writeJSON(w, 400, map[string]any{"error": "新密码须为 8–72 字节"})
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	pwHash, err := s.st.GetMeta("admin_password_hash")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "读取管理员凭据失败"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(body.OldPassword)); err != nil {
		writeJSON(w, 403, map[string]any{"error": "原密码错误"})
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.st.SetMeta("admin_password_hash", string(newHash)); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if s.cfg.Storage.SQLitePath != "" {
		if err := os.Remove(config.InitialPasswordPath(s.cfg.Storage.SQLitePath)); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("初始密码文件未能清除，请手动移除", "err", err)
		}
	}
	// 顺手销毁所有会话,强制重新登录
	s.sessionMu.Lock()
	s.sessions = map[string]session{}
	s.sessionMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiPassthrough 一键透传开关。
// GET:查当前状态。POST {enabled: bool}:写 store.meta passthrough_all,网关代理入口短路。
func (s *Server) apiPassthrough(w http.ResponseWriter, r *http.Request) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	if r.Method == "GET" {
		v, err := s.st.GetMeta("passthrough_all")
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "读取透传状态失败"})
			return
		}
		writeJSON(w, 200, map[string]any{"enabled": strings.EqualFold(v, "true")})
		return
	}
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		writeJSON(w, 400, map[string]any{"error": "必须提供布尔值 enabled"})
		return
	}
	v := "false"
	if *body.Enabled {
		v = "true"
	}
	if err := s.st.SetMeta("passthrough_all", v); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 热生效:通知 gateway
	if s.gw != nil {
		s.gw.SetPassthroughAll(*body.Enabled)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": *body.Enabled})
}

// SetRuntimeRestart installs the supervisor restart callback before serving HTTP.
func (s *Server) SetRuntimeRestart(restart func()) { s.runtimeRestart = restart }

func (s *Server) apiRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		writeJSON(w, 405, map[string]any{"error": "GET or PUT only"})
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := s.st.RuntimeConfig()
	if err != nil || cfg == nil {
		writeJSON(w, 500, map[string]any{"error": "读取数据库设置失败"})
		return
	}
	if r.Method == http.MethodPut {
		if s.runtimeRestartQueued {
			writeJSON(w, 409, map[string]any{"error": "配置已保存，服务正在重启"})
			return
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType != "application/json" {
			writeJSON(w, 415, map[string]any{"error": "需要 application/json"})
			return
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		var input config.RuntimeSettings
		if err := dec.Decode(&input); err != nil || dec.Decode(new(any)) != io.EOF {
			writeJSON(w, 400, map[string]any{"error": "无效的系统设置"})
			return
		}
		cfg, err = cfg.WithRuntimeSettings(input)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		if err := s.st.SaveRuntimeConfig(cfg); err != nil {
			writeJSON(w, 500, map[string]any{"error": "保存数据库设置失败"})
			return
		}
	}
	active, saved := s.cfg.RuntimeSettings(), cfg.RuntimeSettings()
	pending := !reflect.DeepEqual(active, saved)
	restart := pending && r.Method == http.MethodPut && r.URL.Query().Get("restart") == "1" && s.runtimeRestart != nil
	if restart {
		s.runtimeRestartQueued = true
	}
	writeJSON(w, 200, map[string]any{"active": active, "saved": saved, "restart_required": pending,
		"restart_supported": s.runtimeRestart != nil, "restart_scheduled": s.runtimeRestartQueued})
	if restart {
		_ = http.NewResponseController(w).Flush()
		time.AfterFunc(500*time.Millisecond, s.runtimeRestart)
	}
}
