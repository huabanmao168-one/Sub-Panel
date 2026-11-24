// sub-panel: Sub-Panel —— V2Board 订阅前置网关
//
// 用法:
//
//	sub-panel [-db /opt/Sub-Panel/data/sub-panel.db]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/cloudip"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/geoip"
	"github.com/huabanmao168/SubPanel/internal/proxy"
	"github.com/huabanmao168/SubPanel/internal/rules"
	"github.com/huabanmao168/SubPanel/internal/slidingwin"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
	"github.com/huabanmao168/SubPanel/internal/webui"
)

var Version = "0.1.0"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "hashpwd":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: sub-panel hashpwd <password>")
				os.Exit(2)
			}
			h, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), bcrypt.DefaultCost)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			fmt.Println(string(h))
			return
		case "legacy-db-path":
			if len(os.Args) != 3 {
				fmt.Fprintln(os.Stderr, "usage: sub-panel legacy-db-path <config.yml>")
				os.Exit(2)
			}
			legacy, err := config.LoadLegacy(os.Args[2])
			if err != nil {
				fmt.Fprintln(os.Stderr, "invalid legacy configuration")
				os.Exit(1)
			}
			path := legacy.Storage.SQLitePath
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(os.Args[2]), path)
			}
			fmt.Println(filepath.Clean(path))
			return
		case "restore-settings":
			fs := flag.NewFlagSet("restore-settings", flag.ExitOnError)
			dbPath := fs.String("db", config.DefaultDBPath, "SQLite 数据库路径")
			_ = fs.Parse(os.Args[2:])
			if err := restoreSettings(*dbPath); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("已恢复上一份系统设置；请启动服务验证。")
			return
		case "version":
			fmt.Println(Version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	var cfgPath, dbPath string
	fs := flag.NewFlagSet("sub-panel", flag.ExitOnError)
	fs.StringVar(&dbPath, "db", config.DefaultDBPath, "SQLite 数据库路径")
	fs.StringVar(&cfgPath, "c", config.LegacyConfigPath, "仅首次迁移时读取的旧 YAML 路径")
	_ = fs.Parse(os.Args[1:])
	legacyRequired := false
	fs.Visit(func(f *flag.Flag) { legacyRequired = legacyRequired || f.Name == "c" })

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	st, savedCfg, err := openSettings(dbPath, cfgPath, legacyRequired)
	if err != nil {
		logger.Error("加载数据库和配置失败", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	cfg := savedCfg.ForRuntime()

	if err := os.MkdirAll(filepathDir(cfg.HMACSaltFile), 0750); err != nil {
		logger.Error("创建 salt 目录失败", "err", err)
		os.Exit(1)
	}

	needExistingSalt, err := st.HasTokenIDs()
	if err != nil {
		logger.Error("读取订阅标识设置失败", "err", err)
		os.Exit(1)
	}
	if needExistingSalt {
		if _, err := os.Stat(cfg.HMACSaltFile); err != nil {
			logger.Error("缺少原有订阅标识盐文件；请从备份恢复", "err", err)
			os.Exit(1)
		}
	}
	salt, err := token.LoadOrCreateSalt(cfg.HMACSaltFile)
	if err != nil {
		logger.Error("加载 HMAC salt 失败", "err", err)
		os.Exit(1)
	}
	hasher := token.NewHasher(salt)
	if err := st.MigrateTokenIDs(hasher); err != nil {
		logger.Error("迁移订阅标识失败", "err", err)
		os.Exit(1)
	}

	bans := banlist.New(st)
	if err := bans.LoadFromStore(context.Background()); err != nil {
		logger.Error("加载封禁列表失败", "err", err)
		os.Exit(1)
	}

	// 给老数据补 report_id
	if err := st.BackfillReportIDs(); err != nil {
		logger.Error("补 report_id 失败", "err", err)
		os.Exit(1)
	}
	if err := loadTenantsFromDB(st, cfg); err != nil {
		logger.Error("加载机场配置失败", "err", err)
		os.Exit(1)
	}

	rs, err := loadDetectRulesFromDB(st)
	if err != nil {
		logger.Error("加载触发规则失败", "err", err)
		os.Exit(1)
	}
	// 用生效的数据库规则计算滑窗容量，不使用旧 YAML 阈值。
	detectorCfg := cfg.Detector
	detectorCfg.Rules = rs
	det, err := detector.New(&detectorCfg)
	if err != nil {
		logger.Error("检测器初始化失败", "err", err)
		os.Exit(1)
	}
	det.SetRules(rs)

	stopCh := make(chan struct{})
	slidingwin.RunGC(stopCh, time.Minute, det.GCTargets()...)

	// GeoIP xdb (ip2region 满载版) - 提供 IP -> 地理 + 运营商 + 用途类型 查询
	geo := geoip.Global()
	if p := cfg.GeoIP.XDBPath; p != "" {
		if err := geo.Load(p); err != nil {
			logger.Warn("加载 GeoIP xdb 失败,from_cloud_ip / country / usage_type 规则将失效", "path", p, "err", err)
		} else {
			snap := geo.Snapshot()
			logger.Info("GeoIP xdb 已加载", "path", p, "version", snap.Version)
		}
	} else {
		logger.Info("未配置 geoip.xdb_path,GeoIP 功能禁用")
	}

	// 云 IP 匹配器 (底层走 GeoIP xdb,按 ISP 字段反推云厂商)
	cloudMatcher := cloudip.NewMatcher()
	cloudFetcher := cloudip.NewFetcher(cloudMatcher, st, logger)
	det.SetCloudLookup(cloudMatcher.Match)
	// 注入 GeoIP 查询(给 country/usage_type/isp 规则用)
	det.SetGeoLookup(func(ip string) *detector.GeoInfo {
		info := geo.Lookup(ip)
		if info == nil {
			return nil
		}
		return &detector.GeoInfo{
			Country:   info.Country,
			ISOCode:   info.ISOCode,
			ISP:       info.ISP,
			UsageType: info.UsageType,
		}
	})
	ctxFetch, cancelFetch := context.WithCancel(context.Background())
	cloudFetcher.RunPeriodic(ctxFetch, 7*24*time.Hour)

	// 动态规则(IP 白名单)
	rulesMgr := rules.NewManager(st)
	if err := rulesMgr.Reload(); err != nil {
		logger.Error("加载动态规则失败", "err", err)
		os.Exit(1)
	}
	det.SetDynamicIPWhitelist(rulesMgr.IPWhitelisted)

	gw, err := proxy.NewGateway(cfg, hasher, st, bans, det, logger)
	if err != nil {
		logger.Error("网关初始化失败", "err", err)
		os.Exit(1)
	}
	// 注入 GeoIP 查询(给请求日志打 country/usage_type/isp)
	gw.SetGeoLookup(func(ip string) (string, string, string) {
		info := geo.Lookup(ip)
		if info == nil {
			return "", "", ""
		}
		country := info.ISOCode
		if country == "" {
			country = info.Country
		}
		// ip2region 把港澳台 ISO 标为 CN,需要按中文名修正,
		// 否则「禁海外」规则无法拦截港澳台。
		if country == "CN" {
			switch {
			case strings.Contains(info.Country, "香港"):
				country = "HK"
			case strings.Contains(info.Country, "澳门"):
				country = "MO"
			case strings.Contains(info.Country, "台湾"):
				country = "TW"
			}
		}
		return country, info.UsageType, info.ISP
	})
	gw.SetCloudLookup(cloudMatcher.Match)

	// 全局黑名单(海外/云/ISP/浏览器)
	bl := blacklist.New(st)
	gw.SetBlacklist(bl)
	// IP 白名单优先级最高,在网关入口短路放行
	gw.SetIPWhitelist(rulesMgr.IPWhitelisted)
	// UA 黑名单优先级次于 IP 白名单,高于全局黑名单
	gw.SetUABlacklist(rulesMgr.IsUABlacklisted)

	// 启动时恢复「一键透传」开关(store.meta 持久化)
	if v, _ := st.GetMeta("passthrough_all"); v == "true" {
		gw.SetPassthroughAll(true)
		logger.Warn("一键透传已开启 — 所有规则/黑白名单短路")
	}

	// startup: 把库里的展示定制规则推进网关(热生效前的初始加载)
	if rules, err := st.ListDisplayRules(); err == nil {
		gw.SetDisplayRules(rules)
	} else {
		logger.Warn("加载订阅展示规则失败", "err", err)
	}

	// admin server (先创建 ui,subMux 也要用它的 ReportHandler)
	ui := webui.NewServer(savedCfg, st, bans, hasher, cloudMatcher, cloudFetcher, rulesMgr, gw, det, bl, logger)
	verifiedSince, err := st.VerifiedIngressSince(time.Now())
	if err != nil {
		logger.Error("初始化可信入口统计失败", "err", err)
		os.Exit(1)
	}
	ui.SetVerifiedIngressSince(verifiedSince)
	logger.Info("订阅入口仅允许配置的前置代理", "peers", savedCfg.AllowedIngressPeers(), "statistics_since", verifiedSince)

	// 反代 server
	subMux := http.NewServeMux()
	subMux.HandleFunc("/healthz", proxy.Healthz)
	subMux.Handle("/r/", gw.RequireIngress(ui.ReportHandler()))
	subMux.Handle("/", gw)
	subSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           subMux,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	adminSrv := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           ui.Handler(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("订阅网关监听中", "addr", cfg.Listen)
		if err := subSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("订阅网关启动失败", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		logger.Info("管理面监听中", "addr", cfg.AdminListen)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("管理面启动失败", "err", err)
			os.Exit(1)
		}
	}()

	// 定时 vacuum
	go runVacuum(stopCh, st, cfg, logger)

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("收到退出信号", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = subSrv.Shutdown(ctx)
	_ = adminSrv.Shutdown(ctx)
	cancelFetch()
	close(stopCh)
	time.Sleep(200 * time.Millisecond) // 让异步 writer flush
	logger.Info("已退出")
}

func runVacuum(stop <-chan struct{}, st *store.Store, cfg *config.Config, logger *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := st.Vacuum(ctx, cfg.Storage.Retention.Events.Std(), cfg.Storage.Retention.Incidents.Std())
			cancel()
			if err != nil {
				logger.Warn("数据清理失败", "err", err)
			}
		}
	}
}

func filepathDir(p string) string {
	// 极简版 filepath.Dir,避免引入额外包(其实 stdlib 已经有,这里用 stdlib)
	if p == "" {
		return "."
	}
	i := len(p) - 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func printHelp() {
	fmt.Println(`Sub-Panel - V2Board 订阅前置网关

用法:
  sub-panel [-db <sqlite.db>]      启动服务(反代 + Web UI)
  sub-panel [-db <sqlite.db>] -c <legacy.yml>   首次读取指定的旧 YAML
  sub-panel restore-settings [-db <sqlite.db>] 停服后恢复上一份系统配置
  sub-panel version                打印版本
  sub-panel help                   本帮助`)
}

// loadTenantsFromDB: 用 DB 里的(启用的)tenants 覆盖 cfg.Tenants,作为启动时的真实数据源。
func loadTenantsFromDB(st *store.Store, cfg *config.Config) error {
	rows, err := st.ListTenants()
	if err != nil {
		return err
	}
	out := make([]config.Tenant, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		out = append(out, config.Tenant{
			Name:          r.Name,
			SubscribePath: r.SubscribePath,
			Upstream:      r.Upstream,
			UpstreamPath:  r.UpstreamPath,
		})
	}
	cfg.Tenants = out
	return nil
}

// loadDetectRulesFromDB 读 DB 里启用的规则,反序列化成 config.Rule slice。
func loadDetectRulesFromDB(st *store.Store) ([]config.Rule, error) {
	rows, err := st.ListDetectRules()
	if err != nil {
		return nil, err
	}
	out := make([]config.Rule, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		var when config.When
		if err := json.Unmarshal([]byte(r.WhenJSON), &when); err != nil {
			return nil, fmt.Errorf("规则 %s 反序列化失败: %w", r.Name, err)
		}
		out = append(out, config.Rule{
			Name: r.Name,
			Desc: r.Desc,
			When: when,
		})
	}
	return out, nil
}
