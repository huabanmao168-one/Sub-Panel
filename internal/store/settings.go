package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
)

const runtimeSettingsKey = "runtime_settings_v1"
const previousRuntimeSettingsKey = "runtime_settings_previous_v1"
const seedEligibilityKey = "runtime_settings_seed_new_db"

// VerifiedIngressSince establishes a permanent boundary for historic traffic
// that could not be attributed to a trusted ingress peer.
func (s *Store) VerifiedIngressSince(now time.Time) (time.Time, error) {
	const key = "verified_ingress_since_v1"
	if _, err := s.db.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO NOTHING`, key, strconv.FormatInt(now.UnixMilli(), 10)); err != nil {
		return time.Time{}, err
	}
	value, err := s.GetMeta(key)
	if err != nil {
		return time.Time{}, err
	}
	ms, err := strconv.ParseInt(value, 10, 64)
	if err != nil || ms <= 0 {
		return time.Time{}, fmt.Errorf("无效的可信入口统计起点")
	}
	return time.UnixMilli(ms), nil
}

func initSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name IN ('tenants','detect_rules'))`).Scan(&existing); err != nil {
		return err
	}
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	var tenantPK int
	if err := tx.QueryRow(`SELECT pk FROM pragma_table_info('resolved_tokens') WHERE name='tenant'`).Scan(&tenantPK); err != nil {
		return err
	}
	if tenantPK == 0 {
		// Older databases keyed handled records by token alone, so one tenant
		// could overwrite another. Preserve NULL/empty as an all-tenant marker.
		if _, err := tx.Exec(`
			ALTER TABLE resolved_tokens RENAME TO resolved_tokens_legacy;
			CREATE TABLE resolved_tokens (token TEXT NOT NULL, tenant TEXT NOT NULL DEFAULT '', note TEXT, resolved_ts INTEGER NOT NULL, PRIMARY KEY(token, tenant));
			INSERT INTO resolved_tokens SELECT token, COALESCE(tenant,''), note, resolved_ts FROM resolved_tokens_legacy WHERE token IS NOT NULL;
			DROP TABLE resolved_tokens_legacy;
			CREATE INDEX idx_resolved_tenant_ts ON resolved_tokens(tenant, resolved_ts);`); err != nil {
			return err
		}
	}
	// Keep this decision across a failed import: an intentionally empty old table
	// must not be repopulated, and a failed new import must be retryable.
	seed := "yes"
	if existing {
		seed = "no"
	}
	if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO NOTHING`, seedEligibilityKey, seed); err != nil {
		return err
	}
	return tx.Commit()
}

// NeedsLegacyConfig reports whether the schema belongs to an installation that
// predates database settings. A missing YAML must not reset that installation.
func (s *Store) NeedsLegacyConfig() (bool, error) {
	var seed string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, seedEligibilityKey).Scan(&seed)
	return seed != "yes", err
}

// RuntimeConfig returns nil before the one-time import has completed.
func (s *Store) RuntimeConfig() (*config.Config, error) {
	var raw string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, runtimeSettingsKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c config.Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("读取 SQLite 系统设置: %w", err)
	}
	return &c, nil
}

func encodeRuntimeConfig(cfg *config.Config) ([]byte, error) {
	c := *cfg
	// Tenants and rules have their own tables. The database location is a bootstrap argument.
	c.Tenants, c.Paths, c.Storage.SQLitePath = nil, config.Paths{}, ""
	c.Detector.Rules, c.Detector.Windows, c.Detector.ObserveOnly = nil, nil, false
	c.Admin.PasswordHash, c.Admin.SessionKey = "", ""
	return json.Marshal(&c)
}

func (s *Store) SaveRuntimeConfig(cfg *config.Config) error {
	data, err := encodeRuntimeConfig(cfg)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO meta(k,v) SELECT ?,v FROM meta WHERE k=? AND v<>? ON CONFLICT(k) DO UPDATE SET v=excluded.v`, previousRuntimeSettingsKey, runtimeSettingsKey, string(data)); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, runtimeSettingsKey, string(data)); err != nil {
		return err
	}
	return tx.Commit()
}

// RestorePreviousRuntimeConfig rolls back system settings only (not credentials,
// tenant data or rules). It is intended for offline recovery of the admin listener.
func (s *Store) RestorePreviousRuntimeConfig() error {
	res, err := s.db.Exec(`UPDATE meta SET v=(SELECT v FROM meta WHERE k=?) WHERE k=? AND EXISTS(SELECT 1 FROM meta WHERE k=?)`, previousRuntimeSettingsKey, runtimeSettingsKey, previousRuntimeSettingsKey)
	if err := requireAffected(res, err); err != nil {
		return fmt.Errorf("没有可以恢复的上一份系统配置，或读写失败: %w", err)
	}
	return nil
}

// InitRuntimeConfig commits the one-time import and its marker together.
// Existing tenant and rule tables take precedence over legacy seeds.
func (s *Store) InitRuntimeConfig(cfg *config.Config, initialReportSecret string) error {
	data, err := encodeRuntimeConfig(cfg)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO NOTHING`, runtimeSettingsKey, string(data))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('admin_password_hash',?) ON CONFLICT(k) DO NOTHING`, cfg.Admin.PasswordHash); err != nil {
		return err
	}
	if initialReportSecret != "" {
		if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('report_secret',?) ON CONFLICT(k) DO NOTHING`, initialReportSecret); err != nil {
			return err
		}
	}
	var seed string
	if err := tx.QueryRow(`SELECT v FROM meta WHERE k=?`, seedEligibilityKey).Scan(&seed); err != nil {
		return err
	}
	if seed != "yes" {
		return tx.Commit()
	}
	now := time.Now().UnixMilli()
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		for _, t := range cfg.Tenants {
			if _, err := tx.Exec(`INSERT INTO tenants(name,host,subscribe_path,upstream,upstream_path,created_ts,updated_ts) VALUES(?,'',?,?,?,?,?)`,
				t.Name, t.SubscribePath, t.Upstream, t.UpstreamPath, now, now); err != nil {
				return fmt.Errorf("导入机场 %q: %w", t.Name, err)
			}
		}
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM detect_rules`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		for i, rule := range cfg.Detector.Rules {
			when, err := json.Marshal(rule.When)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO detect_rules(name,desc,severity,when_json,sort_order,created_ts,updated_ts) VALUES(?,?,'',?,?,?,?)`,
				rule.Name, rule.Desc, string(when), i, now, now); err != nil {
				return fmt.Errorf("导入触发规则 %q: %w", rule.Name, err)
			}
		}
	}
	return tx.Commit()
}
