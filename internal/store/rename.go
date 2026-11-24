package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

var ErrNameConflict = errors.New("名称已存在")
var ErrRecordNotFound = errors.New("找不到正在编辑的记录")
var ErrTenantPathConflict = errors.New("订阅路径已被其他机场占用")

// SaveTenant writes an existing tenant in place, preserving the report ID and
// relocating records keyed by the old tenant name in the same transaction.
func (s *Store) SaveTenant(original string, row TenantRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM tenants WHERE name=?)`, row.Name).Scan(&exists); err != nil {
		return err
	}
	if exists && original != row.Name {
		return ErrNameConflict
	}
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM tenants WHERE name<>? AND rtrim(subscribe_path,'/')=?)`, original, strings.TrimRight(row.SubscribePath, "/")).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrTenantPathConflict
	}
	now := time.Now().UnixMilli()
	if original == "" {
		if _, err := tx.Exec(`INSERT INTO tenants(name,host,subscribe_path,upstream,upstream_path,report_id,enabled,created_ts,updated_ts) VALUES(?,'',?,?,?,lower(hex(randomblob(16))),?,?,?)`, row.Name, row.SubscribePath, row.Upstream, row.UpstreamPath, row.Enabled, now, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	res, err := tx.Exec(`UPDATE tenants SET name=?, subscribe_path=?, upstream=?, upstream_path=?, enabled=?, updated_ts=? WHERE name=?`, row.Name, row.SubscribePath, row.Upstream, row.UpstreamPath, row.Enabled, now, original)
	if err := requireAffected(res, err); err != nil {
		return err
	}
	if original != row.Name {
		for _, statement := range []string{
			`UPDATE events SET tenant=? WHERE tenant=?`,
			`UPDATE incidents SET tenant=? WHERE tenant=?`,
			`UPDATE user_reports SET tenant=? WHERE tenant=?`,
			`UPDATE display_rules SET tenant=? WHERE tenant=?`,
			`UPDATE resolved_tokens SET tenant=? WHERE tenant=?`,
		} {
			if _, err := tx.Exec(statement, row.Name, original); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) SaveDetectRule(original string, row DetectRuleRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM detect_rules WHERE name=?)`, row.Name).Scan(&exists); err != nil {
		return err
	}
	if exists && original != row.Name {
		return ErrNameConflict
	}
	now := time.Now().Unix()
	if original == "" {
		if _, err := tx.Exec(`INSERT INTO detect_rules(name,desc,severity,when_json,enabled,sort_order,created_ts,updated_ts) VALUES(?,?,'',?,?,?,?,?)`, row.Name, row.Desc, row.WhenJSON, row.Enabled, row.SortOrder, now, now); err != nil {
			return err
		}
	} else {
		res, err := tx.Exec(`UPDATE detect_rules SET name=?,desc=?,when_json=?,enabled=?,sort_order=?,updated_ts=? WHERE name=?`, row.Name, row.Desc, row.WhenJSON, row.Enabled, row.SortOrder, now, original)
		if err := requireAffected(res, err); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func requireAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return ErrRecordNotFound
	}
	return err
}
