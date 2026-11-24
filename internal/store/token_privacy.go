package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/huabanmao168/SubPanel/internal/token"
)

const tokenPrivacyKey = "token_identifiers_v1"

func (s *Store) HasTokenIDs() (bool, error) {
	value, err := s.GetMeta(tokenPrivacyKey)
	return value == "yes", err
}

// MigrateTokenIDs converts old raw credentials and removes old request paths in
// one transaction. Retain the existing salt when migrating or restoring a DB.
func (s *Store) MigrateTokenIDs(h *token.Hasher) error {
	if done, err := s.HasTokenIDs(); err != nil || done {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range []struct{ table, column string }{
		{"events", "token_hash"}, {"incidents", "token_hash"}, {"user_reports", "token"}, {"resolved_tokens", "token"},
	} {
		if err := migrateIdentifierTable(tx, h, item.table, item.column); err != nil {
			return fmt.Errorf("migrate %s: %w", item.table, err)
		}
	}
	// Subscription paths may embed credentials, even on requests that did not
	// match a configured tenant. Existing free-text paths are not safe to retain.
	if _, err := tx.Exec(`UPDATE events SET path=COALESCE((SELECT t.subscribe_path FROM tenants t WHERE t.name=events.tenant),'')`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?, 'yes') ON CONFLICT(k) DO UPDATE SET v=excluded.v`, tokenPrivacyKey); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

func migrateIdentifierTable(tx *sql.Tx, h *token.Hasher, table, column string) error {
	read := `SELECT rowid,` + column + ` FROM ` + table + ` WHERE rowid>? AND ` + column + `<>'' ORDER BY rowid LIMIT 500`
	write := `UPDATE ` + table + ` SET ` + column + `=? WHERE rowid=?`
	var cursor int64
	for {
		rows, err := tx.Query(read, cursor)
		if err != nil {
			return err
		}
		type entry struct {
			id  int64
			raw string
		}
		var batch []entry
		for rows.Next() {
			var row entry
			if err := rows.Scan(&row.id, &row.raw); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(batch) == 0 {
			return err
		}
		for _, row := range batch {
			cursor = row.id
			if strings.HasPrefix(row.raw, token.IDPrefix) && h.Lookup(row.raw) == row.raw {
				continue
			}
			if _, err := tx.Exec(write, h.Hash(row.raw), row.id); err != nil {
				return err
			}
		}
	}
}
