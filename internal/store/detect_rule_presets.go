package store

import (
	"math"
	"time"
)

// InsertDetectRulePresets adds disabled rules as a single transaction, without
// overwriting an existing name. The caller serializes policy changes.
func (s *Store) InsertDetectRulePresets(rows []DetectRuleRow) ([]string, error) {
	inserted := make([]string, 0, len(rows))
	if len(rows) == 0 {
		return inserted, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var sort int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(sort_order),0) FROM detect_rules`).Scan(&sort); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	for _, row := range rows {
		if sort < math.MaxInt64 {
			sort++
		}
		res, err := tx.Exec(`INSERT INTO detect_rules(name,desc,severity,when_json,enabled,sort_order,created_ts,updated_ts)
			VALUES(?,?,'',?,0,?,?,?) ON CONFLICT(name) DO NOTHING`, row.Name, row.Desc, row.WhenJSON, sort, now, now)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 1 {
			inserted = append(inserted, row.Name)
		}
	}
	return inserted, tx.Commit()
}

func (s *Store) SetDetectRuleEnabled(name string, enabled bool) error {
	res, err := s.db.Exec(`UPDATE detect_rules SET enabled=?,updated_ts=? WHERE name=?`, enabled, time.Now().Unix(), name)
	return requireAffected(res, err)
}
