package store

import (
	"context"
	"strings"
	"time"
)

// Only successful subscription deliveries contribute to source diversity.
const deliveredSubscription = `e.action IN ('pass','display') AND e.status BETWEEN 200 AND 299`
const blockedSubscription = `e.action='deny' AND e.status=403`
const multipleSourceSignal = `distinct_ips>=5 AND distinct_uas>=2`

type SuspectRow struct {
	UserReport
	PullCount    int   `json:"pull_count"`
	DistinctIPs  int   `json:"distinct_ips"`
	DistinctUAs  int   `json:"distinct_uas"`
	Denied       int   `json:"denied"`
	LastActivity int64 `json:"last_activity"` // Unix milliseconds, from gateway events
	MultiSource  bool  `json:"multi_source"`
}

type SuspectFilter struct {
	Tenant, Search, Sort, Signal string
	Since                        time.Time
	Limit, Offset                int
}

type SuspectPage struct {
	Items []SuspectRow `json:"items"`
	Total int          `json:"total"`
}

func (s *Store) QuerySuspects(ctx context.Context, f SuspectFilter) (SuspectPage, error) {
	page := SuspectPage{Items: []SuspectRow{}}
	q := `WITH stats AS (
		SELECT e.tenant, e.token_hash,
		  SUM(CASE WHEN ` + deliveredSubscription + ` THEN 1 ELSE 0 END) AS pull_count,
		  SUM(CASE WHEN ` + blockedSubscription + ` THEN 1 ELSE 0 END) AS denied,
		  COUNT(DISTINCT CASE WHEN ` + deliveredSubscription + ` THEN NULLIF(TRIM(e.client_ip),'') END) AS distinct_ips,
		  COUNT(DISTINCT CASE WHEN ` + deliveredSubscription + ` THEN NULLIF(TRIM(e.ua),'') END) AS distinct_uas,
		  MAX(e.ts) AS last_activity
		FROM events e
		WHERE e.ts>=? AND e.token_hash<>'' AND ((` + deliveredSubscription + `) OR (` + blockedSubscription + `))`
	args := []any{f.Since.UnixMilli()}
	if f.Tenant != "" {
		q += ` AND e.tenant=?`
		args = append(args, f.Tenant)
	}
	q += ` GROUP BY e.tenant,e.token_hash
	)
	SELECT r.token,r.tenant,COALESCE(r.uuid,''),COALESCE(r.email,''),COALESCE(r.traffic_used,0),COALESCE(r.traffic_total,0),
	  COALESCE(r.wallet_balance,0),COALESCE(r.commission_balance,0),COALESCE(r.user_created_at,''),COALESCE(r.last_ip,''),
	  COALESCE(r.last_ua,''),COALESCE(r.site_domain,''),r.report_count,r.first_seen,r.last_seen,
	  pull_count,distinct_ips,distinct_uas,denied,last_activity,(` + multipleSourceSignal + `),COUNT(*) OVER()
	FROM stats JOIN user_reports r ON r.tenant=stats.tenant AND r.token=stats.token_hash
	WHERE NOT EXISTS(SELECT 1 FROM resolved_tokens h WHERE h.token=r.token AND (h.tenant='' OR h.tenant=r.tenant))`
	switch f.Signal {
	case "multiple":
		q += ` AND (` + multipleSourceSignal + `)`
	case "denied":
		q += ` AND denied>0`
	}
	if term := strings.ToLower(strings.TrimSpace(f.Search)); term != "" {
		q += ` AND (instr(lower(r.token),?)>0 OR instr(lower(r.email),?)>0 OR instr(lower(r.last_ip),?)>0 OR EXISTS (
			SELECT 1 FROM events e WHERE e.tenant=r.tenant AND e.token_hash=r.token AND e.ts>=?
			AND ((` + deliveredSubscription + `) OR (` + blockedSubscription + `)) AND instr(lower(e.client_ip),?)>0))`
		args = append(args, term, term, term, f.Since.UnixMilli(), term)
	}
	order := "distinct_ips DESC, distinct_uas DESC, pull_count DESC"
	switch f.Sort {
	case "uas":
		order = "distinct_uas DESC, distinct_ips DESC"
	case "pull":
		order = "pull_count DESC, distinct_ips DESC"
	case "denied":
		order = "denied DESC, distinct_ips DESC"
	case "recent":
		order = "last_activity DESC"
	case "usage":
		order = "CASE WHEN r.traffic_total>0 THEN 0 ELSE 1 END, CAST(r.traffic_used AS REAL)/NULLIF(r.traffic_total,0) ASC"
	}
	if f.Limit < 1 || f.Limit > 100 {
		f.Limit = 20
	}
	q += " ORDER BY " + order + ", last_activity DESC, r.tenant, r.token LIMIT ? OFFSET ?"
	args = append(args, f.Limit, max(0, f.Offset))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var r SuspectRow
		if err := rows.Scan(&r.Token, &r.Tenant, &r.UUID, &r.Email, &r.TrafficUsed, &r.TrafficTotal, &r.WalletBalance, &r.CommissionBalance,
			&r.UserCreatedAt, &r.LastIP, &r.LastUA, &r.SiteDomain, &r.ReportCount, &r.FirstSeen, &r.LastSeen,
			&r.PullCount, &r.DistinctIPs, &r.DistinctUAs, &r.Denied, &r.LastActivity, &r.MultiSource, &page.Total); err != nil {
			return page, err
		}
		page.Items = append(page.Items, r)
	}
	return page, rows.Err()
}
