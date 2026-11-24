package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSuspectReviewSeparatesDeliveryAndRejection(t *testing.T) {
	st := openRefactorStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	for _, report := range []UserReport{
		{Tenant: "east", Token: "first", Email: "same@example.invalid"},
		{Tenant: "east", Token: "second", Email: "same@example.invalid"},
		{Tenant: "west", Token: "first", Email: "same@example.invalid"},
		{Tenant: "west", Token: "failure-only", Email: "none@example.invalid"},
		{Tenant: "west", Token: "denied-only", Email: "none@example.invalid"},
	} {
		if err := st.UpsertUserReport(report); err != nil {
			t.Fatal(err)
		}
	}
	event := func(tenant, token, ip, ua, act string, status int, ts time.Time) Event {
		return Event{Tenant: tenant, TokenHash: token, ClientIP: ip, UA: ua, Action: act, Status: status, TS: ts}
	}
	if err := st.insertEvents([]Event{
		event("east", "first", "192.0.2.1", "Client A", "pass", 200, now),
		event("east", "first", "192.0.2.2", "Client A ", "pass", 200, now),
		event("east", "first", "192.0.2.3", "Client A", "display", 200, now),
		event("east", "first", "192.0.2.4", "Client B", "pass", 200, now),
		event("east", "first", "192.0.2.5", "Client B", "pass", 200, now),
		event("east", "first", "192.0.2.6", " ", "pass", 200, now),
		event("east", "first", "198.51.100.8", "Blocked client", "deny", 403, now),
		event("east", "first", "198.51.100.9", "Failed client", "pass", 502, now),
		event("east", "first", "192.0.2.99", "Old Client", "pass", 200, now.Add(-2*time.Hour)),
		event("east", "second", "192.0.2.1", "Client A", "pass", 200, now),
		event("west", "first", "192.0.2.2", "Other client", "pass", 200, now),
		event("west", "failure-only", "192.0.2.3", "Failed client", "pass", 502, now),
		event("west", "denied-only", "192.0.2.4", "Blocked client", "deny", 403, now),
	}); err != nil {
		t.Fatal(err)
	}
	query := func(f SuspectFilter) SuspectPage {
		t.Helper()
		f.Since = now.Add(-time.Hour)
		page, err := st.QuerySuspects(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	page := query(SuspectFilter{Signal: "multiple"})
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("multiple-source filter: %+v", page)
	}
	got := page.Items[0]
	if got.Tenant != "east" || got.Token != "first" || got.PullCount != 6 || got.DistinctIPs != 6 || got.DistinctUAs != 2 || got.Denied != 1 || !got.MultiSource {
		t.Fatalf("bad aggregation: %+v", got)
	}
	if page := query(SuspectFilter{Tenant: "east"}); page.Total != 2 {
		t.Fatalf("same email collapsed independent subscriptions: %+v", page)
	}
	if page := query(SuspectFilter{Signal: "denied", Search: "198.51.100.8"}); page.Total != 1 || page.Items[0].Tenant != "east" {
		t.Fatalf("search missed matching request IP: %+v", page)
	}
	if page := query(SuspectFilter{Limit: 1, Offset: 1, Sort: "denied"}); page.Total != 4 || len(page.Items) != 1 || page.Items[0].Denied != 1 {
		t.Fatalf("paging/sort ran before filtering: %+v", page)
	}
	detail, err := st.QuerySuspectDetail(ctx, "first", "east", now.Add(-time.Hour))
	if err != nil || len(detail.IPs) != 6 || len(detail.UAs) != 2 || len(detail.Bindings) != 5 {
		t.Fatalf("detail diverged from successful delivery metrics: %+v %v", detail, err)
	}
	if err := st.AddResolvedToken(ctx, "first", "east", "checked"); err != nil {
		t.Fatal(err)
	}
	if page := query(SuspectFilter{Search: "first"}); page.Total != 1 || page.Items[0].Tenant != "west" {
		t.Fatalf("marking one tenant affected another: %+v", page)
	}
	if err := st.AddResolvedToken(ctx, "first", "west", "also checked"); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveResolvedToken(ctx, "first", "east"); err != nil {
		t.Fatal(err)
	}
	if page := query(SuspectFilter{Search: "first"}); page.Total != 1 || page.Items[0].Tenant != "east" {
		t.Fatalf("restore removed the wrong scope: %+v", page)
	}
}

func TestDeniedIPRankingKeepsUniqueRuleNames(t *testing.T) {
	st := openRefactorStore(t)
	now := time.Now()
	if err := st.insertIncidents([]Incident{
		{TS: now, Tenant: "east", ClientIP: "192.0.2.8", Action: "deny", RuleTags: []string{"UA_Blacklist", "rule | custom"}},
		{TS: now.Add(time.Second), Tenant: "east", ClientIP: "192.0.2.8", Action: "deny", RuleTags: []string{"UA_Blacklist"}},
		{TS: now, Tenant: "west", ClientIP: "192.0.2.8", Action: "deny", RuleTags: []string{"unrelated"}},
		{TS: now, Tenant: "east", ClientIP: "192.0.2.9", Action: "pass", RuleTags: []string{"pass"}},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.AggIncidentsByIP(context.Background(), IncidentFilter{Tenant: "east", Action: "deny", Since: now.Add(-time.Minute), Limit: 20})
	if err != nil || len(rows) != 1 || rows[0].Count != 2 || len(rows[0].Tags) != 2 || rows[0].Tags[0] != "UA_Blacklist" || rows[0].Tags[1] != "rule | custom" {
		t.Fatalf("ranked tags must be unique and keep their literal names: %+v %v", rows, err)
	}
}

func TestLegacyResolvedTokensUpgradePreservesGlobalAndTenantRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE resolved_tokens(token TEXT PRIMARY KEY,tenant TEXT,note TEXT,resolved_ts INTEGER NOT NULL);
		CREATE INDEX idx_resolved_tenant_ts ON resolved_tokens(tenant,resolved_ts);
		INSERT INTO resolved_tokens VALUES('global',NULL,'old global',1),('scoped','a','old scoped',2);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.AddResolvedToken(ctx, "scoped", "b", "new scoped"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListResolvedTokens(ctx, "a")
	if err != nil || len(rows) != 2 || rows[0].Note != "old scoped" || rows[1].Tenant != "" || rows[1].Note != "old global" {
		t.Fatalf("legacy rows changed: %+v %v", rows, err)
	}
}
