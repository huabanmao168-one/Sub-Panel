package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/token"
)

func openRefactorStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "panel.db"), time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestTenantRenamePreservesIDAndRelations(t *testing.T) {
	st := openRefactorStore(t)
	old := TenantRow{Name: "old", SubscribePath: "/sub/old", Upstream: "https://example.invalid", Enabled: true}
	if err := st.SaveTenant("", old); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTenant("", TenantRow{Name: "taken", SubscribePath: "/sub/taken", Upstream: old.Upstream, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListTenants()
	if err != nil || len(rows) != 2 || rows[0].ReportID == "" {
		t.Fatal("missing tenant report ID")
	}
	id := rows[0].ReportID
	if err := st.UpsertUserReport(UserReport{Token: "test-id", Tenant: old.Name, Email: "fixture@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := st.insertEvents([]Event{{TS: time.Now(), Tenant: old.Name, ClientIP: "192.0.2.7"}}); err != nil {
		t.Fatal(err)
	}
	conflict := old
	conflict.Name = "taken"
	if err := st.SaveTenant(old.Name, conflict); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("rename conflict: %v", err)
	}
	if got, err := st.GetTenantByReportID(id); err != nil || got.Name != old.Name {
		t.Fatal("failed rename changed the old tenant")
	}
	newRow := old
	newRow.Name = "renamed"
	if err := st.SaveTenant(old.Name, newRow); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetTenantByReportID(id); err != nil || got.Name != newRow.Name {
		t.Fatal("report ID or new name was lost")
	}
	if report, err := st.GetUserReportByToken("test-id", newRow.Name); err != nil || report == nil {
		t.Fatal("report did not move")
	}
	if evs, err := st.QueryEvents(context.Background(), EventFilter{Tenant: newRow.Name}); err != nil || len(evs) != 1 {
		t.Fatal("historical event did not move")
	}
}

func TestDetectRenameConflictDoesNotDeleteOriginal(t *testing.T) {
	st := openRefactorStore(t)
	if err := st.SaveDetectRule("", DetectRuleRow{Name: "original", WhenJSON: `{}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDetectRule("", DetectRuleRow{Name: "conflict", WhenJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDetectRule("original", DetectRuleRow{Name: "conflict"}); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := st.SaveDetectRule("original", DetectRuleRow{Name: "updated", WhenJSON: `{}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListDetectRules()
	if err != nil || len(rows) != 2 || rows[1].Name != "updated" {
		t.Fatal("rename did not preserve both records")
	}
}

func TestTokenMigrationPreservesLookupAndScrubsPath(t *testing.T) {
	st := openRefactorStore(t)
	ctx := context.Background()
	const raw = "fixture-credential"
	const tenant = "fixture"
	if err := st.SaveTenant("", TenantRow{Name: tenant, SubscribePath: "/sub/fixture", Upstream: "https://example.invalid", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.insertEvents([]Event{{TS: time.Now(), Tenant: tenant, ClientIP: "192.0.2.1", TokenHash: raw, Path: "/sub/fixture/" + raw}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUserReport(UserReport{Tenant: tenant, Token: raw}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddResolvedToken(ctx, raw, tenant, "test"); err != nil {
		t.Fatal(err)
	}
	h := token.NewHasher([]byte("test salt"))
	for i := 0; i < 2; i++ {
		if err := st.MigrateTokenIDs(h); err != nil {
			t.Fatal(err)
		}
	}
	events, err := st.QueryEvents(ctx, EventFilter{TokenHash: h.Hash(raw)})
	if err != nil || len(events) != 1 || events[0].Path != "/sub/fixture" || events[0].TokenHash == raw {
		t.Fatal("migration did not redact and link history")
	}
	report, err := st.GetUserReportByToken(h.Hash(raw), tenant)
	if err != nil || report == nil {
		t.Fatal("migrated report no longer matches")
	}
	resolved, err := st.ListResolvedTokens(ctx, tenant)
	if err != nil || len(resolved) != 1 || resolved[0].Token != h.Hash(raw) {
		t.Fatal("resolved record lost")
	}
}

func TestCursorStableForSameTimestampAndNewRows(t *testing.T) {
	st := openRefactorStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	row := Event{TS: now, Tenant: "fixture", ClientIP: "192.0.2.1"}
	if err := st.insertEvents([]Event{row, row, row}); err != nil {
		t.Fatal(err)
	}
	first, err := st.QueryEvents(ctx, EventFilter{Limit: 2})
	if err != nil || len(first) != 2 {
		t.Fatal("expected first two rows")
	}
	if err := st.insertEvents([]Event{row}); err != nil {
		t.Fatal(err)
	}
	next, err := st.QueryEvents(ctx, EventFilter{Limit: 2, BeforeTS: first[1].TS, BeforeID: first[1].ID})
	if err != nil || len(next) != 1 || next[0].ID >= first[1].ID {
		t.Fatal("cursor skipped or duplicated rows")
	}
}

func TestRestoreSettingsKeepsCredentials(t *testing.T) {
	st := openRefactorStore(t)
	cfg := config.Defaults("/opt/test.db")
	cfg.Admin.PasswordHash = "fixture-hash"
	if err := st.InitRuntimeConfig(cfg, "fixture-secret"); err != nil {
		t.Fatal(err)
	}
	cfg.AdminListen = "127.0.0.1:30100"
	if err := st.SaveRuntimeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRuntimeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta("admin_password_hash", "updated-fixture-hash"); err != nil {
		t.Fatal(err)
	}
	if err := st.RestorePreviousRuntimeConfig(); err != nil {
		t.Fatal(err)
	}
	saved, err := st.RuntimeConfig()
	if err != nil || saved.AdminListen != "127.0.0.1:19090" {
		t.Fatal("previous listener was not restored")
	}
	if hash, err := st.GetMeta("admin_password_hash"); err != nil || hash != "updated-fixture-hash" {
		t.Fatal("rollback changed credentials")
	}
}
