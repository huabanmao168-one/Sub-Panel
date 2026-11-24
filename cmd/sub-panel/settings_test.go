package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/store"
)

func writeLegacy(t *testing.T, path, db string) {
	t.Helper()
	data := fmt.Sprintf(`listen: "127.0.0.1:20001"
admin_listen: "127.0.0.1:20002"
hmac_salt_file: %q
storage:
  sqlite_path: %q
  batch_flush_interval: 20ms
admin:
  username: legacy-admin
  password_hash: legacy-hash
real_ip:
  trust_headers: [X-Real-IP]
  trust_proxies: [127.0.0.1]
tenants:
  - name: sample
    subscribe_path: /sub/sample
    upstream: https://example.invalid
detector:
  whitelist:
    ips: [192.0.2.5]
  rules:
    - name: sample
      when:
        token_freq: {window: 3h, gte: 12}
`, filepath.Join(filepath.Dir(db), "salt"), db)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsWithoutYAML(t *testing.T) {
	dir := t.TempDir()
	st, cfg, err := openSettings(filepath.Join(dir, "panel.db"), filepath.Join(dir, "missing.yml"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if cfg.AdminListen != "127.0.0.1:19090" || cfg.Admin.Username != "admin" {
		t.Fatal("unexpected fresh install settings")
	}
	passwordPath := config.InitialPasswordPath(cfg.Storage.SQLitePath)
	info, err := os.Stat(passwordPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("initial password file must be private")
	}
	pw, err := os.ReadFile(passwordPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.GetMeta("admin_password_hash")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), pw[:len(pw)-1]) != nil {
		t.Fatal("initial password does not match database credentials")
	}
	if key, err := st.GetMeta("report_secret"); err != nil || len(key) < 20 {
		t.Fatal("fresh installs must initialize reporting authentication")
	}
	if rules, err := loadDetectRulesFromDB(st); err != nil || len(rules) != 2 {
		t.Fatalf("default rules: %d, %v", len(rules), err)
	}
}

func TestLegacySettingsImportedOnce(t *testing.T) {
	dir := t.TempDir()
	db, legacy := filepath.Join(dir, "legacy.db"), filepath.Join(dir, "config.yml")
	writeLegacy(t, legacy, db)
	st, cfg, err := openSettings(db, legacy, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Username != "legacy-admin" || cfg.Storage.BatchFlushInterval.Std() != 20*time.Millisecond || len(cfg.Detector.Whitelist.IPs) != 1 {
		t.Fatal("legacy settings were not preserved")
	}
	if err := loadTenantsFromDB(st, cfg); err != nil || len(cfg.Tenants) != 1 {
		t.Fatalf("migrated tenants: %d, %v", len(cfg.Tenants), err)
	}
	if rules, err := loadDetectRulesFromDB(st); err != nil || len(rules) != 1 || rules[0].When.TokenFreq.Window.Std() != 3*time.Hour {
		t.Fatalf("migrated rules: %d, %v", len(rules), err)
	}
	if err := st.DeleteTenant("sample"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDetectRule("sample"); err != nil {
		t.Fatal(err)
	}
	cfg.AdminListen = "127.0.0.1:29999"
	if err := st.SaveRuntimeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Restart with the original YAML still present; neither removed row returns.
	verify := func() {
		t.Helper()
		st, saved, err := openSettings(db, legacy, true)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if saved.AdminListen != cfg.AdminListen {
			t.Fatal("saved database value was not restored")
		}
		if tenants, err := st.ListTenants(); err != nil || len(tenants) != 0 {
			t.Fatalf("deleted tenant returned: %d, %v", len(tenants), err)
		}
		if rules, err := st.ListDetectRules(); err != nil || len(rules) != 0 {
			t.Fatalf("deleted rule returned: %d, %v", len(rules), err)
		}
	}
	verify()
	if err := os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	verify()
}

func TestUpgradePreservesExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	db, legacy := filepath.Join(dir, "legacy.db"), filepath.Join(dir, "config.yml")
	writeLegacy(t, legacy, db)
	// Simulate a database created before the migration, without the schema marker.
	old, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
	   INSERT INTO meta(k,v) VALUES('admin_password_hash','existing-hash');
	   CREATE TABLE tenants(name TEXT PRIMARY KEY, host TEXT NOT NULL, subscribe_path TEXT NOT NULL,
	     upstream TEXT NOT NULL, upstream_path TEXT, enabled INTEGER NOT NULL, created_ts INTEGER NOT NULL, updated_ts INTEGER NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	st, _, err := openSettings(db, legacy, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, err := st.CountTenants(); err != nil || n != 0 {
		t.Fatalf("empty old tenants table was not preserved: %d, %v", n, err)
	}
	if hash, err := st.GetMeta("admin_password_hash"); err != nil || hash != "existing-hash" {
		t.Fatal("existing database password hash was overwritten")
	}
}

func TestImportRejectsWrongDatabaseLocation(t *testing.T) {
	dir := t.TempDir()
	existing, legacy := filepath.Join(dir, "custom.db"), filepath.Join(dir, "config.yml")
	writeLegacy(t, legacy, existing)
	db := filepath.Join(dir, "wrong.db")
	if _, _, err := openSettings(db, legacy, true); err == nil {
		t.Fatal("expected database path mismatch to be rejected")
	}
	st, err := store.Open(db, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if cfg, err := st.RuntimeConfig(); cfg != nil || err != nil {
		t.Fatal("wrong database was marked as initialized")
	}
}
