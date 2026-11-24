package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/store"
)

func openSettings(dbPath, legacyPath string, legacyRequired bool) (*store.Store, *config.Config, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if err := file.Close(); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	var cfg *config.Config
	st, err := store.OpenConfigured(dbPath, func(st *store.Store) (time.Duration, int, error) {
		c, err := st.RuntimeConfig()
		if err != nil {
			return 0, 0, err
		}
		if c == nil {
			oldDB, err := st.NeedsLegacyConfig()
			if err != nil {
				return 0, 0, err
			}
			legacy, err := config.LoadLegacy(legacyPath)
			var reportSecret string
			switch {
			case err == nil:
				legacyDB, legacyErr := filepath.Abs(legacy.Storage.SQLitePath)
				selectedDB, selectedErr := filepath.Abs(dbPath)
				if legacyErr != nil || selectedErr != nil || legacyDB != selectedDB {
					return 0, 0, fmt.Errorf("旧配置使用其他 SQLite 路径，请用 -db %q 指定旧数据库", legacy.Storage.SQLitePath)
				}
			case errors.Is(err, os.ErrNotExist) && !legacyRequired && !oldDB:
				legacy = config.Defaults(dbPath)
				hash, err := initialPasswordHash(config.InitialPasswordPath(dbPath))
				if err != nil {
					return 0, 0, fmt.Errorf("初始化管理员凭据: %w", err)
				}
				legacy.Admin.PasswordHash = hash
				reportSecret = rand.Text()
			default:
				return 0, 0, fmt.Errorf("导入旧配置 %s: %w", legacyPath, err)
			}
			if err := st.InitRuntimeConfig(legacy, reportSecret); err != nil {
				return 0, 0, err
			}
			c, err = st.RuntimeConfig()
			if err != nil {
				return 0, 0, err
			}
		}
		c.Storage.SQLitePath = dbPath
		cfg = c
		return c.Storage.BatchFlushInterval.Std(), c.Storage.BatchFlushSize, nil
	})
	return st, cfg, err
}

func restoreSettings(path string) error {
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("找不到 SQLite 文件: %s", path)
	}
	st, err := store.Open(path, time.Second, 100)
	if err != nil {
		return err
	}
	defer st.Close()
	return st.RestorePreviousRuntimeConfig()
}

func initialPasswordHash(path string) (string, error) {
	password := rand.Text()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 128 {
			return "", fmt.Errorf("初始密码文件不是权限为 0600 的普通文件")
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", readErr
		}
		password = strings.TrimSpace(string(data))
		if len(password) < 20 || len(password) > 72 {
			return "", fmt.Errorf("初始密码文件无效")
		}
	} else if err != nil {
		return "", err
	} else {
		_, writeErr := fmt.Fprintln(file, password)
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return "", err
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}
