package webui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func parseEventCursor(cursor string) (time.Time, int64, error) {
	left, right, found := strings.Cut(cursor, ":")
	ts, errTS := strconv.ParseInt(left, 10, 64)
	id, errID := strconv.ParseInt(right, 10, 64)
	if !found || errTS != nil || errID != nil || ts <= 0 || id <= 0 {
		return time.Time{}, 0, fmt.Errorf("invalid event cursor")
	}
	return time.UnixMilli(ts), id, nil
}

func (s *Server) eventPage(ctx context.Context, f store.EventFilter, visible func(store.Event) bool) ([]store.Event, string, error) {
	limit := f.Limit
	f.Limit = max(100, limit+1)
	items := make([]store.Event, 0, limit)
	next := func() string { return fmt.Sprintf("%d:%d", f.BeforeTS.UnixMilli(), f.BeforeID) }
	// Skip filtered entries while advancing the cursor, but keep query cost bounded.
	for scan := 0; scan < 8; scan++ {
		rows, err := s.st.QueryEvents(ctx, f)
		if err != nil {
			return nil, "", err
		}
		for _, e := range rows {
			show := visible(e)
			if show && len(items) == limit {
				return items, next(), nil
			}
			f.BeforeTS, f.BeforeID = e.TS, e.ID
			if show {
				items = append(items, e)
			}
		}
		if len(rows) < f.Limit {
			return items, "", nil
		}
	}
	return items, next(), nil
}
