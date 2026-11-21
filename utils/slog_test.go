package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newSlogUnderTest(level zerolog.Level) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(NewSlogHandler(zerolog.New(&buf).Level(level))), &buf
}

func singleSlogLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("want exactly one line, got %q", buf.String())
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &fields); err != nil {
		t.Fatalf("line is not JSON: %v\n%s", err, lines[0])
	}
	return fields
}

func assertFields(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for key, value := range want {
		if got[key] != value {
			t.Errorf("field %q = %#v, want %#v (line %v)", key, got[key], value, got)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected field %q = %#v (line %v)", key, got[key], got)
		}
	}
}

func TestSlogLevelsMapToZerolog(t *testing.T) {
	cases := []struct {
		slog slog.Level
		want string
	}{
		{slog.LevelDebug - 4, "trace"},
		{slog.LevelDebug - 1, "trace"},
		{slog.LevelDebug, "debug"},
		{slog.LevelInfo, "info"},
		{slog.LevelWarn, "warn"},
		{slog.LevelError, "error"},
		{slog.LevelError + 1, "error"},
		{slog.LevelError + 100, "error"},
	}
	for _, c := range cases {
		logger, buf := newSlogUnderTest(zerolog.TraceLevel)
		logger.Log(context.Background(), c.slog, "message")
		line := singleSlogLine(t, buf)
		assertFields(t, line, map[string]any{"level": c.want, "message": "message"})
	}
}

func TestSlogEnabledFollowsZerologLevel(t *testing.T) {
	slogLevels := []slog.Level{slog.LevelDebug - 4, slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError, slog.LevelError + 4}
	// enabled counts how many of slogLevels, from the highest down, the zerolog level lets through.
	zerologLevels := []struct {
		level   zerolog.Level
		enabled int
	}{
		{zerolog.TraceLevel, 6},
		{zerolog.DebugLevel, 5},
		{zerolog.InfoLevel, 4},
		{zerolog.WarnLevel, 3},
		{zerolog.ErrorLevel, 2},
		{zerolog.FatalLevel, 0},
		{zerolog.Disabled, 0},
	}
	for _, z := range zerologLevels {
		for i, level := range slogLevels {
			handler := NewSlogHandler(zerolog.New(&bytes.Buffer{}).Level(z.level))
			want := i >= len(slogLevels)-z.enabled
			if got := handler.Enabled(context.Background(), level); got != want {
				t.Errorf("zerolog %v, slog %v: Enabled = %v, want %v", z.level, level, got, want)
			}
		}
	}
}

func TestSlogEnabledFollowsZerologGlobalLevel(t *testing.T) {
	previous := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(previous) })

	logger, buf := newSlogUnderTest(zerolog.TraceLevel)
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info is enabled although the global level is warn")
	}
	logger.Info("dropped")
	if buf.Len() != 0 {
		t.Errorf("a record below the global level was written: %q", buf.String())
	}
}

func TestSlogDisabledLevelWritesNothing(t *testing.T) {
	logger, buf := newSlogUnderTest(zerolog.WarnLevel)
	logger.Debug("dropped", "key", "value")
	logger.Info("dropped", "key", "value")
	logger.With("key", "value").WithGroup("g").Info("dropped", "key", "value")
	if buf.Len() != 0 {
		t.Fatalf("records below the logger's level were written: %q", buf.String())
	}
	logger.Warn("kept")
	assertFields(t, singleSlogLine(t, buf), map[string]any{"level": "warn", "message": "kept"})
}

func TestSlogAttributes(t *testing.T) {
	logger, buf := newSlogUnderTest(zerolog.InfoLevel)
	logger.Info("ordering", "name", "example.com", "count", 3, "ok", true, "delay", 1500*time.Millisecond, "error", errors.New("refused"))
	assertFields(t, singleSlogLine(t, buf), map[string]any{
		"level":   "info",
		"message": "ordering",
		"name":    "example.com",
		"count":   float64(3),
		"ok":      true,
		"delay":   float64(1500),
		"error":   "refused",
	})
}

func TestSlogDropsRecordTime(t *testing.T) {
	logger, buf := newSlogUnderTest(zerolog.InfoLevel)
	logger.Info("message")
	if _, ok := singleSlogLine(t, buf)["time"]; ok {
		t.Error("the record's time was written; zerolog was configured without a timestamp")
	}
}

type lazyValue struct{ value string }

func (v lazyValue) LogValue() slog.Value { return slog.StringValue(v.value) }

type lazyGroup struct{}

func (lazyGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.String("a", "1"), slog.Int("b", 2))
}

func TestSlogResolvesLogValuers(t *testing.T) {
	logger, buf := newSlogUnderTest(zerolog.InfoLevel)
	logger.Info("message", "lazy", lazyValue{"resolved"}, "group", lazyGroup{})
	assertFields(t, singleSlogLine(t, buf), map[string]any{
		"level":   "info",
		"message": "message",
		"lazy":    "resolved",
		"group.a": "1",
		"group.b": float64(2),
	})
}

func TestSlogGroups(t *testing.T) {
	cases := []struct {
		name string
		log  func(*slog.Logger)
		want map[string]any
	}{
		{
			name: "group opened with WithGroup",
			log:  func(l *slog.Logger) { l.WithGroup("http").Info("m", "status", 200) },
			want: map[string]any{"http.status": float64(200)},
		},
		{
			name: "group given as an attribute",
			log:  func(l *slog.Logger) { l.Info("m", slog.Group("order", "id", "o1", "status", "valid")) },
			want: map[string]any{"order.id": "o1", "order.status": "valid"},
		},
		{
			name: "group attribute inside a group attribute",
			log: func(l *slog.Logger) {
				l.Info("m", slog.Group("order", "id", "o1", slog.Group("authz", "status", "pending")))
			},
			want: map[string]any{"order.id": "o1", "order.authz.status": "pending"},
		},
		{
			name: "group attribute inside WithGroup",
			log: func(l *slog.Logger) {
				l.WithGroup("acme").WithGroup("client").Info("m", slog.Group("order", "id", "o1"))
			},
			want: map[string]any{"acme.client.order.id": "o1"},
		},
		{
			name: "WithAttrs before WithGroup",
			log:  func(l *slog.Logger) { l.With("component", "acme").WithGroup("http").Info("m", "status", 200) },
			want: map[string]any{"component": "acme", "http.status": float64(200)},
		},
		{
			name: "WithAttrs after WithGroup",
			log:  func(l *slog.Logger) { l.WithGroup("http").With("method", "GET").Info("m", "status", 200) },
			want: map[string]any{"http.method": "GET", "http.status": float64(200)},
		},
		{
			name: "WithAttrs between two groups",
			log: func(l *slog.Logger) {
				l.WithGroup("a").With("x", 1).WithGroup("b").With(slog.Group("g", "y", 2)).Info("m", "z", 3)
			},
			want: map[string]any{"a.x": float64(1), "a.b.g.y": float64(2), "a.b.z": float64(3)},
		},
		{
			name: "group with an empty key is inlined",
			log:  func(l *slog.Logger) { l.WithGroup("g").Info("m", slog.Group("", "a", 1)) },
			want: map[string]any{"g.a": float64(1)},
		},
		{
			name: "empty group and empty attribute are dropped",
			log:  func(l *slog.Logger) { l.Info("m", slog.Group("empty"), slog.Attr{}, "kept", true) },
			want: map[string]any{"kept": true},
		},
		{
			name: "WithGroup with an empty name opens nothing",
			log:  func(l *slog.Logger) { l.WithGroup("").Info("m", "a", 1) },
			want: map[string]any{"a": float64(1)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger, buf := newSlogUnderTest(zerolog.InfoLevel)
			c.log(logger)
			want := map[string]any{"level": "info", "message": "m"}
			for key, value := range c.want {
				want[key] = value
			}
			assertFields(t, singleSlogLine(t, buf), want)
		})
	}
}

func TestSlogWithAttrsDoesNotLeakIntoParent(t *testing.T) {
	logger, buf := newSlogUnderTest(zerolog.InfoLevel)
	_ = logger.With("child", true).WithGroup("g")
	logger.Info("m")
	assertFields(t, singleSlogLine(t, buf), map[string]any{"level": "info", "message": "m"})
}
