package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func newTestLogger(t *testing.T, opts LogOptions) (zerolog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger, err := NewLogger(&buf, opts)
	if err != nil {
		t.Fatalf("NewLogger(%+v): %v", opts, err)
	}
	return logger, &buf
}

func outputLines(buf *bytes.Buffer) []string {
	trimmed := strings.TrimRight(buf.String(), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func parseJSONLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		t.Fatalf("line is not JSON: %v\n%s", err, line)
	}
	return fields
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("%s holds %v, want it empty", dir, names)
	}
}

func TestNewLoggerAcceptsLevels(t *testing.T) {
	levels := []struct {
		name  string
		level zerolog.Level
	}{
		{"trace", zerolog.TraceLevel},
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
	}
	spellings := []struct {
		name  string
		spell func(string) string
	}{
		{"lower case", strings.ToLower},
		{"upper case", strings.ToUpper},
		{"surrounding spaces", func(s string) string { return " \t" + s + " \n" }},
	}

	for _, level := range levels {
		for _, spelling := range spellings {
			t.Run(level.name+"/"+spelling.name, func(t *testing.T) {
				logger, buf := newTestLogger(t, LogOptions{Level: spelling.spell(level.name), Format: "json"})

				if level.level > zerolog.TraceLevel {
					logger.WithLevel(level.level - 1).Msg("below")
					if buf.Len() != 0 {
						t.Fatalf("event below %s produced output: %q", level.name, buf.String())
					}
				}

				logger.WithLevel(level.level).Msg("at")
				lines := outputLines(buf)
				if len(lines) != 1 {
					t.Fatalf("event at %s produced %d lines, want 1: %q", level.name, len(lines), buf.String())
				}
				if got := parseJSONLine(t, lines[0])["level"]; got != level.name {
					t.Errorf("level = %v, want %s", got, level.name)
				}
			})
		}
	}
}

func TestNewLoggerRejectsLevels(t *testing.T) {
	for _, value := range []string{"", "fatal", "panic", "disabled", "verbose"} {
		t.Run("value "+strconv.Quote(value), func(t *testing.T) {
			var buf bytes.Buffer
			_, err := NewLogger(&buf, LogOptions{Level: value, Format: "json"})
			if err == nil {
				t.Fatalf("NewLogger accepted level %q", value)
			}
			message := err.Error()
			for _, want := range []string{"log level", strconv.Quote(value), "trace", "debug", "info", "warn", "error"} {
				if !strings.Contains(message, want) {
					t.Errorf("error %q does not contain %q", message, want)
				}
			}
		})
	}
}

func TestNewLoggerFormats(t *testing.T) {
	regularFile := func(t *testing.T) *os.File {
		t.Helper()
		file, err := os.Create(filepath.Join(t.TempDir(), "out.log"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		return file
	}

	jsonCases := []struct {
		name   string
		format string
		toFile bool
	}{
		{"json", "json", false},
		{"JSON in upper case", "JSON", false},
		{"auto on a buffer", "auto", false},
		{"auto on a regular file", "auto", true},
	}
	for _, tc := range jsonCases {
		t.Run(tc.name, func(t *testing.T) {
			var output func() string
			var logger zerolog.Logger
			var err error
			if tc.toFile {
				file := regularFile(t)
				logger, err = NewLogger(file, LogOptions{Level: "info", Format: tc.format})
				output = func() string {
					content, readErr := os.ReadFile(file.Name())
					if readErr != nil {
						t.Fatal(readErr)
					}
					return string(content)
				}
			} else {
				var buf bytes.Buffer
				logger, err = NewLogger(&buf, LogOptions{Level: "info", Format: tc.format})
				output = buf.String
			}
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}

			logger.Info().Msg("hello")
			lines := strings.Split(strings.TrimRight(output(), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("got %d lines, want 1: %q", len(lines), output())
			}
			fields := parseJSONLine(t, lines[0])
			if fields["level"] != "info" {
				t.Errorf("level = %v, want info", fields["level"])
			}
			if fields["message"] != "hello" {
				t.Errorf("message = %v, want hello", fields["message"])
			}
			if _, ok := fields["time"].(string); !ok {
				t.Errorf("time = %v, want a string", fields["time"])
			}
		})
	}

	for _, format := range []string{"console", " console "} {
		t.Run("console spelled "+strconv.Quote(format), func(t *testing.T) {
			logger, buf := newTestLogger(t, LogOptions{Level: "info", Format: format})
			logger.Info().Msg("hello")
			if !strings.Contains(buf.String(), "hello") {
				t.Errorf("console output %q does not contain the message", buf.String())
			}
			if json.Valid(bytes.TrimSpace(buf.Bytes())) {
				t.Errorf("console output parses as JSON: %q", buf.String())
			}
		})
	}

	for _, value := range []string{"", "text"} {
		t.Run("rejects "+strconv.Quote(value), func(t *testing.T) {
			var buf bytes.Buffer
			_, err := NewLogger(&buf, LogOptions{Level: "info", Format: value})
			if err == nil {
				t.Fatalf("NewLogger accepted format %q", value)
			}
			message := err.Error()
			for _, want := range []string{"log format", strconv.Quote(value), "auto", "json", "console"} {
				if !strings.Contains(message, want) {
					t.Errorf("error %q does not contain %q", message, want)
				}
			}
		})
	}
}

func TestNewLoggerFile(t *testing.T) {
	for _, format := range []string{"json", "console"} {
		t.Run("format "+format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "app.log")
			logger, buf := newTestLogger(t, LogOptions{Level: "info", Format: format, File: path})

			logger.Info().Msg("to both")

			if !strings.Contains(buf.String(), "to both") {
				t.Errorf("output %q does not contain the event", buf.String())
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading log file: %v", err)
			}
			lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("log file holds %d lines, want 1: %q", len(lines), content)
			}
			if got := parseJSONLine(t, lines[0])["message"]; got != "to both" {
				t.Errorf("file message = %v, want %q", got, "to both")
			}
		})
	}

	t.Run("no file", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		logger, _ := newTestLogger(t, LogOptions{Level: "info", Format: "json"})
		logger.Info().Msg("only to out")
		assertDirEmpty(t, dir)
	})
}

func TestNewLoggerRejectsFiles(t *testing.T) {
	cases := []struct {
		name string
		path func(t *testing.T, dir string) string
	}{
		{"inside a missing directory", func(t *testing.T, dir string) string { return filepath.Join(dir, "missing", "app.log") }},
		{"a directory", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "a-directory")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tc.path(t, dir)
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			_, err = NewLogger(&buf, LogOptions{Level: "info", Format: "json", File: path})
			if err == nil {
				t.Fatalf("NewLogger accepted log file %s", path)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name %s", err, path)
			}

			after, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Errorf("directory went from %d to %d entries", len(before), len(after))
			}
			if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
				t.Errorf("%s was created", path)
			}
		})
	}
}

func TestNewLoggerValidatesBeforeCreatingFile(t *testing.T) {
	cases := []struct {
		name string
		opts LogOptions
	}{
		{"invalid level", LogOptions{Level: "verbose", Format: "json"}},
		{"invalid format", LogOptions{Level: "info", Format: "text"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.opts.File = filepath.Join(dir, "app.log")
			var buf bytes.Buffer
			if _, err := NewLogger(&buf, tc.opts); err == nil {
				t.Fatalf("NewLogger(%+v) succeeded, want an error", tc.opts)
			}
			assertDirEmpty(t, dir)
		})
	}
}

func TestLooksLikeTerminal(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { devNull.Close() })

	regular, err := os.Create(filepath.Join(t.TempDir(), "regular"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { regular.Close() })

	closed, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		out  io.Writer
		want bool
	}{
		{"character device", devNull, true},
		{"buffer", &bytes.Buffer{}, false},
		{"regular file", regular, false},
		{"closed file", closed, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeTerminal(tc.out); got != tc.want {
				t.Errorf("looksLikeTerminal = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultLogger(t *testing.T) {
	if got := Logger.GetLevel().String(); got != DefaultLogLevel {
		t.Errorf("default Logger level = %s, want DefaultLogLevel %s", got, DefaultLogLevel)
	}

	var buf bytes.Buffer
	logger := Logger.Output(&buf)

	logger.Debug().Msg("hidden")
	if buf.Len() != 0 {
		t.Fatalf("default logger emitted a debug event: %q", buf.String())
	}
	logger.Info().Msg("shown")
	if lines := outputLines(&buf); len(lines) != 1 {
		t.Fatalf("default logger emitted %d lines for an info event, want 1: %q", len(lines), buf.String())
	}
}

func TestInitLogger(t *testing.T) {
	startFrom := func(t *testing.T, level zerolog.Level) {
		t.Helper()
		previous := Logger
		t.Cleanup(func() { Logger = previous })
		Logger = zerolog.New(io.Discard).Level(level)
	}

	t.Run("invalid options keep the logger", func(t *testing.T) {
		startFrom(t, zerolog.WarnLevel)
		if err := InitLogger(LogOptions{Level: "verbose", Format: "json"}); err == nil {
			t.Fatal("InitLogger accepted level verbose")
		}
		var buf bytes.Buffer
		logger := Logger.Output(&buf)
		logger.Info().Msg("below warn")
		if buf.Len() != 0 {
			t.Fatalf("Logger changed: an info event produced %q", buf.String())
		}
		logger.Warn().Msg("at warn")
		if lines := outputLines(&buf); len(lines) != 1 {
			t.Fatalf("Logger changed: a warn event produced %d lines, want 1", len(lines))
		}
	})

	t.Run("valid options replace the logger", func(t *testing.T) {
		startFrom(t, zerolog.WarnLevel)
		if err := InitLogger(LogOptions{Level: "error", Format: "json"}); err != nil {
			t.Fatalf("InitLogger: %v", err)
		}
		var buf bytes.Buffer
		logger := Logger.Output(&buf)
		logger.Warn().Msg("below error")
		if buf.Len() != 0 {
			t.Fatalf("a warn event at level error produced %q", buf.String())
		}
		logger.Error().Msg("at error")
		if lines := outputLines(&buf); len(lines) != 1 {
			t.Fatalf("an error event at level error produced %d lines, want 1: %q", len(lines), buf.String())
		}
	})
}
