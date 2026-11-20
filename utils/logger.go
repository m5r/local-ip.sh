package utils

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logFormatAuto    = "auto"
	logFormatJSON    = "json"
	logFormatConsole = "console"
)

const (
	DefaultLogLevel  = "info"
	DefaultLogFormat = logFormatAuto
)

type LogOptions struct {
	Level  string
	Format string
	File   string
}

type namedLevel struct {
	name  string
	level zerolog.Level
}

// fatal, panic and disabled are left out on purpose: each of them would hide ordinary errors, and
// the last two would also silence the program's fatal exits.
var acceptedLogLevels = []namedLevel{
	{"trace", zerolog.TraceLevel},
	{"debug", zerolog.DebugLevel},
	{"info", zerolog.InfoLevel},
	{"warn", zerolog.WarnLevel},
	{"error", zerolog.ErrorLevel},
}

var acceptedLogFormats = []string{logFormatAuto, logFormatJSON, logFormatConsole}

var Logger = newLogger(os.Stdout, zerolog.InfoLevel, DefaultLogFormat, "")

// NewLogger builds a logger that writes to out and, when opts.File is set, to that file as well.
func NewLogger(out io.Writer, opts LogOptions) (zerolog.Logger, error) {
	level, err := parseLogLevel(opts.Level)
	if err != nil {
		return zerolog.Logger{}, err
	}
	format, err := parseLogFormat(opts.Format)
	if err != nil {
		return zerolog.Logger{}, err
	}
	if opts.File != "" {
		if err := checkLogFile(opts.File); err != nil {
			return zerolog.Logger{}, err
		}
	}
	return newLogger(out, level, format, opts.File), nil
}

// InitLogger replaces Logger with one built from opts that writes to standard output.
func InitLogger(opts LogOptions) error {
	logger, err := NewLogger(os.Stdout, opts)
	if err != nil {
		return err
	}
	Logger = logger
	return nil
}

func newLogger(out io.Writer, level zerolog.Level, format string, file string) zerolog.Logger {
	var writer io.Writer = out
	if format == logFormatConsole || (format == logFormatAuto && looksLikeTerminal(out)) {
		writer = zerolog.ConsoleWriter{Out: out, TimeFormat: time.RFC3339}
	}
	if file != "" {
		writer = zerolog.MultiLevelWriter(writer, &lumberjack.Logger{
			Filename:   file,
			MaxBackups: 3,
			MaxSize:    1,
			MaxAge:     1,
			Compress:   true,
		})
	}
	return zerolog.New(writer).Level(level).With().Timestamp().Logger()
}

func parseLogLevel(value string) (zerolog.Level, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	names := make([]string, 0, len(acceptedLogLevels))
	for _, accepted := range acceptedLogLevels {
		if accepted.name == normalized {
			return accepted.level, nil
		}
		names = append(names, accepted.name)
	}
	return zerolog.NoLevel, fmt.Errorf("invalid log level %q: accepted values are %s", value, strings.Join(names, ", "))
}

func parseLogFormat(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, accepted := range acceptedLogFormats {
		if accepted == normalized {
			return accepted, nil
		}
	}
	return "", fmt.Errorf("invalid log format %q: accepted values are %s", value, strings.Join(acceptedLogFormats, ", "))
}

// checkLogFile refuses anything but a regular file before opening it, because opening a FIFO for
// writing blocks until a reader appears.
func checkLogFile(path string) error {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return fmt.Errorf("log file %s is not a regular file (mode %s)", path, info.Mode().Type())
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("checking log file %s: %w", path, err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening log file %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing log file %s: %w", path, err)
	}
	return nil
}

// looksLikeTerminal is the standard library's character device heuristic, which avoids a
// dependency; it is also true for devices such as /dev/null, where the format does not matter.
func looksLikeTerminal(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
