package utils

import (
	"context"
	"log/slog"

	"github.com/rs/zerolog"
)

// NewSlogHandler returns a slog.Handler that writes every record as one zerolog event of logger. A record is enabled when its level, mapped to zerolog (debug, info, warn and error to the same levels, anything lower to trace, anything higher to error), passes the logger's level and zerolog's global level. Attributes become fields; members of a group become fields whose keys are prefixed with the group names joined by ".". The record's time is dropped because zerolog stamps the line itself.
func NewSlogHandler(logger zerolog.Logger) slog.Handler {
	return &slogHandler{logger: logger}
}

type slogHandler struct {
	logger zerolog.Logger
	// prefix is the dotted path of the groups opened with WithGroup, followed by a dot, or empty.
	prefix string
}

func zerologLevel(level slog.Level) zerolog.Level {
	switch {
	case level < slog.LevelDebug:
		return zerolog.TraceLevel
	case level < slog.LevelInfo:
		return zerolog.DebugLevel
	case level < slog.LevelWarn:
		return zerolog.InfoLevel
	case level < slog.LevelError:
		return zerolog.WarnLevel
	default:
		return zerolog.ErrorLevel
	}
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	zl := zerologLevel(level)
	return zl >= h.logger.GetLevel() && zl >= zerolog.GlobalLevel()
}

func (h *slogHandler) Handle(_ context.Context, record slog.Record) error {
	fields := make([]any, 0, 2*record.NumAttrs())
	record.Attrs(func(a slog.Attr) bool {
		fields = appendAttr(fields, h.prefix, a)
		return true
	})
	event := h.logger.WithLevel(zerologLevel(record.Level))
	if len(fields) > 0 {
		event = event.Fields(fields)
	}
	event.Msg(record.Message)
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var fields []any
	for _, a := range attrs {
		fields = appendAttr(fields, h.prefix, a)
	}
	if len(fields) == 0 {
		return h
	}
	return &slogHandler{logger: h.logger.With().Fields(fields).Logger(), prefix: h.prefix}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &slogHandler{logger: h.logger, prefix: h.prefix + name + "."}
}

// appendAttr follows the slog.Handler rules: an empty attribute is dropped, an empty group is dropped, and a group with an empty key is inlined into the enclosing level. The fields go through zerolog's Fields rather than Any so that errors, durations and times keep zerolog's own encoding instead of being marshalled to JSON by reflection (an error would become {}).
func appendAttr(fields []any, prefix string, a slog.Attr) []any {
	value := a.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		members := value.Group()
		if len(members) == 0 {
			return fields
		}
		if a.Key != "" {
			prefix += a.Key + "."
		}
		for _, member := range members {
			fields = appendAttr(fields, prefix, member)
		}
		return fields
	}
	if a.Key == "" && value.Any() == nil {
		return fields
	}
	return append(fields, prefix+a.Key, value.Any())
}
