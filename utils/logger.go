package utils

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

var consoleWriter = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
var fileWriter = &lumberjack.Logger{
	Filename:   "/var/log/local-ip.sh.log",
	MaxBackups: 3,
	MaxSize:    1,    // megabytes
	MaxAge:     1,    // days
	Compress:   true, // disabled by default
}
var multi = zerolog.MultiLevelWriter(consoleWriter, fileWriter)

var Logger = zerolog.New(multi).With().Timestamp().Logger()
