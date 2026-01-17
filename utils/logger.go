package utils

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

const DefaultLogFile = "/var/log/local-ip.sh.log"

var consoleWriter = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}

var Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()

func InitLogger(logFile string) {
	if logFile == "" {
		logFile = DefaultLogFile
	}

	fileWriter := &lumberjack.Logger{
		Filename:   logFile,
		MaxBackups: 3,
		MaxSize:    1,
		MaxAge:     1,
		Compress:   true,
	}

	multi := zerolog.MultiLevelWriter(consoleWriter, fileWriter)
	Logger = zerolog.New(multi).With().Timestamp().Logger()
}
