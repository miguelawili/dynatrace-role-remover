package logger

import (
	"log"
	"os"

	"github.com/sirupsen/logrus"
)

func NewLogger() *logrus.Logger {
	return logrus.New()
}

func InitLogger(logger *logrus.Logger, logLevel string) {
	// logging-related configurations
	l, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Error parsing log level.\n%v", err)
	}
	logger.SetLevel(l)
	logger.SetOutput(os.Stdout)
	// logger.SetFormatter(&logrus.JSONFormatter{})
}
