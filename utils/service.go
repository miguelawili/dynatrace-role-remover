package utils

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type Service struct {
	logger    *logrus.Logger
	dynatrace *Dynatrace
	client    http.Client
}

func NewService(logger *logrus.Logger, dynatrace *Dynatrace) *Service {
	return &Service{
		logger:    logger,
		dynatrace: dynatrace,
	}
}
