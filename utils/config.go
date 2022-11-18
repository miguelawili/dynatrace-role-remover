package utils

import (
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

type config struct {
	AppName            string
	Logging            logging
	Dynatrace          dynatrace
	WhitelistedUsers   []string
	WhitelistedDomains []string
}

type logging struct {
	Level string
}

type dynatrace struct {
	ClientId     string
	ClientSecret string
	Urn          string
}

func parseConfigFile(fileName string) *config {
	var conf config
	file, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("Error reading configuration file.\n%v", err)
	}

	_, err = toml.Decode(string(file), &conf)

	return &conf
}

func InitConfig(fileName string) *config {
	conf := parseConfigFile(fileName)

	return conf
}
