package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	logger "dynatrace-role-remover/logger"
	util "dynatrace-role-remover/utils"
)

type authenticationPayload struct {
	Grant_type    string
	Client_id     string
	Client_secret string
	Scope         string
	Resource      string
}

func main() {
	conf := util.InitConfig("config/settings.toml")
	dynatrace := conf.Dynatrace
	log := logger.NewLogger()
	logger.InitLogger(log, conf.Logging.Level)

	dynatraceUrl := "https://sso.dynatrace.com/sso/oauth2/token"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "account-idm-read account-idm-write")
	data.Set("client_id", dynatrace.ClientId)
	data.Set("client_secret", dynatrace.ClientSecret)
	data.Set("resource", dynatrace.Urn)

	req, err := http.NewRequest("POST", dynatraceUrl, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalf("Error creating http request.\n%v", err)
	}
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Debugf("Error reading request body: %v\n", err)
	}
	log.Debugf("reqBody: %v\n", string(reqBody))

	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	log.Debugf("request: %+v", req)

	client := http.Client{}

	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error executing http request.\n%v", err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error reading response body.\n%v", err)
	}
	defer res.Body.Close()

	log.Infof("body: %v\n", string(body))

	roleRemover := util.NewService(log, &dynatrace)
	log.Debugf("roleRemover Type, Value: %T, %+v\n", roleRemover, roleRemover)
}
