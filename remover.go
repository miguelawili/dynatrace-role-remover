package main

import (
	"encoding/json"
	"fmt"
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

// for debugging purposes
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string // Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)                             // Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host)) // Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	} // Return the request as a string
	return strings.Join(request, "\n")
}

func getUrl(accountUuid string, path string) string {
	var sb strings.Builder
	userManagementBaseUrl := "https://api.dynatrace.com/iam/v1/accounts"

	sb.WriteString(userManagementBaseUrl)
	sb.WriteString("/")
	sb.WriteString(accountUuid)
	sb.WriteString("/")
	sb.WriteString(path)

	return sb.String()
}
func getBearerToken(accessToken string) string {
	var sb strings.Builder

	const BEARER_PREFIX string = "Bearer "

	sb.WriteString(BEARER_PREFIX)
	sb.WriteString(accessToken)

	return sb.String()
}

type authenticateResponse struct {
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	Expiration  int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
	Resource    string `json:"resource"`
}

type listUsersResponse struct {
	Items []user
	Count int
}

type user struct {
	Uid              string
	Email            string
	Name             string
	Surname          string
	UserStatus       string
	EmergencyContact bool
	UserMetadata     userMetadata
}

type userMetadata struct {
	SuccessfulLoginCounter int
	FailedLoginCounter     int
	LastSuccessfulLogin    string
	LastFailedLogin        string
	CreatedAt              string
	UpdatedAt              string
}

func main() {
	conf := util.InitConfig("config/settings.toml")
	dynatrace := conf.Dynatrace
	log := logger.NewLogger()
	logger.InitLogger(log, conf.Logging.Level)

	authUrl := "https://sso.dynatrace.com/sso/oauth2/token"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "account-idm-read account-idm-write")
	data.Set("client_id", dynatrace.ClientId)
	data.Set("client_secret", dynatrace.ClientSecret)
	data.Set("resource", dynatrace.Urn)

	req, err := http.NewRequest("POST", authUrl, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalf("Error creating http request.\n%v", err)
	}
	log.Debugf("request:\n%s", formatRequest(req))

	// Add header data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	log.Debugf("res body:\n%s", string(body))

	var authResp authenticateResponse
	json.Unmarshal(body, &authResp)
	log.Debugf("authResp:\n%+v", authResp)

	accountUuid := strings.Split(authResp.Resource, ":")[2]
	bearerToken := getBearerToken(authResp.AccessToken)

	log.Debugf("%s", getUrl(accountUuid, "users"))

	req, err = http.NewRequest("GET", getUrl(accountUuid, "users"), nil)
	if err != nil {
		log.Fatalf("Error creation of request for getting list of users.\nERR: %v", err)
	}
	req.Header.Set("Authorization", bearerToken)

	res, err = client.Do(req)
	if err != nil {
		log.Fatalf("Error execution of request for getting list of users.\nERR: %v", err)
	}
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error reading response body for getting list of users.\n%v", err)
	}
	defer res.Body.Close()
	log.Debugf("res body:\n%s", string(body))

	var listUsersResp listUsersResponse
	json.Unmarshal(body, &listUsersResp)
	log.Debugf("listUsersResp:\n%+v", listUsersResp)

}
