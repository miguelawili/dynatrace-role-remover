package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	logger "dynatrace-role-remover/logger"
	util "dynatrace-role-remover/utils"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

type authenticationPayload struct {
	Grant_type    string
	Client_id     string
	Client_secret string
	Scope         string
	Resource      string
}

func getUrl(accountUuid string, resourcePaths []string) string {
	var sb strings.Builder
	userManagementBaseUrl := "https://api.dynatrace.com/iam/v1/accounts"
	sb.WriteString(userManagementBaseUrl)
	sb.WriteString("/")
	sb.WriteString(accountUuid)
	sb.WriteString("/")
	for idx, resourcePath := range resourcePaths {
		sb.WriteString(resourcePath)

		if idx < len(resourcePaths)-1 {
			sb.WriteString("/")
		}
	}

	return sb.String()
}

func inWhitelistedDomain(email string, domains []string) bool {
	for _, domain := range domains {
		if strings.Contains(email, domain) {
			return true
		}
	}
	return false
}

func filterUsers(users []user, domains []string) ([]user, []user) {
	var activeUsers []user
	var inactiveUsers []user
	//timeLayout := "2006-01-02T15:04:05.000Z"
	timeLayout := time.RFC3339
	lastValidDate := time.Now().AddDate(0, -6, 0) // 6 months ago

	for _, user := range users {
		isActive := false

		if user.UserLoginMetadata.LastSuccessfulLogin == "" {
			inactiveUsers = append(inactiveUsers, user)
			continue
		}
		if !inWhitelistedDomain(user.Email, domains) {
			inactiveUsers = append(inactiveUsers, user)
			continue
		}

		lastActivity, err := time.Parse(timeLayout, user.UserLoginMetadata.LastSuccessfulLogin)
		if err != nil {
			log.Fatalf("Error parsing lastSuccessfulLogin.\nERR: %v", err)
		}

		isActive = lastActivity.After(lastValidDate)

		if isActive {
			activeUsers = append(activeUsers, user)
		} else {
			inactiveUsers = append(inactiveUsers, user)
		}
	}

	return activeUsers, inactiveUsers
}

func getBearerToken(accessToken string) string {
	var sb strings.Builder

	const BEARER_PREFIX string = "Bearer "

	sb.WriteString(BEARER_PREFIX)
	sb.WriteString(accessToken)

	return sb.String()
}

func removeNonSamlGroups(groups []userGroup) []userGroup {
	var retainedGroups []userGroup

	for _, group := range groups {
		if group.Owner == "SAML" {
			retainedGroups = append(retainedGroups, group)
		}
	}

	return retainedGroups
}

func listNonSamlGroups(client http.Client, accountId string, bearerToken string) []string {
	var groupUuids []string
	var groups listGroupsResponse

	req, err := http.NewRequest("GET", getUrl(accountId, []string{"groups"}), nil)
	if err != nil {
		log.Errorf("Error creating request for listing user's groups.\nERR: %v", err)
	}
	req.Header.Set("Authorization", bearerToken)
	log.Debugf("listNonSamlGroups() req:\n%v", req)

	res, err := client.Do(req)
	if err != nil {
		log.Errorf("Error exeucting request for listing user's groups.\nERR: %v", err)
	}

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error parsing body.\nERR: %v", err)
	}

	json.Unmarshal(respBody, &groups)
	log.Debugf("listNonSamlGroups: %v", groups)

	for _, group := range groups.Items {
		if group.Owner == "SAML" {
			continue
		}

		groupUuids = append(groupUuids, group.Uuid+":"+group.Name)
	}

	return groupUuids
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

type listGroupsResponse struct {
	Count int
	Items []group
}

type group struct {
	Uuid                     string
	Name                     string
	Description              string
	FederatedAttributeValues []string
	Owner                    string
	CreatedAt                string
	UpdatedAt                string
}

type userGroupsResponse struct {
	Uid              string
	Email            string
	Name             string
	Surname          string
	Groups           []userGroup
	EmergencyContact bool
	UserStatus       string
}

type userGroup struct {
	GroupName   string
	Uuid        string
	Owner       string
	Description string
	Hidden      bool
	AccountUuid string
	AccountName string
	CreatedAt   string
	UpdatedAt   string
}

type user struct {
	Uid               string
	Email             string
	Name              string
	Surname           string
	UserStatus        string
	EmergencyContact  bool
	UserLoginMetadata userLoginMetadata
	Groups            []userGroup
}

func (u *user) getGroups(client http.Client, accountId string, bearerToken string) []userGroup {
	var userGroups userGroupsResponse

	req, err := http.NewRequest("GET", getUrl(accountId, []string{"users", u.Email}), nil)
	if err != nil {
		log.Errorf("Error creating request for listing user's groups.\nERR: %v", err)
	}
	req.Header.Set("Authorization", bearerToken)
	log.Debugf("getGroups() req:\n%v", req)

	res, err := client.Do(req)
	if err != nil {
		log.Errorf("Error exeucting request for listing user's groups.\nERR: %v", err)
	}

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error parsing body.\nERR: %v", err)
	}

	json.Unmarshal(respBody, &userGroups)
	log.Debugf("userGroups: %v", userGroups)

	return userGroups.Groups
}

func (u *user) delete(client http.Client, accountId string, bearerToken string) bool {
	req, err := http.NewRequest("DELETE", getUrl(accountId, []string{"users", u.Email}), nil)
	if err != nil {
		log.Errorf("Error creating request for user deletion.\nERR: %v", err)
	}
	req.Header.Set("Authorization", bearerToken)
	log.Debugf("delete() req:\n%v", req)

	res, err := client.Do(req)
	if err != nil {
		log.Errorf("Error executing request for user deletion.\nERR: %v", err)
	}

	if res.StatusCode == 200 {
		return true
	}
	return false
}

func (u *user) updateGroups(client http.Client, accountId string, bearerToken string, groupsToRemove []string) bool {
	if len(u.Groups) < 1 {
		return true
	}

	req, err := http.NewRequest(http.MethodDelete, getUrl(accountId, []string{"users", u.Email, "groups"}), nil)
	if err != nil {
		log.Errorf("Error creating request for updating user's groups.\nERR: %v", err)
	}
	req.Header.Set("Authorization", bearerToken)
	req.Header.Set("Content-Type", "application/json")

	queryParams := req.URL.Query()
	for _, groupToRemove := range groupsToRemove {
		queryParams.Add("group-uuid", strings.Split(groupToRemove, ":")[0])
	}
	req.URL.RawQuery = queryParams.Encode()

	log.Debugln("updateGroups() req:")
	log.Debugf("Host: %s\n", req.Host)
	log.Debugf("Path: %s\n", req.URL.Path)
	log.Debugf("Query Params: %s\n", req.URL.Query())
	log.Debugf("Method: %s\n", req.Method)
	log.Debugf("Proto: %s\n", req.Proto)
	log.Debugln("Headers:")
	for key, element := range req.Header {
		log.Debugf("\t%s:%s", key, element)
	}
	if req.Body != nil {
		reqBody, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Debugf("%v", err)
		}
		log.Debugf("Body:\n%#v", string(reqBody))
	}

	log.Debugf("updateGroups() req:\n%#v", req)

	res, err := client.Do(req)
	if err != nil {
		log.Errorf("Error executing request for updating user's groups.\nERR: %v", err)
	}
	defer res.Body.Close()
	log.Debugln("updateGroups() res:")
	log.Debugf("Proto: %s\n", res.Proto)
	log.Debugln("Headers:")
	for key, element := range res.Header {
		log.Debugf("\t%s:%s", key, element)
	}
	resBody, _ := ioutil.ReadAll(res.Body)
	log.Debugf("Body:\n%#v", string(resBody))
	log.Debugf("updateGroups() res:\n%#v", res)

	if res.StatusCode == 200 {
		return true
	}
	return false
}

type userLoginMetadata struct {
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
	log = logger.NewLogger()
	logger.InitLogger(log, conf.Logging.Level)
	log.Infof("Successfully parsed configuration file!")

	log.Debugf("conf:\n%v", conf)

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
	log.Debugf("request:\n%s", req)

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

	accountUuid := strings.Split(authResp.Resource, ":")[2]
	bearerToken := getBearerToken(authResp.AccessToken)

	log.Debugf("%s", getUrl(accountUuid, []string{"users"}))

	req, err = http.NewRequest("GET", getUrl(accountUuid, []string{"users"}), nil)
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

	whitelistedUsers := make(map[string]int)
	for _, user := range conf.WhitelistedUsers {
		whitelistedUsers[user] = 1
	}
	log.Debugf("whitelistedUsers:\n%v", &whitelistedUsers)

	whitelistedDomains := conf.WhitelistedDomains
	log.Debugf("whitelistedDomains:\n%v", &whitelistedDomains)

	activeUsers, inactiveUsers := filterUsers(listUsersResp.Items, whitelistedDomains)

	nonSamlGroups := listNonSamlGroups(client, accountUuid, bearerToken)
	log.Debugln("main() nonSamlGroups:")
	for _, nonSamlGroup := range nonSamlGroups {
		log.Debugf("\t%v", nonSamlGroup)
	}

	for _, usr := range activeUsers {
		if _, ok := whitelistedUsers[usr.Email]; ok {
			// skip whitelisted users
			continue
		}

		groups := usr.getGroups(client, accountUuid, bearerToken)
		// // for when making it work on next loop
		// activeUsers[idx].Groups = removeNonSamlGroups(groups)

		// for when making it work on current loop
		usr.Groups = removeNonSamlGroups(groups)

		if usr.updateGroups(client, accountUuid, bearerToken, nonSamlGroups) {
			log.Infof("Successfully updated %s's groups.\n", usr.Email)
		} else {
			log.Fatalf("Error updating %s's groups.", usr.Email)
		}
		log.Debugf("usr:\n%+v", usr)
	}

	if len(inactiveUsers) > 0 {
		log.Debugln("======")
		log.Debugln("Inactive Users: ")
		for _, usr := range inactiveUsers {
			if _, ok := whitelistedUsers[usr.Email]; ok {
				// skip whitelisted users
				continue
			}

			usr.delete(client, accountUuid, bearerToken)
			log.Debugf("usr:\n%#v", usr)
		}
	}
}
