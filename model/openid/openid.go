package oauthopenid

import (
	"encoding/json"
	"net/http"
	"io"
	"io/ioutil"
	"strings"

	"github.com/mattermost/mattermost-server/v5/einterfaces"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/services/httpservice"
	"github.com/mattermost/mattermost-server/v5/shared/mlog"
	"github.com/mattermost/mattermost-server/v5/utils/testutils"
)

type OpenIdProvider struct {
}

type OpenIdProviderUrls struct {
	AuthEndpoint    string `json:"authorization_endpoint"`
	TokenEndpoint   string `json:"token_endpoint"`
	UserApiEndpoint string `json:"userinfo_endpoint"`
}

// Keycloak sepcific
type OpenIdUser struct {
	Id        string   `json:"uniqueId"`
	Username  string   `json:"preferred_username"`
	Email     string   `json:"email"`
	FirstName string   `json:"given_name"`
	LastName  string   `json:"family_name"`
	Roles     []string `json:"roles"`
}

func init() {
	provider := &OpenIdProvider{}
	einterfaces.RegisterOauthProvider(model.SERVICE_OPENID, provider)
}

func userFromOpenIdUser(oiu *OpenIdUser) *model.User {
	user := &model.User{}
	username := oiu.Username
	user.Username = model.CleanUsername(username)
	user.FirstName = oiu.FirstName
	user.LastName = oiu.LastName
	user.Email = oiu.Email
	user.Email = strings.ToLower(user.Email)
	user.AuthData = model.NewString(oiu.getAuthData())
	user.AuthService = model.SERVICE_OPENID
	var roles string
	roles = model.SYSTEM_USER_ROLE_ID
	for _, r := range oiu.Roles {
		if r == "mattermost_admins" {
			roles = model.SYSTEM_USER_ROLE_ID+" "+model.SYSTEM_ADMIN_ROLE_ID
		} else {
			mlog.Debug("Skipping unknown role when processing user: " + username + " role: " + r)
		}
	}
	user.Roles = roles
	mlog.Debug("Parsed user from openId as model user: " + user.ToJson())

	return user
}

func openIdUserFromJson(data io.Reader) (*OpenIdUser, error) {
	var oiu OpenIdUser
	body, err1 := ioutil.ReadAll(data)
	if err1 != nil {
		return nil, err1
	}
	mlog.Debug("Received OpenID User data: " + string(body))
	err2 := json.Unmarshal(body, &oiu)
	if err2 != nil {
		return nil, err2
	}
	return &oiu, nil
}

func (oiu *OpenIdUser) ToJson() string {
	b, err := json.Marshal(oiu)
	if err != nil {
		return ""
	}
	return string(b)
}


func (oiu *OpenIdUser) getAuthData() string {
	return oiu.Id
}

func (m *OpenIdProvider) GetUserFromJson(data io.Reader, tokenUser *model.User) (*model.User, error) {
	oiu, err := openIdUserFromJson(data)
	if err != nil {
		return nil, err
	}
	return userFromOpenIdUser(oiu), nil
}

func (m *OpenIdProvider) GetSSOSettings(config *model.Config, service string) (*model.SSOSettings, error) {
	// This is suuuper janky. But needed a good way to make the http client with just a config
	h := httpservice.MakeHTTPService(&testutils.StaticConfigService{Cfg: config})
	req, err := http.NewRequest("GET", *config.OpenIdSettings.DiscoveryEndpoint, nil)
	if err != nil {
		mlog.Warn("Error while making discovery request", mlog.Err(err))
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	resp, err2 := h.MakeClient(true).Do(req)
	if err2 != nil {
		mlog.Warn("Error while fetching discovery request", mlog.Err(err2))
		return nil, err2
	}

	defer resp.Body.Close()

	var oidcUrls OpenIdProviderUrls
	err3 := json.NewDecoder(resp.Body).Decode(&oidcUrls)
	if err3 != nil {
		mlog.Warn("Error while deserializing discovery response", mlog.Err(err3))
		return nil, err3
	}

	// Merge the 'discovered' endpoints with the original settings
	newSettings := &model.SSOSettings{
		Enable: config.OpenIdSettings.Enable,
		Id: config.OpenIdSettings.Id,
		Secret: config.OpenIdSettings.Secret,
		Scope: config.OpenIdSettings.Scope,
		AuthEndpoint: &oidcUrls.AuthEndpoint,
		TokenEndpoint: &oidcUrls.TokenEndpoint,
		UserApiEndpoint: &oidcUrls.UserApiEndpoint,
		DiscoveryEndpoint: config.OpenIdSettings.DiscoveryEndpoint,
		ButtonText: config.OpenIdSettings.ButtonText,
		ButtonColor: config.OpenIdSettings.ButtonColor,
	}
	return newSettings, nil
}

func (m *OpenIdProvider) GetUserFromIdToken(idToken string) (*model.User, error) {
	return nil, nil
}

func (m *OpenIdProvider) IsSameUser(dbUser, oauthUser *model.User) bool {
	// PCTE converted from emails as unique to SSO ID as unique
	// so check IDs first (which will be in authData), then check email
	return *dbUser.AuthData == *oauthUser.AuthData ||
		dbUser.Email == oauthUser.Email
}
