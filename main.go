package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/arielril/oauth2-ms365-sample/log"
)

var logger = log.GetInstance()

type AccessTokenResponseOK struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type ExecOpts struct {
	Tenant       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	State        string
	Scope        string
}

func main() {
	var tenant string
	flag.StringVar(&tenant, "tenant", "common", "Tenant ID")

	var clientID string
	flag.StringVar(&clientID, "client_id", "", "Required. Application Client ID")

	var clientSecret string
	flag.StringVar(&clientSecret, "client_secret", "", "Required. Application Client Secret")

	var redirectURI string
	flag.StringVar(&redirectURI, "redirect", "http://localhost:3001/token", "Application redirect URI")

	var state string
	flag.StringVar(&state, "auth_code", "", "Authorization Code, '&code=' querystring")

	var scope string
	flag.StringVar(&scope, "scope", "openid user.read", "Authorization Scope")

	flag.Parse()

	if clientID == "" || clientSecret == "" {
		flag.Usage()
		return
	}

	opts := ExecOpts{
		Tenant:       tenant,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		State:        state,
		Scope:        scope,
	}

	urlToOpen := fmt.Sprintf(
		"https://login.microsoftonline.com/%v/oauth2/v2.0/authorize?client_id=%v&response_type=code&redirect_uri=%v&response_mode=query&scope=%v&state=%v",
		opts.Tenant, opts.ClientID, url.QueryEscape(opts.RedirectURI), url.QueryEscape(opts.Scope), url.QueryEscape(opts.State),
	)
	logger.Info().Msgf("open this URL in your browser to start the flow: %v", urlToOpen)

	http.HandleFunc("/token", handleAuthCode(opts))

	if err := http.ListenAndServe(":3001", nil); err != nil {
		logger.Fatal().Msgf("server failed: %v", err)
	}
}

func handleAuthCode(opts ExecOpts) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			qs := r.URL.Query()

			if qs["error"] != nil {
				logger.Warning().Msgf("failed to auth on Office365: %v", qs["error_description"])
				return
			}

			logger.Print().Msgf("received state: %v", qs["state"])
			logger.Print().Msgf("received ID Token: %v", qs["id_token"])

			accessToken := getAccessToken(
				opts.Tenant,
				opts.ClientID, opts.Scope,
				qs["code"][0],
				opts.ClientSecret,
				opts.RedirectURI,
			)

			logger.Print().Msgf("received access token: [%v]", accessToken.AccessToken)
			logger.Print().Msgf("received ID token: [%v]", accessToken.IDToken)
		}

		rw.WriteHeader(http.StatusAccepted)
		fmt.Fprint(rw, "got it")
	}
}

func getAccessToken(tenant, clientId, scope, code, clientSecret, redirectURI string) AccessTokenResponseOK {
	resp, err := http.PostForm(
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
		url.Values{
			"client_id":     []string{clientId},
			"scope":         []string{scope},
			"code":          []string{code},
			"redirect_uri":  []string{redirectURI},
			"grant_type":    []string{"authorization_code"},
			"client_secret": []string{clientSecret},
		},
	)
	if err != nil {
		logger.Error().Msgf("failed to get access token. error: %v", err)
		return AccessTokenResponseOK{}
	}

	d, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Msgf("failed to get access token. error: %v", err)
		return AccessTokenResponseOK{}
	}
	defer func() { resp.Body.Close() }()

	var respBody AccessTokenResponseOK

	if err = json.Unmarshal(d, &respBody); err != nil {
		logger.Error().Msgf("failed to decode response. error: %v", err)
		return AccessTokenResponseOK{}
	}

	logger.Print().Msgf("access token response: %#v", respBody)

	return respBody
}
