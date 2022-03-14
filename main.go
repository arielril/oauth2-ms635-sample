package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/arielril/oauth2-ms365-sample/log"
	"github.com/pkg/browser"
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
	flag.StringVar(&state, "state", "", "Request state")

	var scope string
	flag.StringVar(&scope, "scope", "openid user.read", "Authorization Scope")

	flag.Parse()

	if clientID == "" || clientSecret == "" {
		flag.Usage()
		return
	}

	if state == "" {
		state = generateRandomString(20)
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
	logger.Info().Msgf("this URL will open on your browser to start the flow:\n\t%v\n", urlToOpen)

	err := browser.OpenURL(urlToOpen)
	if err != nil {
		logger.Warning().Msgf("could not open url in browser. please copy and open manually. error: %v\n", err)
	}

	http.HandleFunc("/token", handleAuthCode(opts))

	if err := http.ListenAndServe(":3001", nil); err != nil {
		logger.Fatal().Msgf("server failed: %v\n", err)
	}
}

func handleAuthCode(opts ExecOpts) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			qs := r.URL.Query()

			if qs["error"] != nil {
				logger.Warning().Msgf("failed to auth on Office365: %v\n", qs["error_description"])
				return
			}

			logger.Print().Label("AUT").Msgf("received state: %v\n", qs["state"])
			logger.Print().Label("AUT").Msgf("received ID Token: %v\n", qs["id_token"])

			accessToken := getAccessToken(
				opts.Tenant,
				opts.ClientID, opts.Scope,
				qs["code"][0],
				opts.ClientSecret,
				opts.RedirectURI,
			)

			logger.Print().Label("TOK").Msgf("received access token: [%v]\n", accessToken.AccessToken)
			logger.Print().Label("TOK").Msgf("received ID token: [%v]\n", accessToken.IDToken)
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
		logger.Error().Msgf("failed to get access token. error: %v\n", err)
		return AccessTokenResponseOK{}
	}

	d, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Msgf("failed to get access token. error: %v\n", err)
		return AccessTokenResponseOK{}
	}
	defer func() { resp.Body.Close() }()

	var respBody AccessTokenResponseOK

	if err = json.Unmarshal(d, &respBody); err != nil {
		logger.Error().Msgf("failed to decode response. error: %v\n", err)
		return AccessTokenResponseOK{}
	}

	return respBody
}

func generateRandomString(length int) string {
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	bts := make([]byte, length)

	if _, err := rand.Read(bts); err != nil {
		return ""
	}

	for i, b := range bts {
		bts[i] = chars[b%byte(len(chars))]
	}

	return string(bts)
}
