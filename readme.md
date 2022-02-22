# OAuth2 Authorization Code Flow - Microsoft Office365 Sample

This is a CLI that can help testing the configuration from Azure Applications, executing the OAuth2 Authorization Code Flow. 

The CLI starts a Go HTTP server listening in the port 3001, by default. 

The execution result will be a log of the `access_token` and `id_token` returned from Microsoft Graph API.

## Installation

```sh
$ go install -v github.com/arielril/oauth2-ms365-sample
```

## Usage

```sh
$ oauth2-ms365-sample
  -client_id string
    	Required. Application Client ID
  -client_secret string
    	Required. Application Client Secret
  -redirect string
    	Application redirect URI (default "http://localhost:3001/token")
  -scope string
    	Authorization Scope (default "openid user.read")
  -state string
    	Request state
  -tenant string
    	Tenant ID (default "common")
```

For this CLI to work, it is needed to set the redirect URI in the Azure Application configuration to have the value `http://localhost:3001/token`.

### Execute the Authorization Code Flow

```sh
$ oauth2-ms365-sample -state "MyCrazyAuthCode" -client_id "DB6AA2C9-9311-4B82-B8C3-ECBC43CD56BB" -client_secret "C2186546-B88E-4627-BC3B-5313C1E0ECE7" -scope "openid" -tenant "B78B2739-5EA6-487D-83E3-33D6253559FA"

[INF] open this URL in your browser to start the flow: https://login.microsoftonline.com/B78B2739-5EA6-487D-83E3-33D6253559FA/oauth2/v2.0/authorize?client_id=DB6AA2C9-9311-4B82-B8C3-ECBC43CD56BB&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Ftoken&response_mode=query&scope=openid&state=MyCrazyAuthCode
[AUT] received state: [MyCrazyAuthCode]
[AUT] received ID Token: []
[TOK] received access token: [<access_token_jwt>]
[TOK] received ID token: [<id_token_jwt>]
```
