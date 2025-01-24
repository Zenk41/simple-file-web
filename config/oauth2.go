package config

import (

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	GoogleOauthConfigRegister oauth2.Config
	GoogleOauthConfigLogin    oauth2.Config
}

var AppConfig Config

func GoogleConfig(clientID, clientSecret, registerCallback, loginCallback string) {
	AppConfig.GoogleOauthConfigRegister = oauth2.Config{
		RedirectURL:  registerCallback,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	AppConfig.GoogleOauthConfigLogin = oauth2.Config{
		RedirectURL:  loginCallback,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}