package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	GoogleOauthConfigRegister oauth2.Config
	GoogleOauthConfigLogin    oauth2.Config
}

var AppConfig Config

func GoogleConfig(v *viper.Viper) {

	// Debug: Print loaded environment variables
	fmt.Println("GOOGLE_CLIENT_ID in config:", v.GetString("GOOGLE_CLIENT_ID"))
	fmt.Println("GOOGLE_CLIENT_SECRET in config:", v.GetString("GOOGLE_CLIENT_SECRET"))

	AppConfig.GoogleOauthConfigRegister = oauth2.Config{
		RedirectURL:  fmt.Sprintf("http://localhost:%s/api/oauth/register/callback", os.Getenv("PORT")),
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	AppConfig.GoogleOauthConfigLogin = oauth2.Config{
		RedirectURL:  fmt.Sprintf("http://localhost:%s/api/oauth/login/callback", os.Getenv("PORT")),
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
}
