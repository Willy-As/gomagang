package auth

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var GoogleOauthConfig *oauth2.Config

func init() {
	GoogleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     "1088941664415-jf8agui0m00h84kqgcv42i9npfg821cm.apps.googleusercontent.com",
		ClientSecret: "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",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}
