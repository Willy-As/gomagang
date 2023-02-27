package auth

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var GoogleOauthConfig *oauth2.Config

func init() {
	GoogleOauthConfig = &oauth2.Config{
		RedirectURL:  "https://magang.up.railway.app/auth/google/callback",
		ClientID:     "1088941664415-jf8agui0m00h84kqgcv42i9npfg821cm.apps.googleusercontent.com",
		ClientSecret: "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",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}
