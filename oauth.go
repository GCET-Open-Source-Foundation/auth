package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

/*
OAuthInit initializes the Google OAuth configuration.
It uses sync.Once to safely set the configuration once for this Auth instance.
*/
func (a *Auth) OAuthInit(clientID, clientSecret, redirectURL string) error {
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return ErrEmptyInput
	}

	a.oauthOnce.Do(func() {
		a.oauthConfig = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		}
	})
	return nil
}

/*
GetGoogleLoginURL generates the URL to the Google consent screen.
*/
func (a *Auth) GetGoogleLoginURL(state string) (string, error) {
	if state == "" {
		return "", ErrEmptyInput
	}
	if a.oauthConfig == nil {
		return "", ErrOAuthNotInitialized
	}
	return a.oauthConfig.AuthCodeURL(state), nil
}

/*
HandleGoogleCallback exchanges the auth code for a token, fetches user info,
upserts the user into the database, and returns a generated JWT string.
*/
func (a *Auth) HandleGoogleCallback(ctx context.Context, code string) (string, error) {
	if code == "" {
		return "", ErrEmptyInput
	}
	if a.oauthConfig == nil {
		return "", ErrOAuthNotInitialized
	}

	token, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}

	client := a.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProfileFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status code %d", ErrOAuthProfileFetchFailed, resp.StatusCode)
	}

	var user googleUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProfileFetchFailed, err)
	}

	if !user.VerifiedEmail {
		return "", fmt.Errorf("oauth email is not verified by provider")
	}

	if err := a.upsertOAuthUser(ctx, user.Email); err != nil {
		return "", err
	}

	jwtStr, err := a.GenerateToken(user.Email)
	if err != nil {
		return "", fmt.Errorf("failed to generate jwt after oauth login: %w", err)
	}

	return jwtStr, nil
}
