package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// GetGoogleLoginURL generates the Google OAuth login URL.
func (a *Auth) GetGoogleLoginURL(state string) (string, error) {
	if a.oauthConfig == nil {
		return "", ErrOAuthNotInit
	}
	return a.oauthConfig.AuthCodeURL(state), nil
}

// HandleGoogleCallback handles the callback from Google OAuth,
// fetches the user profile, upserts the user into the database,
// and returns a signed JWT token.
func (a *Auth) HandleGoogleCallback(ctx context.Context, code string) (string, error) {
	if a.oauthConfig == nil {
		return "", ErrOAuthNotInit
	}

	// Exchange the authorization code for a token
	token, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}

	// Fetch user profile from Google
	client := a.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProfileFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: non-200 status code", ErrOAuthProfileFailed)
	}

	var profile struct {
		Email string `json:"email"`
		Id    string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return "", fmt.Errorf("%w: failed to parse profile: %v", ErrOAuthProfileFailed, err)
	}

	if profile.Email == "" {
		return "", fmt.Errorf("%w: no email returned from profile", ErrOAuthProfileFailed)
	}

	// Upsert user into database
	if err := a.upsertOAuthUser(profile.Email); err != nil {
		return "", err
	}

	// Generate and return JWT token
	return a.GenerateToken(profile.Email)
}
