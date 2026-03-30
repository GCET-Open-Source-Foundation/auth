package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	google_auth_url  = "https://accounts.google.com/o/oauth2/v2/auth"
	google_token_url = "https://oauth2.googleapis.com/token"
	google_user_url  = "https://www.googleapis.com/oauth2/v2/userinfo"
)

type GoogleUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type google_token_response struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

/*
Google_auth_url returns the URL to redirect the user to for Google login.
The state parameter should be a random string to prevent CSRF attacks.
*/
func (a *Auth) Google_auth_url(state string) (string, error) {
	if a.google_client_id == "" {
		return "", fmt.Errorf("run auth.Google_init() first")
	}

	params := url.Values{
		"client_id":     {a.google_client_id},
		"redirect_uri":  {a.google_redirect_url},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
	}

	return google_auth_url + "?" + params.Encode(), nil
}

/*
Google_exchange takes the authorization code from Google's callback
and exchanges it for the user's profile information.
*/
func (a *Auth) Google_exchange(code string) (*GoogleUser, error) {
	if a.google_client_id == "" {
		return nil, fmt.Errorf("run auth.Google_init() first")
	}

	/* Exchange code for access token */
	data := url.Values{
		"code":          {code},
		"client_id":     {a.google_client_id},
		"client_secret": {a.google_client_secret},
		"redirect_uri":  {a.google_redirect_url},
		"grant_type":    {"authorization_code"},
	}

	resp, err := http.Post(google_token_url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp google_token_response
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	/* Use access token to get user info */
	req, err := http.NewRequest("GET", google_user_url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info: %w", err)
	}

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo request failed (status %d): %s", userResp.StatusCode, string(userBody))
	}

	var user GoogleUser
	if err := json.Unmarshal(userBody, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &user, nil
}

/*
user_exists checks if a user_id already exists in the users table.
*/
func (a *Auth) user_exists(userID string) bool {
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM users WHERE user_id = $1)"
	err := a.Conn.QueryRow(context.Background(), query, userID).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

/*
Link_google links a Google account to a user.
If the user doesn't exist in the users table, it creates them automatically
with a random password so that all existing functions (permissions, roles,
JWT) work with OAuth users out of the box.
*/
func (a *Auth) Link_google(guser *GoogleUser, userID string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first")
	}

	/* Create the user in the users table if they don't exist */
	if !a.user_exists(userID) {
		randomBytes := make([]byte, 32)
		_, err := rand.Read(randomBytes)
		if err != nil {
			return fmt.Errorf("failed to generate random password: %w", err)
		}
		randomPass := base64.RawStdEncoding.EncodeToString(randomBytes)

		err = a.Register_user(userID, randomPass)
		if err != nil {
			return fmt.Errorf("failed to auto-register oauth user: %w", err)
		}
	}

	/* Link the Google account to the user */
	query := `
		INSERT INTO oauth_users (provider, provider_id, user_id, email, name)
		VALUES ('google', $1, $2, $3, $4)
		ON CONFLICT (provider, provider_id)
		DO UPDATE SET email = $3, name = $4
	`
	_, err := a.Conn.Exec(context.Background(), query, guser.ID, userID, guser.Email, guser.Name)
	if err != nil {
		return fmt.Errorf("failed to link google account: %w", err)
	}

	return nil
}
