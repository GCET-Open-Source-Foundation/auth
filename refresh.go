package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

/*
RefreshToken represents a stored refresh token in the database.
Each refresh token is tied to a user and has an expiration time.
Tokens can be individually revoked without affecting other tokens.
*/
type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

/*
RefreshTokenConfig holds the configuration for refresh token behaviour.
Expiry is how long a refresh token remains valid (e.g. 7 days).
TokenLength is the byte length of the random token (default 32 = 64 hex chars).
*/
type RefreshTokenConfig struct {
	Expiry      time.Duration
	TokenLength int
}

/*
RefreshTokenInit configures the refresh token settings on the Auth instance.
If tokenLength <= 0, it defaults to 32 bytes.
This must be called after Init() to use refresh token features.
*/
func (a *Auth) RefreshTokenInit(cfg RefreshTokenConfig) error {
	if cfg.Expiry <= 0 {
		return fmt.Errorf("%w: refresh token expiry must be positive", ErrInvalidInput)
	}

	if cfg.TokenLength <= 0 {
		cfg.TokenLength = 32
	}

	a.refreshTokenExpiry = cfg.Expiry
	a.refreshTokenLength = cfg.TokenLength

	return nil
}

/*
GenerateRefreshToken creates a new opaque refresh token for the given user,
stores it in the database, and returns the token string.
The caller should return this to the client alongside the JWT access token.
*/
func (a *Auth) GenerateRefreshToken(userID string) (string, error) {
	if userID == "" {
		return "", ErrEmptyInput
	}
	if a.Conn == nil {
		return "", ErrDatabaseUnavailable
	}
	if a.refreshTokenExpiry <= 0 {
		return "", fmt.Errorf("%w: refresh tokens not configured, call RefreshTokenInit first", ErrNotInitialized)
	}

	/* Generate a cryptographically secure random token */
	tokenBytes := make([]byte, a.refreshTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	expiresAt := time.Now().Add(a.refreshTokenExpiry)

	query := `
		INSERT INTO refresh_tokens (token, user_id, expires_at, revoked, created_at)
		VALUES ($1, $2, $3, false, NOW())
	`
	_, err := a.Conn.Exec(a.ctx, query, token, userID, expiresAt)
	if err != nil {
		return "", fmt.Errorf("%w: failed to store refresh token: %v", ErrDatabaseUnavailable, err)
	}

	return token, nil
}

/*
ValidateRefreshToken checks if a refresh token is valid (exists, not revoked, not expired).
If valid, it returns the associated user ID.
*/
func (a *Auth) ValidateRefreshToken(token string) (string, error) {
	if token == "" {
		return "", ErrEmptyInput
	}
	if a.Conn == nil {
		return "", ErrDatabaseUnavailable
	}

	var userID string
	var expiresAt time.Time
	var revoked bool

	query := "SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token = $1"
	err := a.Conn.QueryRow(a.ctx, query, token).Scan(&userID, &expiresAt, &revoked)
	if err != nil {
		return "", ErrRefreshTokenInvalid
	}

	if revoked {
		return "", ErrRefreshTokenRevoked
	}

	if time.Now().After(expiresAt) {
		return "", ErrRefreshTokenExpired
	}

	return userID, nil
}

/*
RotateRefreshToken validates the old refresh token, revokes it,
and issues a new one. This implements refresh token rotation, which
limits the damage if a token is leaked.

Returns the new token and the associated user ID.
*/
func (a *Auth) RotateRefreshToken(oldToken string) (newToken string, userID string, err error) {
	/* Validate the existing token first */
	userID, err = a.ValidateRefreshToken(oldToken)
	if err != nil {
		return "", "", err
	}

	/* Revoke the old token */
	if err := a.RevokeRefreshToken(oldToken); err != nil {
		return "", "", fmt.Errorf("failed to revoke old token: %w", err)
	}

	/* Issue a new one */
	newToken, err = a.GenerateRefreshToken(userID)
	if err != nil {
		return "", "", err
	}

	return newToken, userID, nil
}

/*
RevokeRefreshToken marks a specific refresh token as revoked.
The token will no longer pass validation.
*/
func (a *Auth) RevokeRefreshToken(token string) error {
	if token == "" {
		return ErrEmptyInput
	}
	if a.Conn == nil {
		return ErrDatabaseUnavailable
	}

	cmdTag, err := a.Conn.Exec(a.ctx,
		"UPDATE refresh_tokens SET revoked = true WHERE token = $1",
		token,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	if cmdTag.RowsAffected() == 0 {
		return ErrRefreshTokenInvalid
	}

	return nil
}

/*
RevokeAllUserRefreshTokens revokes every refresh token for a given user.
Use this when a user changes their password or you detect suspicious activity.
*/
func (a *Auth) RevokeAllUserRefreshTokens(userID string) error {
	if userID == "" {
		return ErrEmptyInput
	}
	if a.Conn == nil {
		return ErrDatabaseUnavailable
	}

	_, err := a.Conn.Exec(a.ctx,
		"UPDATE refresh_tokens SET revoked = true WHERE user_id = $1",
		userID,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	return nil
}

/*
CleanupExpiredRefreshTokens removes expired refresh tokens from the database.
This is called periodically by the background cleanup routine.
*/
func (a *Auth) CleanupExpiredRefreshTokens() error {
	if a.Conn == nil {
		return ErrDatabaseUnavailable
	}

	_, err := a.Conn.Exec(a.ctx,
		"DELETE FROM refresh_tokens WHERE expires_at < NOW()",
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	return nil
}
