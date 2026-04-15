package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateSalt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(salt), nil
}

func (a *Auth) LoginUser(username, password string) bool {
	if a.Conn == nil {
		return false
	}

	var storedHash, storedSalt string
	query := "SELECT password_hash, salt FROM users WHERE user_id = $1"
	err := a.Conn.QueryRow(context.Background(), query, username).Scan(&storedHash, &storedSalt)
	if err != nil {
		return false
	}

	if !a.comparePasswords(password, storedSalt, storedHash) {
		return false
	}

	return true
}

/*
LoginJWT validates a token string by calling auth.ValidateToken (JWT login).
This is the recommended way to validate a user's JWT.
It returns the claims if the token is valid.
*/
func (a *Auth) LoginJWT(tokenString string) (*JWTClaims, error) {
	/*
		We call ValidateToken from jwt.go to handle the logic.
		This keeps all user login methods in users.go, but all
		JWT logic in jwt.go.
	*/
	return a.ValidateToken(tokenString)
}

func (a *Auth) RegisterUser(username, password string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	salt, err := generateSalt(32)
	if err != nil {
		return err
	}

	hash := a.HashPassword(password, salt)

	_, err = a.Conn.Exec(context.Background(),
		"INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)",
		username, hash, salt,
	)
	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) ChangePass(username, newPassword string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	newSalt, err := generateSalt(32)
	if err != nil {
		return fmt.Errorf("could not generate new salt: %w", err)
	}

	newHash := a.HashPassword(newPassword, newSalt)

	cmdTag, err := a.Conn.Exec(context.Background(),
		"UPDATE users SET password_hash = $1, salt = $2 WHERE user_id = $3",
		newHash, newSalt, username,
	)
	if err != nil {
		return fmt.Errorf("database error while updating password: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("user '%s' not found", username)
	}

	return nil
}

func (a *Auth) DeleteUser(username string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.Conn.Exec(
		context.Background(),
		"DELETE FROM users WHERE user_id = $1",
		username,
	)

	if err != nil {
		return err
	}
	return nil
}
