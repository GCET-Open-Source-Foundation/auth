package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/mail"
)

func generateSalt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(salt), nil
}

func (a *Auth) LoginUser(username, password string) error {
	if a.Conn == nil {
		return ErrDatabaseUnavailable
	}

	var storedHash, storedSalt string
	query := "SELECT password_hash, salt FROM users WHERE user_id = $1"
	err := a.Conn.QueryRow(context.Background(), query, username).Scan(&storedHash, &storedSalt)
	if err != nil {
		return ErrUserNotFound
	}

	if !a.comparePasswords(password, storedSalt, storedHash) {
		return ErrInvalidCredentials
	}

	return nil
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
		return ErrNotInitialized
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
		return ErrNotInitialized
	}

	newSalt, err := generateSalt(32)
	if err != nil {
		return fmt.Errorf("%w: could not generate new salt: %v", ErrInvalidInput, err)
	}

	newHash := a.HashPassword(newPassword, newSalt)

	cmdTag, err := a.Conn.Exec(context.Background(),
		"UPDATE users SET password_hash = $1, salt = $2 WHERE user_id = $3",
		newHash, newSalt, username,
	)
	if err != nil {
		return fmt.Errorf("%w: database error while updating password: %v", ErrDatabaseUnavailable, err)
	}

	if cmdTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (a *Auth) DeleteUser(username string) error {
	if a.Conn == nil {
		return ErrNotInitialized
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

type User struct {
	UserID string `json:"user_id"`
}

func (a *Auth) UserExists(userEmail string) (bool, error) {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return false, ErrInvalidEmail
	}
	if a.Conn == nil {
		return false, ErrDatabaseUnavailable
	}

	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)"
	err := a.Conn.QueryRow(context.Background(), query, userEmail).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	return exists, nil
}

func (a *Auth) ListUsers(limit, offset int) ([]User, error) {
	if a.Conn == nil {
		return nil, ErrDatabaseUnavailable
	}

	query := "SELECT user_id FROM users LIMIT $1 OFFSET $2"
	rows, err := a.Conn.Query(context.Background(), query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UserID); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return users, nil
}
