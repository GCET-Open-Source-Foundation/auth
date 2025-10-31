package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generate_salt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(salt), nil
}

func Login_user(username, password string) bool {
	if !init_check {
		return false
	}

	var storedHash, storedSalt string
	query := "SELECT password_hash, salt FROM users WHERE user_id = $1"
	err := conn.QueryRow(context.Background(), query, username).Scan(&storedHash, &storedSalt)
	if err != nil {
		return false
	}

	if !compare_passwords(password, storedSalt, storedHash) {
		return false
	}

	return true
}

/*
Login_jwt validates a token string by calling auth.Validate_token (JWT login).
This is the recommended way to validate a user's JWT.
It returns the claims if the token is valid.
*/
func Login_jwt(token_string string) (*jwt_claims, error) {
	/*
		We call Validate_token from jwt.go to handle the logic.
		This keeps all user login methods in users.go, but all
		JWT logic in jwt.go.
	*/
	return Validate_token(token_string)
}

func Register_user(username, password string) error {
	if !init_check {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	salt, err := generate_salt(32)
	if err != nil {
		return err
	}

	hash := Hash_password(password, salt)

	_, err = conn.Exec(context.Background(),
		"INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)",
		username, hash, salt,
	)
	if err != nil {
		return err
	}

	return nil
}

func ChangePass(username, newPassword string) error {
	if !init_check {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	newSalt, err := generate_salt(32)
	if err != nil {
		return fmt.Errorf("could not generate new salt: %w", err)
	}

	newHash := Hash_password(newPassword, newSalt)

	cmdTag, err := conn.Exec(context.Background(),
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

func Delete_user(username string) error {
	if !init_check {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := conn.Exec(
		context.Background(),
		"DELETE FROM users WHERE user_id = $1",
		username,
	)

	if err != nil {
		return err
	}
	return nil
}
