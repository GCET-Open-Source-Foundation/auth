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

func Register_user(username, password string) bool {
	if !init_check {
		return false
	}

	salt, err := generate_salt(32)
	if err != nil {
		return false
	}

	hash := Hash_password(password, salt)

	_, err = conn.Exec(context.Background(),
		"INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)",
		username, hash, salt,
	)

	return err == nil
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
