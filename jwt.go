package auth

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims defines JWT payload
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// loadSecret reads the secret from a file or env var
func loadSecret() ([]byte, error) {
	// First, try file (for Docker/K8s)
	if path := os.Getenv("JWT_SECRET_FILE"); strings.TrimSpace(path) != "" {
		if data, err := os.ReadFile(path); err == nil { // <-- changed from ioutil.ReadFile
			return []byte(strings.TrimSpace(string(data))), nil
		}
	}

	// Fallback to env var
	if s := os.Getenv("JWT_SECRET"); strings.TrimSpace(s) != "" {
		return []byte(s), nil
	}

	return nil, fmt.Errorf("JWT secret not found. Set JWT_SECRET or JWT_SECRET_FILE")
}

// GenerateToken creates JWT for a user ID, duration = token expiry
func GenerateToken(userID string, duration time.Duration) (string, error) {
	secret, err := loadSecret()
	if err != nil {
		return "", err
	}

	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return signed, nil
}

// ParseToken validates JWT and returns user ID
func ParseToken(tokenStr string) (string, error) {
	secret, err := loadSecret()
	if err != nil {
		return "", err
	}

	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims.UserID, nil
	}

	return "", fmt.Errorf("invalid token")
}
