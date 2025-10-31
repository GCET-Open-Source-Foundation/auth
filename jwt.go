package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
A secret key for signing JWTs.
This is stored in memory only, similar to the pepper.
*/
var jwt_secret []byte

/*
A global variable to check if the JWT secret has been set.
*/
var jwt_init_check bool = false

/*
jwt_claims struct defines the custom claims for our JWT.
It includes the standard RegisteredClaims and adds the user ID.
*/
type jwt_claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

/*
JWT_init sets the secret key used for signing and validating JWTs.

This function should be stricly called in the global call,
directly after calling auth.Init().

Losing or changing this secret will invalidate all existing tokens.
*/
func JWT_init(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}

	jwt_secret = []byte(secret)
	jwt_init_check = true
	return nil
}

/*
Generate_token creates a new, signed JWT for a given username
with a specified expiry duration.
*/
func Generate_token(username string, expiry_duration time.Duration) (string, error) {
	if !jwt_init_check {
		return "", fmt.Errorf("run auth.JWT_init() first to set the JWT secret")
	}
	if !init_check {
		return "", fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	claims := jwt_claims{
		username,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry_duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "gcet-auth-library",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token_string, err := token.SignedString(jwt_secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return token_string, nil
}

/*
Validate_token parses a token string, validates its signature and claims,
and returns the jwt_claims if the token is valid.

It is recommended to use users.go->Login_jwt() instead, as this
function may change.
*/
func Validate_token(token_string string) (*jwt_claims, error) {
	if !jwt_init_check {
		return nil, fmt.Errorf("run auth.JWT_init() first to set the JWT secret")
	}

	token, err := jwt.ParseWithClaims(token_string, &jwt_claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwt_secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	if claims, ok := token.Claims.(*jwt_claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
