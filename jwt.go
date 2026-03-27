package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
jwt_claims struct defines the custom claims for our JWT.
It includes the standard RegisteredClaims and adds the user ID.
*/
type jwt_claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

/*
JWT_init sets the secret key and an optional expiration duration for JWTs.

It should be called immediately after auth.Init(). If no expiry is provided (or if it is <= 0),
the library uses the default 24-hour duration. 
Losing or changing this secret will invalidate all existing tokens.
*/
func (a *Auth) JWT_init(secret string, expiry ...time.Duration) error {
	if secret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}
	var effectiveExpiry time.Duration
	if len(expiry) > 0 {
		effectiveExpiry = expiry[0]
	}
	a.jwt_once.Do(func() {
		a.jwt_secret = []byte(secret)
		if effectiveExpiry > 0 {
			a.jwt_expiry = effectiveExpiry
		}
	})
	return nil
}

/*
Generate_token creates a new, signed JWT for a given username.
It supports an optional variadic expiry_duration for backward compatibility.
If no duration is provided, it falls back to the configured a.jwt_expiry.
*/
func (a *Auth) Generate_token(username string, expiry_duration ...time.Duration) (string, error) {
    if len(a.jwt_secret) == 0 {
        return "", fmt.Errorf("run auth.JWT_init() first")
    }

    /* Logic to use passed duration OR fallback to struct config */
    var duration time.Duration
    if len(expiry_duration) > 0 {
        duration = expiry_duration[0]
    } else {
        duration = a.jwt_expiry
    }

    claims := jwt_claims{
        UserID: username,
    	RegisteredClaims: jwt.RegisteredClaims{
        	ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "gcet-auth-library",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token_string, err := token.SignedString(a.jwt_secret)
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
func (a *Auth) Validate_token(token_string string) (*jwt_claims, error) {
	if len(a.jwt_secret) == 0 {
		return nil, fmt.Errorf("run auth.JWT_init() first to set the JWT secret")
	}

	token, err := jwt.ParseWithClaims(token_string, &jwt_claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwt_secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	if claims, ok := token.Claims.(*jwt_claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
