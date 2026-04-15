package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
JWTClaims struct defines the custom claims for our JWT.
It includes the standard RegisteredClaims and adds the user ID.
*/
type JWTClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

/*
JWTInit sets the secret key and an optional expiration duration for JWTs.

It should be called immediately after auth.Init(). If no expiry is provided (or if it is <= 0),
the library uses the default 24-hour duration. 
Losing or changing this secret will invalidate all existing tokens.
*/
func (a *Auth) JWTInit(secret string, expiry ...time.Duration) error {
	if secret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}
	var effectiveExpiry time.Duration
	if len(expiry) > 0 {
		effectiveExpiry = expiry[0]
	}
	a.jwtOnce.Do(func() {
		a.jwtSecret = []byte(secret)
		if effectiveExpiry > 0 {
			a.jwtExpiry = effectiveExpiry
		}
	})
	return nil
}

/*
GenerateToken creates a new, signed JWT for a given username.
It supports an optional variadic expiryDuration for backward compatibility.
If no duration is provided, it falls back to the configured a.jwtExpiry.
*/
func (a *Auth) GenerateToken(username string, expiryDuration ...time.Duration) (string, error) {
    if len(a.jwtSecret) == 0 {
        return "", fmt.Errorf("run auth.JWTInit() first")
    }

    /* Logic to use passed duration OR fallback to struct config */
    var duration time.Duration
    if len(expiryDuration) > 0 {
        duration = expiryDuration[0]
    } else {
        duration = a.jwtExpiry
    }

    claims := JWTClaims{
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

	tokenString, err := token.SignedString(a.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

/*
ValidateToken parses a token string, validates its signature and claims,
and returns the JWTClaims if the token is valid.

It is recommended to use users.go->LoginJWT() instead, as this
function may change.
*/
func (a *Auth) ValidateToken(tokenString string) (*JWTClaims, error) {
	if len(a.jwtSecret) == 0 {
		return nil, fmt.Errorf("run auth.JWTInit() first to set the JWT secret")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
