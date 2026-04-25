package auth

import "errors"

var (
	ErrNotInitialized      = errors.New("auth package not initialized")
	ErrDatabaseUnavailable = errors.New("database connection unavailable")
	ErrInvalidToken        = errors.New("invalid jwt token")
	ErrTokenExpired        = errors.New("jwt token expired")
	ErrOTPExpired          = errors.New("otp expired")
	ErrInvalidOTP          = errors.New("invalid otp code")
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrSMTPNotInitialized  = errors.New("smtp not initialized")
	ErrJWTSecretMissing    = errors.New("jwt secret not initialized")
	ErrInvalidInput        = errors.New("invalid input provided")
	ErrInvalidEmail        = errors.New("invalid email format")
	ErrEmptyInput          = errors.New("required field cannot be empty")
	ErrOAuthNotInit        = errors.New("oauth not initialized")
	ErrOAuthExchangeFailed = errors.New("oauth code exchange failed")
	ErrOAuthProfileFailed  = errors.New("oauth profile fetch failed")
)
