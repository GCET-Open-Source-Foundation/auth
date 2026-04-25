package tests

import (
	"errors"
	"fmt"
	"testing"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
TestErrorsAreSentinels verifies that all sentinel errors are distinct and non-nil.
*/
func TestErrorsAreSentinels(t *testing.T) {
	sentinels := []error{
		auth.ErrNotInitialized,
		auth.ErrDatabaseUnavailable,
		auth.ErrInvalidToken,
		auth.ErrTokenExpired,
		auth.ErrOTPExpired,
		auth.ErrInvalidOTP,
		auth.ErrUserNotFound,
		auth.ErrInvalidCredentials,
		auth.ErrSMTPNotInitialized,
		auth.ErrJWTSecretMissing,
		auth.ErrInvalidInput,
		auth.ErrInvalidEmail,
		auth.ErrEmptyInput,
		auth.ErrRateLimitExceeded,
		auth.ErrRefreshTokenInvalid,
		auth.ErrRefreshTokenRevoked,
		auth.ErrRefreshTokenExpired,
		auth.ErrOAuthNotInitialized,
		auth.ErrOAuthExchangeFailed,
		auth.ErrOAuthProfileFetchFailed,
	}

	for i, err := range sentinels {
		if err == nil {
			t.Errorf("sentinel error at index %d is nil", i)
		}
		for j, other := range sentinels {
			if i != j && errors.Is(err, other) {
				t.Errorf("sentinel errors at index %d and %d should be distinct", i, j)
			}
		}
	}
}

/*
TestErrorWrapping verifies that wrapped errors can be unwrapped to the sentinel.
*/
func TestErrorWrapping(t *testing.T) {
	wrapped := fmt.Errorf("%w: some detail", auth.ErrDatabaseUnavailable)

	if !errors.Is(wrapped, auth.ErrDatabaseUnavailable) {
		t.Error("wrapped error should match ErrDatabaseUnavailable via errors.Is")
	}
}
