package tests

import (
	"context"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/* ======================== Init / Close ======================== */

/*
TestInitEmptyInputs verifies that Init rejects empty required fields.
*/
func TestInitEmptyInputs(t *testing.T) {
	ctx := context.Background()

	if _, err := auth.Init(ctx, 5432, "", "pass", "dbname", "localhost"); err == nil {
		t.Error("expected error for empty dbUser")
	}
	if _, err := auth.Init(ctx, 5432, "user", "pass", "", "localhost"); err == nil {
		t.Error("expected error for empty dbName")
	}
	if _, err := auth.Init(ctx, 5432, "user", "pass", "dbname", ""); err == nil {
		t.Error("expected error for empty host")
	}
}

/*
TestInitBadConnection verifies that Init fails gracefully with a bad database connection.
*/
func TestInitBadConnection(t *testing.T) {
	ctx := context.Background()

	_, err := auth.Init(ctx, 9999, "nobody", "wrong", "noexist", "127.0.0.1")
	if err == nil {
		t.Error("expected error for bad database connection")
	}
}

/*
TestSMTPInitEmptyInputs verifies that SMTPInit rejects empty fields.
*/
func TestSMTPInitEmptyInputs(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.SMTPInit("", "pass", "host", "587"); err == nil {
		t.Error("expected error for empty email")
	}
	if err := a.SMTPInit("user@test.com", "", "host", "587"); err == nil {
		t.Error("expected error for empty password")
	}
	if err := a.SMTPInit("user@test.com", "pass", "", "587"); err == nil {
		t.Error("expected error for empty host")
	}
	if err := a.SMTPInit("user@test.com", "pass", "host", ""); err == nil {
		t.Error("expected error for empty port")
	}
}

/*
TestSMTPInitInvalidEmail verifies that SMTPInit rejects malformed emails.
*/
func TestSMTPInitInvalidEmail(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.SMTPInit("not-an-email", "pass", "host", "587"); err == nil {
		t.Error("expected error for invalid email")
	}
}

/*
TestSMTPInitValid verifies that SMTPInit accepts valid input.
*/
func TestSMTPInitValid(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.SMTPInit("user@example.com", "password", "smtp.example.com", "587"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

/*
TestCloseDoesNotPanic verifies that Close does not panic on a freshly init'd Auth.
*/
func TestCloseDoesNotPanic(t *testing.T) {
	a := auth.NewBareAuth()
	a.Close()
}

/* ======================== OTP Config ======================== */

/*
TestOTPInitValid verifies that OTPInit accepts valid config.
*/
func TestOTPInitValid(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.OTPInit(8, 10*time.Minute); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

/*
TestOTPInitInvalid verifies that OTPInit rejects bad config.
*/
func TestOTPInitInvalid(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.OTPInit(3, 5*time.Minute); err == nil {
		t.Error("expected error for length < 4")
	}
	if err := a.OTPInit(11, 5*time.Minute); err == nil {
		t.Error("expected error for length > 10")
	}
	if err := a.OTPInit(6, -1*time.Minute); err == nil {
		t.Error("expected error for negative expiry")
	}
	if err := a.OTPInit(6, 0); err == nil {
		t.Error("expected error for zero expiry")
	}
}

/* ======================== Refresh Token Config ======================== */

/*
TestRefreshTokenInitValid verifies that RefreshTokenInit accepts valid config.
*/
func TestRefreshTokenInitValid(t *testing.T) {
	a := auth.NewBareAuth()

	err := a.RefreshTokenInit(auth.RefreshTokenConfig{
		Expiry:      7 * 24 * time.Hour,
		TokenLength: 32,
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

/*
TestRefreshTokenInitInvalid verifies that RefreshTokenInit rejects bad config.
*/
func TestRefreshTokenInitInvalid(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 0}); err == nil {
		t.Error("expected error for zero expiry")
	}
	if err := a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: -time.Hour}); err == nil {
		t.Error("expected error for negative expiry")
	}
}

/*
TestRefreshTokenEmptyInputs verifies that empty inputs are rejected.
*/
func TestRefreshTokenEmptyInputs(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: time.Hour})

	if _, err := a.GenerateRefreshToken(""); err == nil {
		t.Error("expected error for empty userID")
	}
	if _, err := a.ValidateRefreshToken(""); err == nil {
		t.Error("expected error for empty token")
	}
	if err := a.RevokeRefreshToken(""); err == nil {
		t.Error("expected error for empty token")
	}
	if err := a.RevokeAllUserRefreshTokens(""); err == nil {
		t.Error("expected error for empty userID")
	}
}
