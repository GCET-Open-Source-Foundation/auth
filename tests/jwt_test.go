package tests

import (
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

func TestJWTInit(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.JWTInit(""); err == nil {
		t.Error("expected error for empty JWT secret")
	}
	if err := a.JWTInit("my-secret-key"); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestJWTInitCustomExpiry(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.JWTInit("secret", 2*time.Hour); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := a.GenerateToken("testuser")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	claims, err := a.ValidateToken(token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}
	if claims.UserID != "testuser" {
		t.Errorf("expected 'testuser', got '%s'", claims.UserID)
	}
}

func TestJWTInitIdempotent(t *testing.T) {
	a := auth.NewBareAuth()

	_ = a.JWTInit("first-secret")
	_ = a.JWTInit("second-secret")

	token, _ := a.GenerateToken("testuser")

	b := auth.NewBareAuth()
	_ = b.JWTInit("first-secret")

	_, err := b.ValidateToken(token)
	if err != nil {
		t.Error("token should validate with first secret (sync.Once should ignore second)")
	}
}

func TestGenerateToken(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	token, err := a.GenerateToken("testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Error("expected a non-empty token")
	}
}

func TestGenerateTokenEmpty(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	_, err := a.GenerateToken("")
	if err == nil {
		t.Error("expected error for empty username")
	}
}

func TestGenerateTokenNotInitialized(t *testing.T) {
	a := auth.NewBareAuth()

	_, err := a.GenerateToken("testuser")
	if err == nil {
		t.Error("expected error when JWT is not initialized")
	}
}

func TestValidateToken(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	token, err := a.GenerateToken("testuser")
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	claims, err := a.ValidateToken(token)
	if err != nil {
		t.Fatalf("unexpected error validating token: %v", err)
	}
	if claims.UserID != "testuser" {
		t.Errorf("expected UserID 'testuser', got '%s'", claims.UserID)
	}
}

func TestValidateTokenExpired(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	token, err := a.GenerateToken("testuser", -1*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = a.ValidateToken(token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidateTokenInvalidString(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	_, err := a.ValidateToken("this.is.not.a.valid.jwt")
	if err == nil {
		t.Error("expected error for invalid token string")
	}
}

func TestValidateTokenWrongSecret(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("secret-one")

	token, err := a.GenerateToken("testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b := auth.NewBareAuth()
	_ = b.JWTInit("secret-two")

	_, err = b.ValidateToken(token)
	if err == nil {
		t.Error("expected error when validating with wrong secret")
	}
}

func TestLoginJWT(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	token, err := a.GenerateToken("jwtuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := a.LoginJWT(token)
	if err != nil {
		t.Fatalf("unexpected error from LoginJWT: %v", err)
	}
	if claims.UserID != "jwtuser" {
		t.Errorf("expected UserID 'jwtuser', got '%s'", claims.UserID)
	}
}

func TestGenerateTokenCustomExpiry(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	token, err := a.GenerateToken("testuser", 1*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := a.ValidateToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "testuser" {
		t.Errorf("expected UserID 'testuser', got '%s'", claims.UserID)
	}
}
