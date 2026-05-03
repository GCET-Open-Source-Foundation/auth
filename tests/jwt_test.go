package tests

import (
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
TestJWTInit verifies that the JWT secret and expiry are set correctly.
*/
func TestJWTInit(t *testing.T) {
	a := auth.NewBareAuth()

	/* Empty secret should fail */
	if err := a.JWTInit(""); err == nil {
		t.Error("expected error for empty JWT secret")
	}

	/* Valid secret should succeed */
	if err := a.JWTInit("my-secret-key"); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

/*
TestJWTInitCustomExpiry verifies that a custom expiry is applied.
*/
func TestJWTInitCustomExpiry(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.JWTInit("secret", 2*time.Hour); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	/* Generate and validate — if it works the expiry was accepted */
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

/*
TestJWTInitIdempotent verifies that JWTInit only sets the secret once.
*/
func TestJWTInitIdempotent(t *testing.T) {
	a := auth.NewBareAuth()

	_ = a.JWTInit("first-secret")
	_ = a.JWTInit("second-secret")

	/* Token generated should only work with the first secret */
	token, _ := a.GenerateToken("testuser")

	b := auth.NewBareAuth()
	_ = b.JWTInit("first-secret")

	_, err := b.ValidateToken(token)
	if err != nil {
		t.Error("token should validate with first secret (sync.Once should ignore second)")
	}
}

/*
TestGenerateToken verifies that a valid JWT is generated for a given user.
*/
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

/*
TestGenerateTokenEmpty checks that empty username is rejected.
*/
func TestGenerateTokenEmpty(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	_, err := a.GenerateToken("")
	if err == nil {
		t.Error("expected error for empty username")
	}
}

/*
TestGenerateTokenNotInitialized checks that token generation fails without JWTInit.
*/
func TestGenerateTokenNotInitialized(t *testing.T) {
	a := auth.NewBareAuth()

	_, err := a.GenerateToken("testuser")
	if err == nil {
		t.Error("expected error when JWT is not initialized")
	}
}

/*
TestValidateToken verifies the full generate-then-validate round trip.
*/
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

/*
TestValidateTokenExpired checks that an expired token is correctly rejected.
*/
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

/*
TestValidateTokenInvalidString checks that garbage input is rejected.
*/
func TestValidateTokenInvalidString(t *testing.T) {
	a := auth.NewBareAuth()
	_ = a.JWTInit("test-secret")

	_, err := a.ValidateToken("this.is.not.a.valid.jwt")
	if err == nil {
		t.Error("expected error for invalid token string")
	}
}

/*
TestValidateTokenWrongSecret checks that a token signed with a different secret fails.
*/
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

/*
TestLoginJWT verifies that LoginJWT works as a pass-through to ValidateToken.
*/
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

/*
TestGenerateTokenCustomExpiry verifies that a custom expiry produces a valid token.
*/
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
