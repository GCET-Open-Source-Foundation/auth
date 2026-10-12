package tests

import (
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

func TestRefreshTokenGenerateAndValidateWithRedis(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	if !setupRedis(t, a) {
		t.Skip("Redis is not available")
	}

	err := a.RefreshTokenInit(auth.RefreshTokenConfig{
		Expiry:      1 * time.Hour,
		TokenLength: 32,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userID := "user_123"
	_ = a.RegisterUser(userID, "password123")
	token, err := a.GenerateRefreshToken(userID)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	if len(token) == 0 {
		t.Fatal("expected non-empty token")
	}

	validUserID, err := a.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("unexpected error validating token: %v", err)
	}

	if validUserID != userID {
		t.Errorf("expected user ID %q, got %q", userID, validUserID)
	}
}

func TestRefreshTokenRevokeWithRedis(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	if !setupRedis(t, a) {
		t.Skip("Redis is not available")
	}

	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{
		Expiry:      1 * time.Hour,
		TokenLength: 32,
	})

	userID := "user_456"
	_ = a.RegisterUser(userID, "password456")
	token, _ := a.GenerateRefreshToken(userID)

	err := a.RevokeRefreshToken(token)
	if err != nil {
		t.Fatalf("unexpected error revoking token: %v", err)
	}

	_, err = a.ValidateRefreshToken(token)
	if err == nil {
		t.Error("expected error for revoked token")
	}
}

func TestRevokeAllUserRefreshTokensWithRedis(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	if !setupRedis(t, a) {
		t.Skip("Redis is not available")
	}

	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{
		Expiry:      1 * time.Hour,
		TokenLength: 32,
	})

	userID := "user_789"
	_ = a.RegisterUser(userID, "password789")
	token1, _ := a.GenerateRefreshToken(userID)
	token2, _ := a.GenerateRefreshToken(userID)

	_ = a.RegisterUser("user_other", "password_other")
	otherToken, _ := a.GenerateRefreshToken("user_other")

	err := a.RevokeAllUserRefreshTokens(userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := a.ValidateRefreshToken(token1); err == nil {
		t.Error("expected token1 to be invalid after mass revocation")
	}
	if _, err := a.ValidateRefreshToken(token2); err == nil {
		t.Error("expected token2 to be invalid after mass revocation")
	}

	if uid, err := a.ValidateRefreshToken(otherToken); err != nil || uid != "user_other" {
		t.Errorf("expected other user's token to remain valid, got err: %v", err)
	}
}
