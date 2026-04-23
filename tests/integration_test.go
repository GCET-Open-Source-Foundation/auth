package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/* ======================== Init Integration ======================== */

/*
TestIntegrationInit verifies that Init successfully connects to a real database
and creates all required tables.
*/
func TestIntegrationInit(t *testing.T) {
	a := setupTestAuth(t)

	if a.Conn == nil {
		t.Fatal("expected non-nil database connection")
	}
}

/* ======================== User Registration & Login ======================== */

/*
TestIntegrationRegisterAndLogin tests the full user lifecycle:
register -> login -> wrong password -> non-existent user -> delete -> post-delete.
*/
func TestIntegrationRegisterAndLogin(t *testing.T) {
	a := setupTestAuth(t)

	err := a.RegisterUser("alice@example.com", "strongP@ssw0rd")
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}

	err = a.LoginUser("alice@example.com", "strongP@ssw0rd")
	if err != nil {
		t.Errorf("expected successful login, got: %v", err)
	}

	err = a.LoginUser("alice@example.com", "wrongpassword")
	if err == nil {
		t.Error("expected error for wrong password")
	}

	err = a.LoginUser("nobody@example.com", "password")
	if err == nil {
		t.Error("expected error for non-existent user")
	}

	err = a.DeleteUser("alice@example.com")
	if err != nil {
		t.Errorf("failed to delete user: %v", err)
	}

	err = a.LoginUser("alice@example.com", "strongP@ssw0rd")
	if err == nil {
		t.Error("expected error logging in after deletion")
	}
}

/*
TestIntegrationUserExists verifies the UserExists check against a real database.
*/
func TestIntegrationUserExists(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RegisterUser("check@example.com", "password123")

	exists, err := a.UserExists("check@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist")
	}

	exists, err = a.UserExists("nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected user not to exist")
	}
}

/*
TestIntegrationListUsers verifies pagination of users.
*/
func TestIntegrationListUsers(t *testing.T) {
	a := setupTestAuth(t)

	_ = a.RegisterUser("list1@example.com", "pass1")
	_ = a.RegisterUser("list2@example.com", "pass2")
	_ = a.RegisterUser("list3@example.com", "pass3")

	users, err := a.ListUsers(2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}

	users, err = a.ListUsers(10, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user on second page, got %d", len(users))
	}
}

/*
TestIntegrationChangePassword verifies that password changes work end-to-end.
*/
func TestIntegrationChangePassword(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RegisterUser("changeme@example.com", "oldPassword")

	err := a.ChangePass("changeme@example.com", "newPassword")
	if err != nil {
		t.Fatalf("failed to change password: %v", err)
	}

	err = a.LoginUser("changeme@example.com", "oldPassword")
	if err == nil {
		t.Error("expected old password to fail after change")
	}

	err = a.LoginUser("changeme@example.com", "newPassword")
	if err != nil {
		t.Errorf("expected new password to succeed: %v", err)
	}
}

/*
TestIntegrationChangePassNonExistent verifies that changing a ghost user's password fails.
*/
func TestIntegrationChangePassNonExistent(t *testing.T) {
	a := setupTestAuth(t)

	err := a.ChangePass("ghost@example.com", "newpass")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got: %v", err)
	}
}

/*
TestIntegrationDuplicateRegistration verifies PK constraint on duplicate user.
*/
func TestIntegrationDuplicateRegistration(t *testing.T) {
	a := setupTestAuth(t)

	err := a.RegisterUser("dupe@example.com", "password1")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	err = a.RegisterUser("dupe@example.com", "password2")
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

/* ======================== User + JWT Combined ======================== */

/*
TestIntegrationRegisterLoginJWT tests:
register -> login with password -> generate JWT -> validate -> LoginJWT.
*/
func TestIntegrationRegisterLoginJWT(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.JWTInit("integration-test-secret")
	_ = a.RegisterUser("jwtuser@example.com", "securepass")

	err := a.LoginUser("jwtuser@example.com", "securepass")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	token, err := a.GenerateToken("jwtuser@example.com")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := a.ValidateToken(token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}
	if claims.UserID != "jwtuser@example.com" {
		t.Errorf("expected 'jwtuser@example.com', got '%s'", claims.UserID)
	}

	claims2, err := a.LoginJWT(token)
	if err != nil {
		t.Fatalf("LoginJWT failed: %v", err)
	}
	if claims2.UserID != "jwtuser@example.com" {
		t.Errorf("expected 'jwtuser@example.com', got '%s'", claims2.UserID)
	}
}

/* ======================== User + Pepper ======================== */

/*
TestIntegrationPepperRegistration verifies peppered registration round-trip.
*/
func TestIntegrationPepperRegistration(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.PepperInit("test-pepper-value")
	_ = a.RegisterUser("peppered@example.com", "mypassword")

	err := a.LoginUser("peppered@example.com", "mypassword")
	if err != nil {
		t.Errorf("login with pepper should succeed: %v", err)
	}
}

/* ======================== Spaces, Roles, Permissions ======================== */

/*
TestIntegrationSpacesRolesPermissions tests the complete RBAC lifecycle.
*/
func TestIntegrationSpacesRolesPermissions(t *testing.T) {
	a := setupTestAuth(t)

	err := a.CreateSpace("workspace-alpha", 1)
	if err != nil {
		t.Fatalf("failed to create space: %v", err)
	}

	err = a.CreateRole("admin")
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	_ = a.RegisterUser("rbac@example.com", "password")

	err = a.CreatePermissions("rbac@example.com", "workspace-alpha", "admin")
	if err != nil {
		t.Fatalf("failed to assign permission: %v", err)
	}

	err = a.CheckPermissions("rbac@example.com", "workspace-alpha", "admin")
	if err != nil {
		t.Errorf("expected permission to exist: %v", err)
	}

	err = a.CheckPermissions("rbac@example.com", "workspace-alpha", "viewer")
	if err == nil {
		t.Error("expected error for non-existent permission")
	}

	_ = a.DeletePermission("rbac@example.com", "workspace-alpha", "admin")

	err = a.CheckPermissions("rbac@example.com", "workspace-alpha", "admin")
	if err == nil {
		t.Error("expected error after deleting permission")
	}

	_ = a.DeleteRole("admin")
	_ = a.DeleteSpace("workspace-alpha")
}

/*
TestIntegrationCascadeDeleteUser verifies FK ON DELETE CASCADE for permissions.
*/
func TestIntegrationCascadeDeleteUser(t *testing.T) {
	a := setupTestAuth(t)

	_ = a.CreateSpace("cascade-space", 1)
	_ = a.CreateRole("editor")
	_ = a.RegisterUser("cascade@example.com", "password")
	_ = a.CreatePermissions("cascade@example.com", "cascade-space", "editor")

	err := a.CheckPermissions("cascade@example.com", "cascade-space", "editor")
	if err != nil {
		t.Fatalf("permission should exist before delete: %v", err)
	}

	_ = a.DeleteUser("cascade@example.com")

	err = a.CheckPermissions("cascade@example.com", "cascade-space", "editor")
	if err == nil {
		t.Error("expected permission to be cascade-deleted with user")
	}
}

/* ======================== OTP Integration ======================== */

/*
TestIntegrationOTPVerify tests OTP store/verify round-trip.
We bypass SendOTP (needs real SMTP) and insert directly.
*/
func TestIntegrationOTPVerify(t *testing.T) {
	a := setupTestAuth(t)

	expiry := time.Now().Add(5 * time.Minute)
	_, err := a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"otp@example.com", "123456", expiry,
	)
	if err != nil {
		t.Fatalf("failed to insert test OTP: %v", err)
	}

	err = a.VerifyOTP("otp@example.com", "999999")
	if err == nil {
		t.Error("expected error for wrong OTP code")
	}

	err = a.VerifyOTP("otp@example.com", "123456")
	if err != nil {
		t.Errorf("expected OTP verification to succeed: %v", err)
	}

	err = a.VerifyOTP("otp@example.com", "123456")
	if err == nil {
		t.Error("expected error when reusing OTP")
	}
}

/*
TestIntegrationOTPExpired verifies that an expired OTP is rejected.
*/
func TestIntegrationOTPExpired(t *testing.T) {
	a := setupTestAuth(t)

	expiry := time.Now().Add(-1 * time.Minute)
	_, _ = a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"expired@example.com", "654321", expiry,
	)

	err := a.VerifyOTP("expired@example.com", "654321")
	if !errors.Is(err, auth.ErrOTPExpired) {
		t.Errorf("expected ErrOTPExpired, got: %v", err)
	}
}

/*
TestIntegrationOTPExists verifies the OTPExists function.
*/
func TestIntegrationOTPExists(t *testing.T) {
	a := setupTestAuth(t)

	expiry := time.Now().Add(5 * time.Minute)
	_, _ = a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"exists@example.com", "111111", expiry,
	)

	exists, err := a.OTPExists("exists@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected OTP to exist")
	}

	exists, err = a.OTPExists("nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected OTP not to exist")
	}
}

/*
TestIntegrationListActiveOTPs verifies listing of active OTPs.
*/
func TestIntegrationListActiveOTPs(t *testing.T) {
	a := setupTestAuth(t)

	expiry := time.Now().Add(5 * time.Minute)
	_, _ = a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"active1@example.com", "111111", expiry,
	)
	_, _ = a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"active2@example.com", "222222", expiry,
	)

	emails, err := a.ListActiveOTPs(10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(emails) < 2 {
		t.Errorf("expected at least 2 active OTPs, got %d", len(emails))
	}
}

/* ======================== Refresh Token Integration ======================== */

/*
TestIntegrationRefreshTokenFullCycle tests:
generate -> validate -> rotate -> old revoked -> new valid -> explicit revoke.
*/
func TestIntegrationRefreshTokenFullCycle(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour, TokenLength: 32})
	_ = a.RegisterUser("refresh@example.com", "password")

	token, err := a.GenerateRefreshToken("refresh@example.com")
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty refresh token")
	}
	if len(token) != 64 {
		t.Errorf("expected token length 64, got %d", len(token))
	}

	userID, err := a.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("failed to validate refresh token: %v", err)
	}
	if userID != "refresh@example.com" {
		t.Errorf("expected 'refresh@example.com', got '%s'", userID)
	}

	newToken, rotatedUserID, err := a.RotateRefreshToken(token)
	if err != nil {
		t.Fatalf("failed to rotate: %v", err)
	}
	if newToken == "" || newToken == token {
		t.Error("expected a new, different token")
	}
	if rotatedUserID != "refresh@example.com" {
		t.Errorf("expected 'refresh@example.com', got '%s'", rotatedUserID)
	}

	_, err = a.ValidateRefreshToken(token)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected ErrRefreshTokenRevoked for old token, got: %v", err)
	}

	_, err = a.ValidateRefreshToken(newToken)
	if err != nil {
		t.Fatalf("new token should be valid: %v", err)
	}

	_ = a.RevokeRefreshToken(newToken)

	_, err = a.ValidateRefreshToken(newToken)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected ErrRefreshTokenRevoked, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenRevokeAll tests revoking all tokens for a user.
*/
func TestIntegrationRefreshTokenRevokeAll(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour})
	_ = a.RegisterUser("revokeall@example.com", "password")

	token1, _ := a.GenerateRefreshToken("revokeall@example.com")
	token2, _ := a.GenerateRefreshToken("revokeall@example.com")
	token3, _ := a.GenerateRefreshToken("revokeall@example.com")

	_ = a.RevokeAllUserRefreshTokens("revokeall@example.com")

	for _, tok := range []string{token1, token2, token3} {
		_, err := a.ValidateRefreshToken(tok)
		if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
			t.Errorf("expected ErrRefreshTokenRevoked, got: %v", err)
		}
	}
}

/*
TestIntegrationRefreshTokenInvalid verifies that a bogus token is rejected.
*/
func TestIntegrationRefreshTokenInvalid(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour})

	_, err := a.ValidateRefreshToken("this-token-does-not-exist")
	if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenCleanup verifies that expired tokens are cleaned up.
*/
func TestIntegrationRefreshTokenCleanup(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour})
	_ = a.RegisterUser("cleanup@example.com", "password")

	expiredTime := time.Now().Add(-1 * time.Hour)
	_, _ = a.Conn.Exec(context.Background(),
		"INSERT INTO refresh_tokens (token, user_id, expires_at, revoked, created_at) VALUES ($1, $2, $3, false, NOW())",
		"expired-token-abc", "cleanup@example.com", expiredTime,
	)

	_ = a.CleanupExpiredRefreshTokens()

	_, err := a.ValidateRefreshToken("expired-token-abc")
	if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid after cleanup, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenCascadeDeleteUser verifies FK ON DELETE CASCADE for refresh tokens.
*/
func TestIntegrationRefreshTokenCascadeDeleteUser(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour})
	_ = a.RegisterUser("cascade-rt@example.com", "password")

	token, _ := a.GenerateRefreshToken("cascade-rt@example.com")

	_, err := a.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("token should be valid: %v", err)
	}

	_ = a.DeleteUser("cascade-rt@example.com")

	_, err = a.ValidateRefreshToken(token)
	if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid after user deletion, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenChainRotation tests 5 sequential rotations:
all old tokens revoked, only the latest valid.
*/
func TestIntegrationRefreshTokenChainRotation(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour})
	_ = a.RegisterUser("chain@example.com", "password")

	token, _ := a.GenerateRefreshToken("chain@example.com")

	var allOldTokens []string
	for i := 0; i < 5; i++ {
		allOldTokens = append(allOldTokens, token)
		newToken, _, err := a.RotateRefreshToken(token)
		if err != nil {
			t.Fatalf("rotation %d failed: %v", i+1, err)
		}
		token = newToken
	}

	for i, old := range allOldTokens {
		_, err := a.ValidateRefreshToken(old)
		if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
			t.Errorf("old token %d should be revoked, got: %v", i, err)
		}
	}

	userID, err := a.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("latest token should be valid: %v", err)
	}
	if userID != "chain@example.com" {
		t.Errorf("expected 'chain@example.com', got '%s'", userID)
	}
}

/* ======================== Combined: JWT + Refresh Token ======================== */

/*
TestIntegrationJWTRefreshTokenFlow tests the complete authentication flow:
register -> login -> JWT + refresh -> validate -> rotate -> new JWT -> validate.
*/
func TestIntegrationJWTRefreshTokenFlow(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.JWTInit("jwt-refresh-test-secret")
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 7 * 24 * time.Hour})

	_ = a.RegisterUser("fullflow@example.com", "mypassword")

	err := a.LoginUser("fullflow@example.com", "mypassword")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	accessToken, _ := a.GenerateToken("fullflow@example.com", 1*time.Hour)
	refreshToken, _ := a.GenerateRefreshToken("fullflow@example.com")

	claims, err := a.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("failed to validate access token: %v", err)
	}
	if claims.UserID != "fullflow@example.com" {
		t.Errorf("unexpected UserID: %s", claims.UserID)
	}

	newRefresh, userID, err := a.RotateRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	newAccess, _ := a.GenerateToken(userID, 1*time.Hour)

	claims, err = a.ValidateToken(newAccess)
	if err != nil {
		t.Fatalf("failed to validate new access token: %v", err)
	}
	if claims.UserID != "fullflow@example.com" {
		t.Errorf("unexpected UserID: %s", claims.UserID)
	}

	_, err = a.ValidateRefreshToken(refreshToken)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("old refresh token should be revoked, got: %v", err)
	}

	_, err = a.ValidateRefreshToken(newRefresh)
	if err != nil {
		t.Errorf("new refresh token should be valid: %v", err)
	}
}

/* ======================== Combined: Rate Limiter + Login ======================== */

/*
TestIntegrationRateLimitedLogin tests rate limiting on login attempts.
*/
func TestIntegrationRateLimitedLogin(t *testing.T) {
	a := setupTestAuth(t)

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	defer rl.Stop()

	_ = a.RegisterUser("limited@example.com", "correctpass")

	userKey := "limited@example.com"

	for i := 0; i < 3; i++ {
		_ = rl.Allow(userKey)
		_ = a.LoginUser("limited@example.com", "wrongpass")
	}

	err := rl.Allow(userKey)
	if !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Errorf("expected ErrRateLimitExceeded, got: %v", err)
	}

	rl.Reset(userKey)

	err = rl.Allow(userKey)
	if err != nil {
		t.Errorf("expected allowed after reset: %v", err)
	}

	err = a.LoginUser("limited@example.com", "correctpass")
	if err != nil {
		t.Errorf("expected successful login after reset: %v", err)
	}
}

/* ======================== Combined: Rate Limiter + JWT ======================== */

/*
TestIntegrationRateLimitedJWTValidation tests rate limiting on token validation.
*/
func TestIntegrationRateLimitedJWTValidation(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.JWTInit("rate-limit-jwt-secret")

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	defer rl.Stop()

	clientIP := "192.168.1.100"

	for i := 0; i < 5; i++ {
		_ = rl.Allow(clientIP)
		_, _ = a.ValidateToken("bogus-token")
	}

	err := rl.Allow(clientIP)
	if !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Error("expected rate limit exceeded on 6th request")
	}

	err = rl.Allow("10.0.0.1")
	if err != nil {
		t.Errorf("different IP should not be rate limited: %v", err)
	}
}

/* ======================== Combined: Password Change + Revoke Tokens ======================== */

/*
TestIntegrationPasswordChangeRevokesTokens tests: change password -> revoke all -> re-login.
*/
func TestIntegrationPasswordChangeRevokesTokens(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.JWTInit("pass-change-secret")
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 24 * time.Hour})

	_ = a.RegisterUser("secure@example.com", "oldpass")

	rt1, _ := a.GenerateRefreshToken("secure@example.com")
	rt2, _ := a.GenerateRefreshToken("secure@example.com")

	_ = a.ChangePass("secure@example.com", "newpass")
	_ = a.RevokeAllUserRefreshTokens("secure@example.com")

	_, err := a.ValidateRefreshToken(rt1)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected rt1 revoked, got: %v", err)
	}
	_, err = a.ValidateRefreshToken(rt2)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected rt2 revoked, got: %v", err)
	}

	err = a.LoginUser("secure@example.com", "newpass")
	if err != nil {
		t.Errorf("login with new password should succeed: %v", err)
	}

	rtNew, _ := a.GenerateRefreshToken("secure@example.com")
	_, err = a.ValidateRefreshToken(rtNew)
	if err != nil {
		t.Errorf("new refresh token should be valid: %v", err)
	}
}

/* ======================== Combined: Rate Limiter + OTP ======================== */

/*
TestIntegrationRateLimitedOTPVerification tests rate limiting on OTP guessing.
*/
func TestIntegrationRateLimitedOTPVerification(t *testing.T) {
	a := setupTestAuth(t)

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	defer rl.Stop()

	expiry := time.Now().Add(5 * time.Minute)
	_, _ = a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"otprl@example.com", "999888", expiry,
	)

	otpKey := "otp:otprl@example.com"

	for i := 0; i < 5; i++ {
		_ = rl.Allow(otpKey)
		_ = a.VerifyOTP("otprl@example.com", "000000")
	}

	err := rl.Allow(otpKey)
	if !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Errorf("expected rate limit exceeded, got: %v", err)
	}
}

/* ======================== Full Auth Flow ======================== */

/*
TestIntegrationFullAuthFlow tests a realistic full application flow:
register -> RBAC setup -> rate-limited login -> JWT + refresh ->
check permissions -> rotate -> change password -> revoke all -> re-login.
*/
func TestIntegrationFullAuthFlow(t *testing.T) {
	a := setupTestAuth(t)
	_ = a.JWTInit("full-flow-secret")
	_ = a.RefreshTokenInit(auth.RefreshTokenConfig{Expiry: 7 * 24 * time.Hour})

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 10,
		Window:      time.Minute,
	})
	defer rl.Stop()

	_ = a.CreateSpace("dashboard", 1)
	_ = a.CreateRole("viewer")
	_ = a.CreateRole("admin")

	err := a.RegisterUser("fulltest@example.com", "MyS3cureP@ss")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_ = a.CreatePermissions("fulltest@example.com", "dashboard", "viewer")

	_ = rl.Allow("fulltest@example.com")
	err = a.LoginUser("fulltest@example.com", "MyS3cureP@ss")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	jwt, _ := a.GenerateToken("fulltest@example.com")
	rt, _ := a.GenerateRefreshToken("fulltest@example.com")

	claims, _ := a.LoginJWT(jwt)

	err = a.CheckPermissions(claims.UserID, "dashboard", "viewer")
	if err != nil {
		t.Errorf("user should have viewer permission: %v", err)
	}

	err = a.CheckPermissions(claims.UserID, "dashboard", "admin")
	if err == nil {
		t.Error("user should NOT have admin permission")
	}

	newRT, userID, err := a.RotateRefreshToken(rt)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if userID != "fulltest@example.com" {
		t.Errorf("unexpected user: %s", userID)
	}

	_ = a.ChangePass("fulltest@example.com", "NewP@ssw0rd!")
	_ = a.RevokeAllUserRefreshTokens("fulltest@example.com")

	_, err = a.ValidateRefreshToken(newRT)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected revoked, got: %v", err)
	}

	err = a.LoginUser("fulltest@example.com", "NewP@ssw0rd!")
	if err != nil {
		t.Fatalf("re-login failed: %v", err)
	}

	newJWT, _ := a.GenerateToken("fulltest@example.com")
	finalClaims, err := a.ValidateToken(newJWT)
	if err != nil {
		t.Fatalf("failed to validate new JWT: %v", err)
	}
	if finalClaims.UserID != "fulltest@example.com" {
		t.Errorf("unexpected final UserID: %s", finalClaims.UserID)
	}

	newFinalRT, _ := a.GenerateRefreshToken("fulltest@example.com")
	_, err = a.ValidateRefreshToken(newFinalRT)
	if err != nil {
		t.Errorf("final refresh token should be valid: %v", err)
	}
}
