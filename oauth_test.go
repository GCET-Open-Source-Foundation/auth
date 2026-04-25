package auth

import (
	"strings"
	"testing"
)

func TestInitGoogleOAuth(t *testing.T) {
	auth := &Auth{}

	// Test missing inputs
	err := auth.InitGoogleOAuth("", "secret", "http://localhost/callback")
	if err != ErrEmptyInput {
		t.Errorf("expected ErrEmptyInput for missing clientID, got %v", err)
	}

	err = auth.InitGoogleOAuth("client", "", "http://localhost/callback")
	if err != ErrEmptyInput {
		t.Errorf("expected ErrEmptyInput for missing clientSecret, got %v", err)
	}

	err = auth.InitGoogleOAuth("client", "secret", "")
	if err != ErrEmptyInput {
		t.Errorf("expected ErrEmptyInput for missing redirectURL, got %v", err)
	}

	// Test successful initialization
	err = auth.InitGoogleOAuth("my-client-id", "my-client-secret", "http://localhost/callback")
	if err != nil {
		t.Errorf("expected nil error for valid inputs, got %v", err)
	}

	if auth.oauthConfig == nil {
		t.Fatal("expected oauthConfig to be initialized")
	}

	if auth.oauthConfig.ClientID != "my-client-id" {
		t.Errorf("expected ClientID to be 'my-client-id', got %s", auth.oauthConfig.ClientID)
	}
}

func TestGetGoogleLoginURL(t *testing.T) {
	auth := &Auth{}

	// Test uninitialized state
	_, err := auth.GetGoogleLoginURL("random-state")
	if err != ErrOAuthNotInit {
		t.Errorf("expected ErrOAuthNotInit when uninitialized, got %v", err)
	}

	// Initialize and test URL generation
	err = auth.InitGoogleOAuth("my-client-id", "my-client-secret", "http://localhost/callback")
	if err != nil {
		t.Fatalf("failed to init oauth: %v", err)
	}

	url, err := auth.GetGoogleLoginURL("random-state")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if !strings.Contains(url, "client_id=my-client-id") {
		t.Errorf("expected url to contain client_id, got %s", url)
	}
	if !strings.Contains(url, "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback") {
		t.Errorf("expected url to contain encoded redirect_uri, got %s", url)
	}
	if !strings.Contains(url, "state=random-state") {
		t.Errorf("expected url to contain state, got %s", url)
	}
}
