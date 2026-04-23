package tests

import (
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
TestNewRateLimiter verifies that a rate limiter is created with valid config.
*/
func TestNewRateLimiter(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rl.Stop()

	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

/*
TestNewRateLimiterInvalidConfig checks that invalid configs are rejected.
*/
func TestNewRateLimiterInvalidConfig(t *testing.T) {
	_, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 0,
		Window:      time.Minute,
	})
	if err == nil {
		t.Error("expected error for MaxRequests=0")
	}

	_, err = auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: -1,
		Window:      time.Minute,
	})
	if err == nil {
		t.Error("expected error for negative MaxRequests")
	}

	_, err = auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      0,
	})
	if err == nil {
		t.Error("expected error for Window=0")
	}

	_, err = auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      -time.Second,
	})
	if err == nil {
		t.Error("expected error for negative Window")
	}
}

/*
TestRateLimiterAllow checks that requests within the limit are allowed.
*/
func TestRateLimiterAllow(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if err := rl.Allow("user1"); err != nil {
			t.Errorf("request %d should be allowed, got: %v", i+1, err)
		}
	}
}

/*
TestRateLimiterExceeded checks that exceeding the limit returns an error.
*/
func TestRateLimiterExceeded(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		_ = rl.Allow("user1")
	}

	err := rl.Allow("user1")
	if err == nil {
		t.Error("expected rate limit exceeded error")
	}
}

/*
TestRateLimiterEmptyKey checks that empty keys are rejected.
*/
func TestRateLimiterEmptyKey(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	defer rl.Stop()

	if err := rl.Allow(""); err == nil {
		t.Error("expected error for empty key")
	}
}

/*
TestRateLimiterIsolation checks that different keys have independent limits.
*/
func TestRateLimiterIsolation(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	defer rl.Stop()

	_ = rl.Allow("user1")
	_ = rl.Allow("user1")

	if err := rl.Allow("user2"); err != nil {
		t.Errorf("user2 should not be rate limited, got: %v", err)
	}
}

/*
TestRateLimiterWindowExpiry verifies that old timestamps expire and free up capacity.
*/
func TestRateLimiterWindowExpiry(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      50 * time.Millisecond,
	})
	defer rl.Stop()

	_ = rl.Allow("user1")
	_ = rl.Allow("user1")

	if err := rl.Allow("user1"); err == nil {
		t.Error("expected rate limit exceeded")
	}

	time.Sleep(60 * time.Millisecond)

	if err := rl.Allow("user1"); err != nil {
		t.Errorf("expected request to be allowed after window expiry, got: %v", err)
	}
}

/*
TestRateLimiterRemaining checks the remaining count logic.
*/
func TestRateLimiterRemaining(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	defer rl.Stop()

	if r := rl.Remaining("user1"); r != 5 {
		t.Errorf("expected 5 remaining, got %d", r)
	}

	_ = rl.Allow("user1")
	_ = rl.Allow("user1")

	if r := rl.Remaining("user1"); r != 3 {
		t.Errorf("expected 3 remaining, got %d", r)
	}
}

/*
TestRateLimiterReset verifies that resetting a key clears its history.
*/
func TestRateLimiterReset(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	defer rl.Stop()

	_ = rl.Allow("user1")
	_ = rl.Allow("user1")

	if err := rl.Allow("user1"); err == nil {
		t.Error("expected rate limit exceeded before reset")
	}

	rl.Reset("user1")

	if err := rl.Allow("user1"); err != nil {
		t.Errorf("expected request to be allowed after reset, got: %v", err)
	}
}

/*
TestRateLimiterStop verifies that the stop function can be called multiple times safely.
*/
func TestRateLimiterStop(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})

	rl.Stop()
	rl.Stop()
}

/*
TestRateLimiterConcurrent tests that the rate limiter is safe
under concurrent access from multiple goroutines.
*/
func TestRateLimiterConcurrent(t *testing.T) {
	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 100,
		Window:      time.Minute,
	})
	defer rl.Stop()

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				_ = rl.Allow("concurrent-key")
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}

	remaining := rl.Remaining("concurrent-key")
	if remaining != 0 {
		t.Errorf("expected 0 remaining after 500 requests (limit 100), got %d", remaining)
	}
}
