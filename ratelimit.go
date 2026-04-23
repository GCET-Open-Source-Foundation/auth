package auth

import (
	"sync"
	"time"
)

/*
RateLimiterConfig holds the configuration for the sliding-window rate limiter.
MaxRequests is the maximum number of requests allowed within the Window duration.
*/
type RateLimiterConfig struct {
	MaxRequests int
	Window      time.Duration
}

/*
RateLimiter implements an in-memory, per-key sliding-window rate limiter.
It is safe for concurrent use. Keys are typically user IDs, IP addresses, or API keys.
*/
type RateLimiter struct {
	mu       sync.Mutex
	config   RateLimiterConfig
	buckets  map[string][]time.Time
	stopOnce sync.Once
	done     chan struct{}
}

/*
NewRateLimiter creates and returns a new RateLimiter with the given config.
It starts a background goroutine that periodically evicts stale entries
to prevent unbounded memory growth.
*/
func NewRateLimiter(cfg RateLimiterConfig) (*RateLimiter, error) {
	if cfg.MaxRequests <= 0 {
		return nil, ErrInvalidInput
	}
	if cfg.Window <= 0 {
		return nil, ErrInvalidInput
	}

	rl := &RateLimiter{
		config:  cfg,
		buckets: make(map[string][]time.Time),
		done:    make(chan struct{}),
	}

	go rl.cleanup()

	return rl, nil
}

/*
Allow checks whether a request identified by key should be allowed.
It records the current timestamp and returns nil if the request is within
the configured limit, or ErrRateLimitExceeded otherwise.
*/
func (rl *RateLimiter) Allow(key string) error {
	if key == "" {
		return ErrEmptyInput
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.config.Window)

	/* Prune expired timestamps for this key */
	timestamps := rl.buckets[key]
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	if len(valid) >= rl.config.MaxRequests {
		rl.buckets[key] = valid
		return ErrRateLimitExceeded
	}

	rl.buckets[key] = append(valid, now)
	return nil
}

/*
Remaining returns how many requests the key has left in the current window.
*/
func (rl *RateLimiter) Remaining(key string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.config.Window)

	timestamps := rl.buckets[key]
	count := 0
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			count++
		}
	}

	remaining := rl.config.MaxRequests - count
	if remaining < 0 {
		return 0
	}
	return remaining
}

/*
Reset clears the rate limit state for a specific key.
Useful when a user successfully authenticates and you want to clear failed-attempt counters.
*/
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

/*
Stop shuts down the background cleanup goroutine.
Call this when the RateLimiter is no longer needed.
*/
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.done)
	})
}

/*
cleanup runs in the background and periodically removes keys whose
timestamps have all expired. This prevents memory leaks from keys
that made requests long ago but never returned.
*/
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			cutoff := now.Add(-rl.config.Window)
			for key, timestamps := range rl.buckets {
				valid := timestamps[:0]
				for _, ts := range timestamps {
					if ts.After(cutoff) {
						valid = append(valid, ts)
					}
				}
				if len(valid) == 0 {
					delete(rl.buckets, key)
				} else {
					rl.buckets[key] = valid
				}
			}
			rl.mu.Unlock()

		case <-rl.done:
			return
		}
	}
}
