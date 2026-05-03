package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
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
func (rl *RateLimiter) Allow(ctx context.Context, key string) error {
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
func (rl *RateLimiter) Remaining(ctx context.Context, key string) (int, error) {
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
		return 0, nil
	}
	return remaining, nil
}

/*
Reset clears the rate limit state for a specific key.
Useful when a user successfully authenticates and you want to clear failed-attempt counters.
*/
func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
	return nil
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

/* cleanup periodically evicts expired timestamps to prevent memory leaks. */
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanPass()
		case <-rl.done:
			return
		}
	}
}

func (rl *RateLimiter) cleanPass() {
	rl.mu.Lock()
	keys := make([]string, 0, len(rl.buckets))
	for k := range rl.buckets {
		keys = append(keys, k)
	}
	rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.config.Window)
	for _, key := range keys {
		rl.mu.Lock()
		if timestamps, ok := rl.buckets[key]; ok {
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
	}
}

/*
RedisRateLimiter implements a Redis-backed sliding-window rate limiter.
It relies on a pre-loaded Lua script managed by the Auth instance.
*/
type RedisRateLimiter struct {
	client    *redis.Client
	config    RateLimiterConfig
	scriptSHA string
}

/*
NewRedisRateLimiter creates and returns a new RedisRateLimiter.
It requires an initialized Auth instance to use its Redis client and script SHA.
*/
func (a *Auth) NewRedisRateLimiter(cfg RateLimiterConfig) (*RedisRateLimiter, error) {
	if cfg.MaxRequests <= 0 || cfg.Window <= 0 {
		return nil, ErrInvalidInput
	}
	if a.redisClient == nil || a.rateLimitSHA == "" {
		return nil, ErrRedisUnavailable
	}

	return &RedisRateLimiter{
		client:    a.redisClient,
		config:    cfg,
		scriptSHA: a.rateLimitSHA,
	}, nil
}

func (rl *RedisRateLimiter) Allow(ctx context.Context, key string) error {
	if key == "" {
		return ErrEmptyInput
	}

	now := time.Now()
	windowMs := rl.config.Window.Milliseconds()
	nowMs := now.UnixMilli()
	member := now.UnixNano()

	res, err := rl.client.EvalSha(ctx, rl.scriptSHA, []string{"ratelimit:" + key}, windowMs, rl.config.MaxRequests, nowMs, member).Result()
	if err != nil {
		return ErrRateLimitBackendDown
	}

	if allowed, ok := res.(int64); ok && allowed == 1 {
		return nil
	}
	return ErrRateLimitExceeded
}

func (rl *RedisRateLimiter) Remaining(ctx context.Context, key string) (int, error) {
	if key == "" {
		return 0, ErrEmptyInput
	}

	now := time.Now()
	cutoffMs := now.UnixMilli() - rl.config.Window.Milliseconds()

	pipe := rl.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, "ratelimit:"+key, "0", fmt.Sprintf("%d", cutoffMs))
	countCmd := pipe.ZCard(ctx, "ratelimit:"+key)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, ErrRateLimitBackendDown
	}

	count := countCmd.Val()
	remaining := rl.config.MaxRequests - int(count)
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

func (rl *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return ErrEmptyInput
	}
	err := rl.client.Del(ctx, "ratelimit:"+key).Err()
	if err != nil {
		return ErrRateLimitBackendDown
	}
	return nil
}
