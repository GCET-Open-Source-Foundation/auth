package auth

import (
	"context"
	"fmt"
	"net/mail"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

// dbDetails holds the configuration required to connect to the PostgreSQL database.
type dbDetails struct {
	port         uint16
	username     string
	password     string
	databaseName string
	host         string
}

const rateLimitScript = `
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local clearBefore = now - window

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, clearBefore)
local count = redis.call('ZCARD', KEYS[1])

if count >= limit then
    return 0
end

redis.call('ZADD', KEYS[1], now, now)
redis.call('PEXPIRE', KEYS[1], window)
return 1
`

// Auth manages the internal state of the library, including database connections,
// cryptographic parameters, and caching clients. It is safe for concurrent use.
type Auth struct {
	Conn               *pgxpool.Pool
	argonParams        argonParameters
	pepper             string
	pepperOnce         sync.Once
	jwtSecret          []byte
	jwtExpiry          time.Duration
	otpExpiry          time.Duration
	otpLength          int
	jwtOnce            sync.Once
	smtpEmail          string
	smtpPassword       string
	smtpHost           string
	smtpPort           string
	smtp_once          sync.Once
	refreshTokenExpiry time.Duration
	refreshTokenLength int
	ctx                context.Context
	cancel             context.CancelFunc
	oauthConfig        *oauth2.Config
	oauthOnce          sync.Once
	redisClient        *redis.Client
	requestGroup       singleflight.Group
	rateLimitSHA       string
}

/*
Init configures the dbDetails, Connects to the database,
checks schemas, and returns a fully initialized Auth struct.
Init takes context info, db username, db password, db name, host url (e.g. localhost)
*/
func Init(ctx context.Context, port uint16, dbUser, dbPass, dbName, host string) (*Auth, error) {
	if dbUser == "" || dbName == "" || host == "" {
		return nil, ErrEmptyInput
	}
	dbTemp := dbDetails{
		port:         port,
		username:     dbUser,
		password:     dbPass,
		databaseName: dbName,
		host:         host,
	}

	pool, err := dbConnect(ctx, &dbTemp)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	if pool == nil {
		return nil, ErrDatabaseUnavailable
	}

	/* Create a context for the Auth library's lifecycle */
	/* context.WithCancel returns a context and a function to cancel it */
	libCtx, libCancel := context.WithCancel(ctx)

	/* No errors in init */
	temp := &Auth{
		Conn:        pool,
		argonParams: globalDefaultArgon,
		jwtExpiry:   24 * time.Hour,
		otpExpiry:   5 * time.Minute,
		otpLength:   6,
		ctx:         libCtx,
		cancel:      libCancel,
	}

	if err := temp.checkTables(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	/* start the background OTP cleaner */
	temp.startOTPCleanup()

	return temp, nil
}

/*
SMTPInit sets the SMTP server details and credentials.
This must be called once at startup if you intend to use OTP features.
It stores the credentials in memory only.
*/
func (a *Auth) SMTPInit(email, password, host, port string) error {
	if email == "" || password == "" || host == "" || port == "" {
		return ErrEmptyInput
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return ErrInvalidEmail
	}

	a.smtp_once.Do(func() {
		a.smtpEmail = email
		a.smtpPassword = password
		a.smtpHost = host
		a.smtpPort = port
	})
	return nil
}

/*
RedisInit initializes the Redis client for caching and rate limiting.
It verifies the connection by sending a Ping.
*/
func (a *Auth) RedisInit(addr, password string, db int) error {
	if addr == "" {
		return ErrEmptyInput
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	if err := client.Ping(a.ctx).Err(); err != nil {
		client.Close()
		return fmt.Errorf("%w: failed to connect to redis: %v", ErrRedisUnavailable, err)
	}

	sha, err := client.ScriptLoad(a.ctx, rateLimitScript).Result()
	if err != nil {
		client.Close()
		return fmt.Errorf("failed to load rate limit lua script: %w", err)
	}

	a.redisClient = client
	a.rateLimitSHA = sha
	return nil
}

/*
Close performs a graceful shutdown of the Auth library.
It stops background tasks, closes database Connections, and wipes sensitive data from memory.
*/
func (a *Auth) Close() {
	/* 1. Stop background routines (OTP cleaner) */
	if a.cancel != nil {
		a.cancel() /* This sends the signal to otp.go to stop!*/
	}

	/* 2. Close Database Connection */
	if a.Conn != nil {
		a.Conn.Close()
		a.Conn = nil
	}

	/* 3. Wipe Sensitive Memory (Security Best Practice) */
	/* Overwrite JWT secret with zeros */
	if len(a.jwtSecret) > 0 {
		for i := range a.jwtSecret {
			a.jwtSecret[i] = 0
		}
		a.jwtSecret = nil
	}

	/* Clear string secrets (Go strings are immutable, but we can unassign them) */
	/* Note: This is best-effort since GC handles actual string memory */
	a.smtpPassword = ""
	a.pepper = ""
	a.oauthConfig = nil

	/* 4. Close Redis Connection */
	if a.redisClient != nil {
		a.redisClient.Close()
		a.redisClient = nil
	}
}
