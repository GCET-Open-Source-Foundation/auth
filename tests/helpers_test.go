package tests

import (
	"context"
	"fmt"
	"testing"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

/*
Test database connection constants.
These point to a local PostgreSQL instance used exclusively for testing.
*/
const (
	testDBPort    = 5432
	testDBUser    = "testuser"
	testDBPass    = "testpass"
	testDBName    = "testauth"
	testDBHost    = "127.0.0.1"
	testRedisHost = "127.0.0.1:6379"
	testRedisPass = ""
)

/*
setupTestAuth initialises a fully working Auth instance backed by a real
PostgreSQL database. Every call drops and recreates all library tables so
each test starts with a clean slate.

It registers a t.Cleanup callback that closes the Auth instance when the
test finishes.
*/
func setupTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	ctx := context.Background()

	/*
		Drop all tables before Init so we start clean every time.
		This works around a known Postgres case-sensitivity quirk: the
		library's CREATE TABLE uses camelCase column names (e.g. spaceName)
		but Postgres stores them lowercase. The schema checker then fails
		on subsequent Init() calls because it expects the camelCase variant.
	*/
	preCleanDB(t, ctx)

	a, err := auth.Init(ctx, testDBPort, testDBUser, testDBPass, testDBName, testDBHost)
	if err != nil {
		t.Fatalf("failed to initialise Auth: %v", err)
	}

	t.Cleanup(func() {
		a.Close()
	})

	return a
}

/*
preCleanDB connects directly to the test database and drops every table
the library might have created, giving Init() a blank slate.
*/
func preCleanDB(t *testing.T, ctx context.Context) {
	t.Helper()

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		testDBUser, testDBPass, testDBHost, testDBPort, testDBName)
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("preCleanDB: failed to connect: %v", err)
	}
	defer pool.Close()

	pool.Exec(ctx, "DROP TABLE IF EXISTS permissions CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS refresh_tokens CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS otps CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS users CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS roles CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS spaces CASCADE")
}

/*
setupRedis connects the given Auth instance to a test Redis server.
If Redis is not reachable, it returns false, allowing the caller to t.Skip().
*/
func setupRedis(t *testing.T, a *auth.Auth) bool {
	t.Helper()
	err := a.RedisInit(testRedisHost, testRedisPass, 0)
	if err != nil {
		return false
	}
	return true
}
