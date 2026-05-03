package auth

import (
	"context"
	"fmt"
	"log"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
)

/* checkTables systematically creates all required tables if they do not exist. */
func (a *Auth) checkTables(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS spaces (
			spaceName TEXT PRIMARY KEY, 
			authority INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS users (
			user_id TEXT PRIMARY KEY, 
			password_hash TEXT NOT NULL, 
			salt TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS roles (
			role TEXT PRIMARY KEY
		);
		CREATE TABLE IF NOT EXISTS permissions (
			user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, 
			spaceName TEXT NOT NULL REFERENCES spaces(spaceName) ON DELETE CASCADE, 
			role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE, 
			PRIMARY KEY (user_id, spaceName, role)
		);
		CREATE TABLE IF NOT EXISTS otps (
			email TEXT PRIMARY KEY, 
			code TEXT NOT NULL, 
			expires_at TIMESTAMP NOT NULL
		);
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY, 
			user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, 
			expires_at TIMESTAMP NOT NULL, 
			revoked BOOLEAN NOT NULL DEFAULT false, 
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
	`
	_, err := a.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to initialize database schema: %w", err)
	}
	return nil
}

/* dbConnect establishes a connection pool to the PostgreSQL database. */
func dbConnect(ctx context.Context, details *dbDetails) (*pgxpool.Pool, error) {
	/*
		The password may contain multiple special characters,
		therefore it is primordial to use, url.URL here.
	*/
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(details.username, details.password),
		Host:   fmt.Sprintf("%s:%d", details.host, details.port),
		Path:   details.databaseName,
	}

	urlStr := u.String()

	pool, err := pgxpool.New(ctx, urlStr)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create Connection pool: %w\nPlease configure Postgres correctly",
			err,
		)
	}

	if err := pool.QueryRow(ctx, "SELECT 1").Scan(new(int)); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to Connect to Postgres: %w", err)
	}

	log.Println("DB Connection pool established")

	return pool, nil
}
