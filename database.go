package auth

import (
	"context"
	"fmt"
	"log"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
)

/*
Creates the needed schema from scratch for prompted table.
Expects table to not be present at all.
*/
func (a *Auth) create_spaces(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS spaces (
	space_name TEXT PRIMARY KEY,
	authority INTEGER NOT NULL
	 )`
	_, err := a.conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating spaces table: %w", err)
	}
	log.Println("Spaces table created successfully (or already exists).")
	return nil
}

func (a *Auth) create_users(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY,
	password_hash TEXT NOT NULL,
	 salt TEXT NOT NULL
	)`
	_, err := a.conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating users table: %w", err)
	}
	log.Println("Users table created successfully (or already exists).")
	return nil
}

func (a *Auth) create_roles(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS roles (
	role TEXT PRIMARY KEY
	)`
	_, err := a.conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating roles table: %w", err)
	}
	log.Println("Roles table created successfully (or already exists).")
	return nil
}

func (a *Auth) create_permissions(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS permissions (
	user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	space_name TEXT NOT NULL REFERENCES spaces(space_name) ON DELETE CASCADE,
	role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
	PRIMARY KEY (user_id, space_name, role)
	)`
	_, err := a.conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating permissions table: %w", err)
	}
	log.Println("Permissions table created successfully (or already exists).")
	return nil
}

func (a *Auth) create_otps(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS otps (
		email TEXT PRIMARY KEY,
		code TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL
	)`
	_, err := a.conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating otps table: %w", err)
	}
	log.Println("OTPs table created successfully (or already exists).")
	return nil
}

/*
These functions now return 'error' instead of calling log.Fatal()
*/
func (a *Auth) check_spaces(ctx context.Context) error {
	query := `
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'spaces'
            ORDER BY ordinal_position;
      `
	rows, err := a.conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query spaces schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]struct {
		dataType   string
		isNullable string
	}{}
	for rows.Next() {
		var name, dataType, isNullable string
		if err := rows.Scan(&name, &dataType, &isNullable); err != nil {
			return fmt.Errorf("failed to scan spaces schema: %w", err)
		}
		columns[name] = struct {
			dataType   string
			isNullable string
		}{dataType, isNullable}
	}

	expected := map[string]string{
		"space_name": "text",
		"authority":  "integer",
	}

	for col, typ := range expected {
		if c, ok := columns[col]; !ok || c.dataType != typ {
			return fmt.Errorf("spaces table schema mismatch for column '%s': expected %s, got %s", col, typ, c.dataType)
		}
	}

	log.Println("Spaces table schema is correct.")
	return nil
}

func (a *Auth) check_users(ctx context.Context) error {
	query := `
	SELECT column_name, data_type
	FROM information_schema.columns
	WHERE table_name = 'users'
	ORDER BY ordinal_position;
      `
	rows, err := a.conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query users schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			return fmt.Errorf("failed to scan users schema: %w", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"user_id":       "text",
		"password_hash": "text",
		"salt":          "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			return fmt.Errorf("users table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	log.Println("Users table schema is correct.")
	return nil
}

func (a *Auth) check_roles(ctx context.Context) error {
	query := `
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'roles'
            ORDER BY ordinal_position;
	      `
	rows, err := a.conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query roles schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			return fmt.Errorf("failed to scan roles schema: %w", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"role": "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			return fmt.Errorf("roles table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	log.Println("Roles table schema is correct.")
	return nil
}

func (a *Auth) check_permissions(ctx context.Context) error {
	query := `
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'permissions'
            ORDER BY ordinal_position;
      `
	rows, err := a.conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query permissions schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			return fmt.Errorf("failed to scan permissions schema: %w", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"user_id":    "text",
		"space_name": "text",
		"role":       "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			return fmt.Errorf("permissions table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	log.Println("Permissions table schema is correct.")
	return nil
}

func (a *Auth) check_otps(ctx context.Context) error {
	query := `
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'otps'
            ORDER BY ordinal_position;
      `
	rows, err := a.conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query otps schema: %w", err)
	}
	defer rows.Close()

	/* We'll map the columns we find to verify them */
	columns := map[string]struct {
		dataType   string
		isNullable string
	}{}
	for rows.Next() {
		var name, dataType, isNullable string
		if err := rows.Scan(&name, &dataType, &isNullable); err != nil {
			return fmt.Errorf("failed to scan otps schema: %w", err)
		}
		columns[name] = struct {
			dataType   string
			isNullable string
		}{dataType, isNullable}
	}

	/* Define what we expect
	Note: In Postgres, TIMESTAMP WITHOUT TIME ZONE usually shows as 'timestamp without time zone'
	Depending on your specific Postgres setup, it might just be 'timestamp'.
	The library seems to check simple types. Let's assume standard text/timestamp. */
	expected := map[string]string{
		"email":      "text",
		"code":       "text",
		"expires_at": "timestamp without time zone", // standard postgres timestamp type
	}

	for col, typ := range expected {
		if c, ok := columns[col]; !ok || c.dataType != typ {
			/* If validation fails, we return an error */
			return fmt.Errorf("otps table schema mismatch for column '%s': expected %s, got %s", col, typ, c.dataType)
		}
	}

	log.Println("OTPs table schema is correct.")
	return nil
}

/*
Checks if the table exists or not and returns the output in boolean
*/
func (a *Auth) table_exists(ctx context.Context, table string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables  
			WHERE table_schema = 'public'
			AND table_name = $1
	)`
	err := a.conn.QueryRow(ctx, query, table).Scan(&exists)
	return exists, err
}

/*
Systematically checks all tables and returns an error if any check fails.
*/
func (a *Auth) check_tables(ctx context.Context) error {
	var check bool = false
	var err error = nil

	check, err = a.table_exists(ctx, "spaces")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.check_spaces(ctx); err != nil {
				return err
			}
		} else {
			if err = a.create_spaces(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.table_exists(ctx, "users")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.check_users(ctx); err != nil {
				return err
			}
		} else {
			if err = a.create_users(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.table_exists(ctx, "roles")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.check_roles(ctx); err != nil {
				return err
			}
		} else {
			if err = a.create_roles(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.table_exists(ctx, "permissions")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.check_permissions(ctx); err != nil {
				return err
			}
		} else {
			if err = a.create_permissions(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.table_exists(ctx, "otps")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.check_otps(ctx); err != nil {
				return err
			}
		} else {
			if err = a.create_otps(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

/*
Wrapper function around jackc/pgx/v5 pgx.Conn().
Returns a *pgx.Conn structure.
*/

func db_connect(ctx context.Context, details *db_details) (*pgxpool.Pool, error) {
	/*
		The password may contain multiple special characters,
		therefore it is primodial to use, url.URL here.
	*/
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(details.username, details.password),
		Host:   fmt.Sprintf("localhost:%d", details.port),
		Path:   details.database_name,
	}

	urlStr := u.String()

	pool, err := pgxpool.New(ctx, urlStr)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create connection pool: %w\nPlease configure Postgres correctly",
			err,
		)
	}

	if err := pool.QueryRow(ctx, "SELECT 1").Scan(new(int)); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to Postgres: %w", err)
	}

	log.Println("DB connection pool established")

	return pool, nil
}
