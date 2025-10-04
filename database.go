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

If present and schema differs.

You have to erase the table manually.
You are on your own.
*/
func create_spaces(pool *pgxpool.Pool) {
	query := `
        CREATE TABLE IF NOT EXISTS spaces (
            space_name TEXT PRIMARY KEY,
            authority INTEGER NOT NULL
        )`
	_, err := pool.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("Error creating spaces table:", err)
		return
	}
	fmt.Println("Spaces table created successfully (or already exists).")
}

func create_users(pool *pgxpool.Pool) {
	query := `
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )`
	_, err := pool.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("Error creating users table:", err)
		return
	}
	fmt.Println("Users table created successfully (or already exists).")
}

func create_roles(pool *pgxpool.Pool) {
	query := `
        CREATE TABLE IF NOT EXISTS roles (
            role TEXT PRIMARY KEY
        )`
	_, err := pool.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("Error creating roles table:", err)
		return
	}
	fmt.Println("Roles table created successfully (or already exists).")
}

func create_permissions(pool *pgxpool.Pool) {
	query := `
        CREATE TABLE IF NOT EXISTS permissions (
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            space_name TEXT NOT NULL REFERENCES spaces(space_name) ON DELETE CASCADE,
            role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
            PRIMARY KEY (user_id, space_name, role)
        )`
	_, err := pool.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("Error creating permissions table:", err)
		return
	}
	fmt.Println("Permissions table created successfully (or already exists).")
}

/*
These should only be called if we already have prompted table available...
If not available use the create_<prompt> func
Unless the errors we get will be unclear.
*/
func check_spaces(pool *pgxpool.Pool) {
	query := `
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'spaces'
        ORDER BY ordinal_position;
    `
	rows, err := pool.Query(context.Background(), query)
	if err != nil {
		log.Fatal("Failed to query spaces schema:", err)
	}
	defer rows.Close()

	columns := map[string]struct {
		dataType   string
		isNullable string
	}{}
	for rows.Next() {
		var name, dataType, isNullable string
		if err := rows.Scan(&name, &dataType, &isNullable); err != nil {
			log.Fatal("Failed to scan spaces schema:", err)
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
			log.Fatalf("Spaces table schema mismatch for column '%s': expected %s, got %s", col, typ, c.dataType)
		}
	}

	fmt.Println("Spaces table schema is correct.")
}

func check_users(pool *pgxpool.Pool) {
	query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'users'
        ORDER BY ordinal_position;
    `
	rows, err := pool.Query(context.Background(), query)
	if err != nil {
		log.Fatal("Failed to query users schema:", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			log.Fatal("Failed to scan users schema:", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"user_id":       "text",
		"password_hash": "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			log.Fatalf("Users table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	fmt.Println("Users table schema is correct.")
}

func check_roles(pool *pgxpool.Pool) {
	query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'roles'
        ORDER BY ordinal_position;
    `
	rows, err := pool.Query(context.Background(), query)
	if err != nil {
		log.Fatal("Failed to query roles schema:", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			log.Fatal("Failed to scan roles schema:", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"role": "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			log.Fatalf("Roles table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	fmt.Println("Roles table schema is correct.")
}

func check_permissions(pool *pgxpool.Pool) {
	query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'permissions'
        ORDER BY ordinal_position;
    `
	rows, err := pool.Query(context.Background(), query)
	if err != nil {
		log.Fatal("Failed to query permissions schema:", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			log.Fatal("Failed to scan permissions schema:", err)
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
			log.Fatalf("Permissions table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	fmt.Println("Permissions table schema is correct.")
}

/*
Checks if the table exists or not and returns the output in boolean
*/
func table_exists(pool *pgxpool.Pool, table string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables 
			WHERE table_schema = 'public'
			AND table_name = $1
	)`
	/*
		Here exists stores the value that SELECT EXISTS returns conveniently
	*/
	err := pool.QueryRow(context.Background(), query, table).Scan(&exists)
	return exists, err
}

/*
Systematically checks these tables
1. spaces
2. users
3. roles
4. permissions
Creates the tables that doesn't exist yet.
*/
func check_tables(pool *pgxpool.Pool) {
	/*
		Probably not the smartest code I wrote,
		but something good to begin with, modular and easy to read

		We separate all the func calls for a reason, until we get an
		insanely good method to handle different schemas let's just stick
		to human readable code folks, we ain't machines ;)
	*/

	var check bool = false
	var err error = nil

	check, err = table_exists(pool, "spaces")
	if err != nil {
		fmt.Println(err)
		return
	} else {
		if check {
			check_spaces(pool)
		} else {
			create_spaces(pool)
		}
	}

	check, err = table_exists(pool, "users")
	if err != nil {
		fmt.Println(err)
		return
	} else {
		if check {
			check_users(pool)
		} else {
			create_users(pool)
		}
	}

	check, err = table_exists(pool, "roles")
	if err != nil {
		fmt.Println(err)
		return
	} else {
		if check {
			check_roles(pool)
		} else {
			create_roles(pool)
		}
	}

	check, err = table_exists(pool, "permissions")
	if err != nil {
		fmt.Println(err)
		return
	} else {
		if check {
			check_permissions(pool)
		} else {
			create_permissions(pool)
		}
	}
}

/*
Wrapper function around jackc/pgx/v5 pgx.Conn().
Returns a *pgx.Conn structure.
*/

func db_connect(details *db_details) (*pgxpool.Pool, error) {
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

	pool, err := pgxpool.New(context.Background(), urlStr)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create connection pool: %w\nPlease configure Postgres correctly",
			err,
		)
	}

	// Validate connection
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(new(int)); err != nil {
		return nil, fmt.Errorf("failed to connect to Postgres: %w", err)
	}

	fmt.Println("DB connection pool established")
	fmt.Println("Checking needed tables and schemas")
	check_tables(pool)

	return pool, nil
}
