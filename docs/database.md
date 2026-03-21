#**database.go**

database.go is the part of the auth library that connects to Postgres.

it does three main jobs:

Schema creation: If this is a new database, it creates tables for spaces, users, roles, permissions, and OTP.

Schema validation: If the tables already exist, it checks information_schema to verify if the columns and data types match.

Connection management: It builds a Postgres connection and initializes a pgx connection pool that the rest of the library uses.

```go
func (a *Auth) create_spaces(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS spaces (
            space_name TEXT PRIMARY KEY,
            authority INTEGER NOT NULL
        )`
    _, err := a.conn.Exec(ctx, query)
    ...
}
```
The spaces table defines “spaces” in your application, each identified by a space_name and an integer authority.(Check spaces.MD for further clarity)

```go
func (a *Auth) create_users(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )`
    _, err := a.conn.Exec(ctx, query)
    ...
}
```
The users table stores each user’s unique ID, the Argon2 hash of their password, and the salt that was used to compute that hash.
```go
func (a *Auth) create_roles(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS roles (
            role TEXT PRIMARY KEY
        )`
    _, err := a.conn.Exec(ctx, query)
    ...
}
```
The roles table defines the set of roles that can be granted.This makes sure that only known roles are used in permissions.

```go
func (a *Auth) create_permissions(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS permissions (
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            space_name TEXT NOT NULL REFERENCES spaces(space_name) ON DELETE CASCADE,
            role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
            PRIMARY KEY (user_id, space_name, role)
        )`
    _, err := a.conn.Exec(ctx, query)
    ...
}
```
The permissions table basically assigns roles to users in paerticular spaces. It also ensures that if a user is deleted, the corresponding role is also deleted. (DELETE CASCADE).

```go
func (a *Auth) create_otps(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS otps (
            email TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )`
    _, err := a.conn.Exec(ctx, query)
    ...
}
```
 Each row stores an email, the OTP code, and timestamp after which the code should no longer be accepted.

```go
func (a *Auth) check_spaces(ctx context.Context) error {
    query := `
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'spaces'
        ORDER BY ordinal_position;
    `
    rows, err := a.conn.Query(ctx, query)
    ...
}
```
(Check spaces.md for information related to this function.)

```go
func (a *Auth) check_users(ctx context.Context) error {
    query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'users'
        ORDER BY ordinal_position;
    `
    rows, err := a.conn.Query(ctx, query)
    ...
}
```
check_users checks the users table,making sure that the user_id, password_hash, and salt are present and all of type text. If someone has modified the schema manually this check will fail and force you to resolve the mismatch.

```go
func (a *Auth) check_roles(ctx context.Context) error {
    query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'roles'
        ORDER BY ordinal_position;
    `
    rows, err := a.conn.Query(ctx, query)
    ...
}
```
check_roles verifies that the roles table has a single role column of type text. Any deviation from that expected gives error.

```go
func (a *Auth) check_permissions(ctx context.Context) error {
    query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'permissions'
        ORDER BY ordinal_position;
    `
    rows, err := a.conn.Query(ctx, query)
    ...
}
```
check_permissions ensures that permissions has user_id, space_name, and role columns, all of type text. The function only checks column types here.

```go
func (a *Auth) check_otps(ctx context.Context) error {
    query := `
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'otps'
        ORDER BY ordinal_position;
    `
    rows, err := a.conn.Query(ctx, query)
    ...
}
```
it checks the data type and nullability of email, code, and expires_at.
```go
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
```
table_exists asks Postgres whether a named table exists in the schema. It returns a boolean and an error so callers can distinguish “does not exist” from an error.

```go
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

    // ... repeats for users, roles, permissions, otps ...
    return nil
}
```
check_tables runs through each required table.For each name, it first calls table_exists; if the table is present, it runs the corresponding check function to validate the schema and if the table is missing it calls the corresponding create function to build it from scratch.

```go
func db_connect(ctx context.Context, details *db_details) (*pgxpool.Pool, error) {
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
```
db_connect builds a URL using net/url instead of string concatenation.After constructing urlStr, the function creates a pgxpool.then immediately runs a SELECT 1 check: if that query fails, it closes the pool and returns an error so we know the db is not reachable yet. If success,it logs that the connection pool is ready and returns it for the auth package to use.