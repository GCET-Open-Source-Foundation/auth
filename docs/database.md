# **database.go**
database.go is the part of the library that talks to PostgreSQL. It is responsible for creating the tables that the auth system needs, checking that an existing database has the right schema, and wiring up the connection pool so the rest of the package can safely run queries.

Conceptually, it does three main jobs:

Schema creation: If this is a fresh database, it creates tables for spaces, users, roles, permissions, and OTP codes with the right columns and constraints.

Schema validation: If the tables already exist, it inspects information_schema to verify that the columns and data types match what the library expects, failing fast if they do not.

Connection management: It builds a PostgreSQL connection URL safely (handling special characters in passwords) and initializes a pgx connection pool that the rest of the library uses.

With that in mind, the rest of this document walks through the key functions in database.go using small snippets.

Creating the core tables
At the top, there is a series of create_* helpers. Each one creates a specific table only if it does not already exist, and logs a message on success.

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
The spaces table defines “spaces” in your application, each identified by a unique space_name and an integer authority level. This is the backbone for scoping permissions, so every permission later refers back to a row in this table.

```go
func (a *Auth) create_users(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )`
    _, err := a.conn.Exec(ctx, query)
    ...
}
```
The users table stores each user’s unique ID, the Argon2 hash of their password, and the per‑user salt that was used to compute that hash. The raw password is never stored; only password_hash and salt are kept in the database.

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
The roles table defines the set of roles (like admin, reader, editor, etc.) that can be granted to users. This keeps the role names centralized and enforces that only known roles are used in permissions.

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
The permissions table ties everything together: it says “this user has this role in this space”. Foreign keys point to users, spaces, and roles, and ON DELETE CASCADE ensures that when a user or space is removed, their corresponding permission rows disappear automatically instead of becoming orphaned.

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
The otps table supports one‑time‑password flows. Each row stores an email, the OTP code sent to that email, and an expires_at timestamp after which the code should no longer be accepted.

Checking that tables have the right shape
If an existing database already has tables, blindly creating them is not enough. The check_* functions inspect information_schema.columns to ensure the schema matches what the library expects.

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
check_spaces reads back all columns of the spaces table, builds a map of column name to type and nullability, and then compares that against an expected map of required columns (space_name as text, authority as integer). If a column is missing or has the wrong type, it returns an error describing the mismatch instead of silently continuing.

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
check_users does the same for the users table, ensuring that user_id, password_hash, and salt are present and all of type text. If someone has modified the schema by hand (for example changing a type), this check will fail and force you to resolve the mismatch before running auth operations.

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
check_roles is simpler: it verifies that the roles table has a single role column of type text. Any deviation from that expected shape surfaces as an error.

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
check_permissions ensures that permissions has user_id, space_name, and role columns, all of type text. The function only checks column types here; it assumes that the foreign keys and primary key were created correctly when the table was first created.

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
For otps, the check is a bit stricter: it validates the data type and nullability of email, code, and expires_at. The expected type for expires_at is timestamp without time zone, which is the usual representation of a plain timestamp in PostgreSQL; if your database reports something else, the function will flag it as a mismatch.

Detecting and repairing missing tables
Rather than requiring users to manually run migrations, database.go can detect missing tables and create them automatically. This is coordinated by table_exists and check_tables.

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
table_exists simply asks PostgreSQL whether a named table exists in the public schema. It returns a boolean and an error so callers can distinguish “does not exist” from “could not query metadata”.

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
check_tables runs through each required table (spaces, users, roles, permissions, otps) in turn. For each name, it first calls table_exists; if the table is present, it runs the corresponding check_* function to validate the schema, and if the table is missing, it calls the corresponding create_* function to build it from scratch. The loop short‑circuits on the first error so misconfigurations surface quickly instead of being ignored.

Connecting to PostgreSQL with pgx
At the bottom of the file there is a helper to create a connection pool using pgxpool and a db_details struct (defined elsewhere in the package).

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
db_connect builds a PostgreSQL URL using net/url instead of string concatenation. This is important because database passwords often contain special characters, and url.UserPassword will escape them correctly so the connection string remains valid. After constructing urlStr, the function creates a pgxpool.Pool, then immediately runs a SELECT 1 sanity check: if that simple query fails, it closes the pool and returns an error so callers know the database is not reachable yet. On success, it logs that the connection pool is ready and returns it for the rest of the auth package to use.
