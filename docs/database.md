#**database.go**

database.go is the part of the auth library that connects to Postgres.

it does three main jobs:

Schema creation: If this is a new database, it creates tables for spaces, users, roles, permissions, and OTP.

Schema validation: If the tables already exist, it checks information_schema to verify if the columns and data types match.

Connection management: It builds a Postgres connection and initializes a pgx connection pool that the rest of the library uses.

```go
func (a *Auth) createSpaces(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS spaces (
            spaceName TEXT PRIMARY KEY,
            authority INTEGER NOT NULL
        )`
    _, err := a.Conn.Exec(ctx, query)
    ...
}
```
The spaces table defines “spaces” in your application, each identified by a spaceName and an integer authority.(Check spaces.MD for further clarity)

```go
func (a *Auth) createUsers(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )`
    _, err := a.Conn.Exec(ctx, query)
    ...
}
```
The users table stores each user’s unique ID, the Argon2 hash of their password, and the salt that was used to compute that hash.
```go
func (a *Auth) createRoles(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS roles (
            role TEXT PRIMARY KEY
        )`
    _, err := a.Conn.Exec(ctx, query)
    ...
}
```
The roles table defines the set of roles that can be granted.This makes sure that only known roles are used in permissions.

```go
func (a *Auth) createPermissions(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS permissions (
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            spaceName TEXT NOT NULL REFERENCES spaces(spaceName) ON DELETE CASCADE,
            role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
            PRIMARY KEY (user_id, spaceName, role)
        )`
    _, err := a.Conn.Exec(ctx, query)
    ...
}
```
The permissions table basically assigns roles to users in particular spaces. It also ensures that if a user is deleted, the corresponding role is also deleted. (DELETE CASCADE).

```go
func (a *Auth) createOTPs(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS otps (
            email TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )`
    _, err := a.Conn.Exec(ctx, query)
    ...
}
```
 Each row stores an email, the OTP code, and timestamp after which the code should no longer be accepted.

```go
func (a *Auth) checkSpaces(ctx context.Context) error {
    query := `
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'spaces'
        ORDER BY ordinal_position;
    `
    rows, err := a.Conn.Query(ctx, query)
    ...
}
```
(Check spaces.md for information related to this function.)

```go
func (a *Auth) checkUsers(ctx context.Context) error {
    query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'users'
        ORDER BY ordinal_position;
    `
    rows, err := a.Conn.Query(ctx, query)
    ...
}
```
checkUsers checks the users table,making sure that the user_id, password_hash, and salt are present and all of type text. If someone has modified the schema manually this check will fail and force you to resolve the mismatch.

```go
func (a *Auth) checkRoles(ctx context.Context) error {
    query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'roles'
        ORDER BY ordinal_position;
    `
    rows, err := a.Conn.Query(ctx, query)
    ...
}
```
checkRoles verifies that the roles table has a single role column of type text. Any deviation from that expected gives error.

```go
func (a *Auth) checkPermissions(ctx context.Context) error {
    query := `
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'permissions'
        ORDER BY ordinal_position;
    `
    rows, err := a.Conn.Query(ctx, query)
    ...
}
```
checkPermissions ensures that permissions has user_id, spaceName, and role columns, all of type text. The function only checks column types here.

```go
func (a *Auth) checkOTPs(ctx context.Context) error {
    query := `
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'otps'
        ORDER BY ordinal_position;
    `
    rows, err := a.Conn.Query(ctx, query)
    ...
}
```
it checks the data type and nullability of email, code, and expires_at.
```go
func (a *Auth) tableExists(ctx context.Context, table string) (bool, error) {
    var exists bool
    query := `
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            AND table_name = $1
        )`
    err := a.Conn.QueryRow(ctx, query, table).Scan(&exists)
    return exists, err
}
```
tableExists asks Postgres whether a named table exists in the schema. It returns a boolean and an error so callers can distinguish “does not exist” from an error.

```go
func (a *Auth) checkTables(ctx context.Context) error {
    var check bool = false
    var err error = nil

    check, err = a.tableExists(ctx, "spaces")
    if err != nil {
        return err
    } else {
        if check {
            if err = a.checkSpaces(ctx); err != nil {
                return err
            }
        } else {
            if err = a.createSpaces(ctx); err != nil {
                return err
            }
        }
    }

    // ... repeats for users, roles, permissions, otps ...
    return nil
}
```
checkTables runs through each required table.For each name, it first calls tableExists; if the table is present, it runs the corresponding check function to validate the schema and if the table is missing it calls the corresponding create function to build it from scratch.

```go
func dbConnect(ctx context.Context, details *dbDetails) (*pgxpool.Pool, error) {
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
dbConnect builds a URL using net/url instead of string concatenation.After constructing urlStr, the function creates a pgxpool.then immediately runs a SELECT 1 check: if that query fails, it closes the pool and returns an error so we know the db is not reachable yet. If success,it logs that the connection pool is ready and returns it for the auth package to use.