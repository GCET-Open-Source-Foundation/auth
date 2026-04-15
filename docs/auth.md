#**auth.go**

Just to get an idea of what the imports do:-
context- controls timeouts and cancellations
sync-helps with thread security
pgxpool- PostgreSQL connection

```go

type dbDetails struct {
	port          uint16
	username      string
	password      string
	databaseName string
	host          string
}
```
This stores the database port, password, username and database name. Its used only inside this package.

```go
type Auth struct {
	Conn          *pgxpool.Pool
	argonParams  argonParameters
	pepper        string
	pepperOnce   sync.Once
	jwtSecret    []byte
	jwtOnce      sync.Once
	smtpEmail    string
	smtpPassword string
	smtpHost     string
	smtpPort     string
	smtp_once     sync.Once
	ctx           context.Context
	cancel        context.CancelFunc
}
```
This struct stores everything the auth system needs.

Database
Conn : - database connection pool

Security
argonParams :- password hashing settings
pepper:- extra secret for hashing passwords
Jwt_secrets:- secret key for JWT tokens

sync.Once:- ensures that something is set only once and prevents bugs in multi threaded programs.

Init()

```go
func Init(ctx context.Context, port uint16, dbUser, dbPass, dbName, host string) (*Auth, error)
```
This function is basically where the server starts. It first puts all the database information into a struct. Then it tried to connect to the database and returns an error in case it fails. Creating a library context allows the background tasks to run and makes way for a clean shutdown later on. Creating the Auth object makes the system exist in memory.

```go
if err := temp.checkTables(ctx); err != nil {
	pool.Close()
	return nil, err
}
```
This ensures the required tables exist and prevents runtime crashes later.

```go
temp.startOTPCleanup()
```
This runs a background routine and periodically removes expired OTPs

SMTPInit()
```go
func (a *Auth) SMTPInit(email, password, host, port string) error
```
This function stores SMTP details and is needed for sending otp emails. It also checks empty values.
sync.Once can only be used once
Close()
Called when the app is shutting down for a graceful shutting down.
It stops background goroutines and signals the OTP cleaner to stop. It closes database connections to prevent connection leaks and memory leaks. Also wipes secrets from memory by removing them from RAM, clears sensitive strings and logs the shutdown.


 




