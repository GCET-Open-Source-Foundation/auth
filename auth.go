package auth

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

/*
db_details is a type, where any database details
can be held, and the global var right below this
is used at Init func to define a main db here.
*/
type db_details struct {
	port          uint16
	username      string
	password      string
	database_name string
}

/*
Auth is a struct that holds the internal state of the library.
Unlike the previous global-variable approach,
this design allows the library to be safely used concurrently.
*/
type Auth struct {
	conn          *pgxpool.Pool
	argon_params  argon_parameters
	pepper        string
	pepper_once   sync.Once
	jwt_secret    []byte
	jwt_once      sync.Once
	smtp_email    string
	smtp_password string
	smtp_host     string
	smtp_port     string
	smtp_once     sync.Once
	ctx           context.Context
	cancel        context.CancelFunc
}

/*
Init configures the db_details, connects to the database,
checks schemas, and returns a fully initialized Auth struct.

It now requires a context for the connection and schema check process.
*/
func Init(ctx context.Context, port uint16, db_user, db_pass, db_name string) (*Auth, error) {
	db_temp := db_details{
		port:          port,
		username:      db_user,
		password:      db_pass,
		database_name: db_name,
	}

	pool, err := db_connect(ctx, &db_temp)
	if err != nil {
		return nil, fmt.Errorf("db connect failed: %w", err)
	}
	if pool == nil {
		return nil, fmt.Errorf("db connect returned nil connection")
	}

	/* Create a context for the Auth library's lifecycle */
	/* context.WithCancel returns a context and a function to cancel it */
	libCtx, libCancel := context.WithCancel(context.Background())

	/* No errors in init */
	temp := &Auth{
		conn:         pool,
		argon_params: global_default_argon,
		ctx:          libCtx,
		cancel:       libCancel,
	}

	if err := temp.check_tables(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database schema check failed: %w", err)
	}
	/* start the background OTP cleaner */
	temp.start_otp_cleanup()

	return temp, nil
}

/*
SMTP_init sets the SMTP server details and credentials.
This must be called once at startup if you intend to use OTP features.
It stores the credentials in memory only.
*/
func (a *Auth) SMTP_init(email, password, host, port string) error {
	if email == "" || password == "" || host == "" || port == "" {
		return fmt.Errorf("all SMTP parameters (email, password, host, port) are required")
	}

	a.smtp_once.Do(func() {
		a.smtp_email = email
		a.smtp_password = password
		a.smtp_host = host
		a.smtp_port = port
	})
	return nil
}

/*
Close performs a graceful shutdown of the Auth library.
It stops background tasks, closes database connections, and wipes sensitive data from memory.
*/
func (a *Auth) Close() {
	/* 1. Stop background routines (OTP cleaner) */
	if a.cancel != nil {
		a.cancel() /* This sends the signal to otp.go to stop!*/
	}

	/* 2. Close Database Connection */
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}

	/* 3. Wipe Sensitive Memory (Security Best Practice) */
	/* Overwrite JWT secret with zeros */
	if len(a.jwt_secret) > 0 {
		for i := range a.jwt_secret {
			a.jwt_secret[i] = 0
		}
		a.jwt_secret = nil
	}

	/* Clear string secrets (Go strings are immutable, but we can unassign them) */
	a.smtp_password = ""
	a.pepper = ""

	fmt.Println("Auth library closed neatly.")
}
