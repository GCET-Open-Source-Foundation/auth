# **auth.go**
The Auth struct acts as the central state container for the library. Unlike older global-variable approaches, this package uses a struct-based design, allowing multiple instances to run safely in concurrent environments (e.g., handling multiple HTTP requests simultaneously).

It handles the lifecycle of the database connection, background cleanup tasks (such as removing expired OTPs), and secure memory management.

Key Features
Concurrency Safe: Designed using sync.Once and struct-based state to prevent race conditions.

Connection Pooling: Utilizes pgxpool for high-performance PostgreSQL interactions.

Background Task Management: Automatically starts and manages background routines (e.g., OTP cleanup) with context-based cancellation.

Security Best Practices:

Includes a Close() method that wipes sensitive data (like JWT secrets) from memory.

Schema verification upon startup.

Integrated SMTP: Built-in support for configuring SMTP credentials for email operations (e.g., password resets, verification).

Installation
Assuming this package is part of your local module or a remote repository:

```Go

import "your-module-path/auth"
```
Ensure you have the necessary dependencies:

```Bash

go get github.com/jackc/pgx/v5/pgxpool
```
Usage Guide
Initialization
To use the library, you must initialize the Auth struct using the Init function. This establishes the database connection and verifies the schema.

```Go

package main

import (
    "context"
    "log"
    "your-module-path/auth"
)

func main() {
    ctx := context.Background()

    // 1. Initialize the Auth library
    // Arguments: context, port, username, password, database_name
    appAuth, err := auth.Init(ctx, 5432, "postgres", "secret_pass", "mydb")
    if err != nil {
        log.Fatalf("Failed to init auth: %v", err)
    }

    // 2. Ensure resources are cleaned up when main exits
    defer appAuth.Close()

    log.Println("Auth library initialized successfully")
}
```
SMTP Configuration
If your application requires sending emails (for OTPs or Magic Links), you must configure the SMTP settings once after initialization.

```Go

// Configure SMTP (Email, Password, Host, Port)
err := appAuth.SMTP_init(
    "admin@example.com",
    "smtp_password_123",
    "smtp.gmail.com",
    "587",
)

if err != nil {
    log.Printf("Failed to set SMTP: %v", err)
}
```
Graceful Shutdown
The Close() method is critical for application hygiene. It stops background Go routines and securely clears memory.

```Go

// Usually called via defer in main()
defer appAuth.Close()
```
API Reference
type Auth
The main struct holding the internal state.

Note: Fields are unexported to enforce encapsulation and safety. Interaction should happen via methods.

func Init
```Go

func Init(ctx context.Context, port uint16, db_user, db_pass, db_name string) (*Auth, error)
```
Parameters:

ctx: A context to manage the timeout of the initial connection and schema check.

port: PostgreSQL port (e.g., 5432).

db_user: Database username.

db_pass: Database password.

db_name: Target database name.

Returns:

*Auth: A pointer to the initialized instance.

error: If connection fails or schema validation (check_tables) fails.

Behavior:

Connects to the database using db_connect.

Creates an internal lifecycle context (libCtx).

Runs check_tables to ensure the DB structure is correct.

Starts start_otp_cleanup in the background.

func (*Auth) SMTP_init
```Go

func (a *Auth) SMTP_init(email, password, host, port string) error
```
Sets the SMTP credentials. Uses sync.Once internally, so subsequent calls are ignored (or safe).

Returns: Error if any parameter is an empty string.

func (*Auth) Close
```Go

func (a *Auth) Close()
```
Performs a "destructor-like" cleanup.

Cancels Context: Signals the background OTP cleaner (and any other background jobs) to stop immediately.

Closes DB: Closes the pgxpool connection.

Wipes Memory: Overwrites the byte slice of the JWT secret with zeros and clears credential strings to reduce the risk of memory dump attacks.

Internal Architecture
Lifecycle Management
The library manages its own lifecycle using context.WithCancel.

Creation: When Init is called, a derived context libCtx is created.

Usage: This context is passed to background workers (like the OTP cleaner).

Termination: When Close() is called, libCancel() is executed, propagating a cancellation signal to all background workers to exit their loops.

Security Mechanisms
Memory Wiping: Go relies on Garbage Collection, meaning secrets can linger in memory. The Close method actively zero-fills the jwt_secret slice, mitigating risks if the application memory is dumped after shutdown.

Thread Safety: Critical configuration steps (like setting the pepper or SMTP details) are protected by sync.Once, ensuring that configuration is atomic and immutable after the first set.
