package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/GCET-Open-Source-Foundation/auth/email"
)

/* OTP_init configures the OTP settings. If values are 0, defaults are used. */
func (a *Auth) OTP_init(length int, expiry time.Duration) error {
	if length < 4 || length > 10 {
		return fmt.Errorf("invalid OTP length: %d (must be between 4 and 10)", length)
	}
	if expiry <= 0 {
		return fmt.Errorf("invalid OTP expiry: %v", expiry)
	}

	a.otp_length = length
	a.otp_expiry = expiry
	return nil
}

/* Helper: Generates a secure random number based on the configured OTP length */
func (a *Auth) generate_otp() (string, error) {
	/* 1. Validation Guard */
	if a.otp_length < 4 || a.otp_length > 10 {
		return "", fmt.Errorf("invalid OTP length: %d (must be between 4 and 10)", a.otp_length)
	}

	/* 2. Calculate the max value (e.g., 10^6 = 1,000,000)*/
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(a.otp_length)), nil)

	/* 3. Generate secure random number */
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	/* 4. Dynamically pad the string (e.g., 6 digits becomes %06d) */
	return fmt.Sprintf("%0*d", a.otp_length, n), nil
}

/*
SendOTP generates an OTP, saves it to the DB (upsert), and emails it.
Usage: auth.SendOTP("user@example.com")
*/
func (a *Auth) SendOTP(user_email string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first")
	}
	if a.smtp_host == "" {
		return fmt.Errorf("run auth.SMTP_init() first")
	}

	/* 1. Generate Code */
	code, err := a.generate_otp()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	/* 2. Set Expiry (Uses the config field instead of hardcoded value) */
	if a.otp_expiry <= 0 {
		return fmt.Errorf("invalid OTP expiry duration: %v", a.otp_expiry)
	}
	expiry := time.Now().Add(a.otp_expiry)
	/* 3. Upsert into DB (Update if email exists, Insert if new) */
	query := `
		INSERT INTO otps (email, code, expires_at) 
		VALUES ($1, $2, $3)
		ON CONFLICT (email) 
		DO UPDATE SET code = $2, expires_at = $3
	`
	_, err = a.Conn.Exec(context.Background(), query, user_email, code, expiry)
	if err != nil {
		return fmt.Errorf("db error saving OTP: %w", err)
	}

	/* 4. Send Email */
	subject := "Your Verification Code"
	/* Format to '5 minutes' instead of '5m0s' */
	minutes := int(a.otp_expiry.Minutes())
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for %d minutes.", code, minutes)
	err = email.SendEmail(
		a.smtp_host, a.smtp_port,
		a.smtp_email, a.smtp_password,
		user_email, subject, body,
	)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

/*
VerifyOTP checks if the code is correct and not expired.
If valid, it deletes the OTP to prevent reuse.
*/
func (a *Auth) VerifyOTP(user_email, input_code string) bool {
	if a.Conn == nil {
		return false
	}

	var storedCode string
	var expiry time.Time

	/* Get the OTP */
	query := "SELECT code, expires_at FROM otps WHERE email = $1"
	err := a.Conn.QueryRow(context.Background(), query, user_email).Scan(&storedCode, &expiry)
	if err != nil {
		return false /* OTP not found */
	}

	/* Check match and expiry */
	if storedCode != input_code || time.Now().After(expiry) {
		return false
	}

	/* Valid! Delete it. */
	_, _ = a.Conn.Exec(context.Background(), "DELETE FROM otps WHERE email = $1", user_email)
	return true
}

/*
start_otp_cleanup is an internal function that runs in the background.
It periodically deletes expired OTPs from the database.
The cleanup cycle is fixed (5 minutes) to ensure consistent performance
regardless of the configured OTP expiration duration.
*/
func (a *Auth) start_otp_cleanup() {
	/* Fixed 5-minute interval to prevent DB stress */
	ticker	:=	time.NewTicker(5 * time.Minute)

	go func() {
		/* Ensure the ticker stops when we exit to prevent leaks */
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				/* The Timer ticked: Do the work */
				if a.Conn != nil {
					_, _ = a.Conn.Exec(context.Background(), "DELETE FROM otps WHERE expires_at < NOW()")
				}

			case <-a.ctx.Done():
				/* The Context was cancelled: STOP EVERYTHING */
				/* This returns from the function, killing the goroutine "neatly" */
				return
			}
		}
	}()
}
