package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/GCET-Open-Source-Foundation/auth/email"
)

/* Helper: Generates a secure 6-digit random number */
func generate_otp() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	/* Pad with zeros to ensure 6 digits (e.g., "001234") */
	return fmt.Sprintf("%06d", n), nil
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
	code, err := generate_otp()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	/* 2. Set Expiry (5 minutes) */
	expiry := time.Now().Add(5 * time.Minute)

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
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for 5 minutes.", code)

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
It automatically deletes expired OTPs every 5 minutes.
*/
func (a *Auth) start_otp_cleanup() {
	/* Hardcoded interval of 5 minutes */
	ticker := time.NewTicker(5 * time.Minute)

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
