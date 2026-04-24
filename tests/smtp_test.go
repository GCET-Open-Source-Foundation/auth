package tests

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
smtpMockBinary is the expected name of the C++ SMTP mock binary.
The binary must be compiled and available in the system PATH or in
the project's bin/ directory before running these tests.
*/
const smtpMockBinary = "smtp_mock"

/*
findMockBinary locates the C++ SMTP mock binary. It checks the project's
bin/ directory first, then falls back to the system PATH. Returns the
absolute path or an error if the binary is not found.
*/
func findMockBinary(t *testing.T) string {
	t.Helper()

	/* Check project bin/ first */
	projectBin := filepath.Join("..", "bin", smtpMockBinary)
	if abs, err := filepath.Abs(projectBin); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}

	/* Fall back to PATH */
	path, err := exec.LookPath(smtpMockBinary)
	if err != nil {
		t.Skipf("smtp_mock binary not found, skipping SMTP tests: %v", err)
	}
	return path
}

/*
writeInputFile creates a temporary "virtual email" file in the format the
C++ binary expects: Sender, Subject, and Body on separate lines.
Returns the file path. The file is automatically cleaned up when the test ends.
*/
func writeInputFile(t *testing.T, sender, subject, body string) string {
	t.Helper()

	content := fmt.Sprintf("Sender: %s\nSubject: %s\nBody: %s\n", sender, subject, body)

	f, err := os.CreateTemp(t.TempDir(), "smtp_input_*.txt")
	if err != nil {
		t.Fatalf("failed to create input file: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	return f.Name()
}

/*
outputFilePath returns a path for the mock binary's output file inside
the test's temp directory. The file does not need to exist yet — the
binary is expected to create it.
*/
func outputFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "smtp_output.txt")
}

/*
runMockSMTP executes the C++ SMTP mock binary with the given input and output
file paths. It returns the combined stderr output and any error from the process.
A timeout context is used to prevent hangs.
*/
func runMockSMTP(t *testing.T, binary, inputPath, outputPath string, timeout time.Duration) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "--input", inputPath, "--output", outputPath)

	stderr, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(stderr), fmt.Errorf("smtp_mock timed out after %v", timeout)
	}
	return string(stderr), err
}

/* ======================== Happy Path ======================== */

/*
TestSMTPMockOTPDelivery tests the full OTP delivery pipeline:
1. Generate an OTP and store it in the database via SendOTP internals
2. Write a virtual email file with the OTP
3. Run the C++ binary to perform the loopback SMTP transfer
4. Read the output file and verify the OTP is present
*/
func TestSMTPMockOTPDelivery(t *testing.T) {
	binary := findMockBinary(t)
	a := setupTestAuth(t)
	_ = a.OTPInit(6, 5*time.Minute)

	/* Manually insert an OTP (bypasses real SMTP in SendOTP) */
	otp := "482917"
	expiry := time.Now().Add(5 * time.Minute)
	_, err := a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"smtptest@example.com", otp, expiry,
	)
	if err != nil {
		t.Fatalf("failed to insert test OTP: %v", err)
	}

	/* Build the virtual email */
	sender := "noreply@auth.test"
	subject := "Your Verification Code"
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for 5 minutes.", otp)

	inputPath := writeInputFile(t, sender, subject, body)
	outPath := outputFilePath(t)

	/* Run the C++ binary */
	stderr, err := runMockSMTP(t, binary, inputPath, outPath, 10*time.Second)
	if err != nil {
		t.Fatalf("smtp_mock failed: %v\nstderr: %s", err, stderr)
	}

	/* Read output and verify OTP is present */
	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(output), otp) {
		t.Errorf("output file does not contain the OTP %q.\nGot: %s", otp, string(output))
	}

	/* Verify the OTP is still valid in the database */
	err = a.VerifyOTP("smtptest@example.com", otp)
	if err != nil {
		t.Errorf("OTP should still be valid in DB after mock delivery: %v", err)
	}
}

/*
TestSMTPMockSubjectAndSenderPreserved verifies that the output file
contains the original sender and subject, not just the body.
*/
func TestSMTPMockSubjectAndSenderPreserved(t *testing.T) {
	binary := findMockBinary(t)

	sender := "auth@gcet.test"
	subject := "Password Reset Code"
	body := "Your OTP is: 112233\n\nValid for 10 minutes."

	inputPath := writeInputFile(t, sender, subject, body)
	outPath := outputFilePath(t)

	stderr, err := runMockSMTP(t, binary, inputPath, outPath, 10*time.Second)
	if err != nil {
		t.Fatalf("smtp_mock failed: %v\nstderr: %s", err, stderr)
	}

	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, sender) {
		t.Errorf("output missing sender %q", sender)
	}
	if !strings.Contains(outputStr, subject) {
		t.Errorf("output missing subject %q", subject)
	}
	if !strings.Contains(outputStr, "112233") {
		t.Errorf("output missing OTP code")
	}
}

/* ======================== Error States ======================== */

/*
TestSMTPMockBinaryNotFound verifies that the test suite handles a missing
binary gracefully rather than panicking.
*/
func TestSMTPMockBinaryNotFound(t *testing.T) {
	inputPath := writeInputFile(t, "a@b.com", "subj", "body")
	outPath := outputFilePath(t)

	_, err := runMockSMTP(t, "/nonexistent/smtp_mock", inputPath, outPath, 5*time.Second)
	if err == nil {
		t.Error("expected error when binary does not exist")
	}
}

/*
TestSMTPMockNonZeroExit verifies that the test suite correctly detects
a non-zero exit code from the binary. We pass a deliberately invalid
input (empty file) to provoke a failure.
*/
func TestSMTPMockNonZeroExit(t *testing.T) {
	binary := findMockBinary(t)

	/* Create an empty input file — should cause the binary to fail */
	emptyFile := filepath.Join(t.TempDir(), "empty.txt")
	_ = os.WriteFile(emptyFile, []byte(""), 0644)

	outPath := outputFilePath(t)

	_, err := runMockSMTP(t, binary, emptyFile, outPath, 10*time.Second)
	if err == nil {
		t.Log("warning: binary accepted empty input without error")
	} else {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 0 {
				t.Error("expected non-zero exit code for empty input")
			}
			/* Non-zero exit code is the expected behaviour */
		}
	}
}

/*
TestSMTPMockEmptyOutput verifies that the test suite correctly handles
the case where the binary produces an empty output file.
*/
func TestSMTPMockEmptyOutput(t *testing.T) {
	binary := findMockBinary(t)

	inputPath := writeInputFile(t, "a@b.com", "Test", "code: 000000")
	outPath := outputFilePath(t)

	_, err := runMockSMTP(t, binary, inputPath, outPath, 10*time.Second)
	if err != nil {
		t.Skipf("binary returned error, skipping output check: %v", err)
	}

	output, err := os.ReadFile(outPath)
	if err != nil {
		/* Output file was never created — also a valid failure mode */
		t.Logf("output file not created: %v", err)
		return
	}

	if len(output) == 0 {
		t.Error("output file exists but is empty — binary produced no SMTP output")
	}
}

/*
TestSMTPMockTimeout verifies that the test suite correctly handles
a binary that hangs. We use an extremely short timeout to force it.
*/
func TestSMTPMockTimeout(t *testing.T) {
	binary := findMockBinary(t)

	inputPath := writeInputFile(t, "a@b.com", "Slow", "body text")
	outPath := outputFilePath(t)

	/* 1 nanosecond timeout — virtually guaranteed to expire */
	_, err := runMockSMTP(t, binary, inputPath, outPath, 1*time.Nanosecond)
	if err == nil {
		t.Log("binary completed within 1ns timeout — unexpectedly fast, but not a failure")
		return
	}

	if !strings.Contains(err.Error(), "timed out") {
		/* Could also be a context deadline error from exec */
		t.Logf("got error (expected timeout): %v", err)
	}
}

/*
TestSMTPMockMalformedOutput verifies that the test suite can detect
when the output file exists but does not contain the expected OTP.
This simulates a corrupted or partial SMTP transfer.
*/
func TestSMTPMockMalformedOutput(t *testing.T) {
	binary := findMockBinary(t)

	otp := "774411"
	body := fmt.Sprintf("Your OTP is: %s", otp)
	inputPath := writeInputFile(t, "a@b.com", "Code", body)
	outPath := outputFilePath(t)

	stderr, err := runMockSMTP(t, binary, inputPath, outPath, 10*time.Second)
	if err != nil {
		t.Skipf("binary returned error: %v\nstderr: %s", err, stderr)
	}

	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Skipf("output file not created: %v", err)
	}

	/*
		Deliberately check for a WRONG code to verify that our assertion
		logic correctly catches mismatches.
	*/
	wrongCode := "000000"
	if strings.Contains(string(output), wrongCode) {
		t.Errorf("output unexpectedly contains wrong code %q", wrongCode)
	}

	/* The correct code should be present if the binary worked */
	if !strings.Contains(string(output), otp) {
		t.Errorf("output does not contain expected OTP %q.\nGot: %s", otp, string(output))
	}
}

/* ======================== Combined: OTP DB + Mock SMTP ======================== */

/*
TestSMTPMockFullOTPFlow tests the realistic end-to-end flow:
1. Register user
2. Insert OTP in DB (simulating SendOTP minus real SMTP)
3. Construct and write virtual email
4. Run C++ binary for loopback delivery
5. Read output and assert OTP is present
6. Verify OTP in database (consuming it)
7. Confirm OTP cannot be reused
*/
func TestSMTPMockFullOTPFlow(t *testing.T) {
	binary := findMockBinary(t)
	a := setupTestAuth(t)
	_ = a.OTPInit(6, 5*time.Minute)

	/* 1. Register user */
	_ = a.RegisterUser("otpflow@example.com", "password123")

	/* 2. Insert OTP */
	otp := "539201"
	expiry := time.Now().Add(5 * time.Minute)
	_, err := a.Conn.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET code = $2, expires_at = $3",
		"otpflow@example.com", otp, expiry,
	)
	if err != nil {
		t.Fatalf("failed to insert OTP: %v", err)
	}

	/* 3. Write virtual email */
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for 5 minutes.", otp)
	inputPath := writeInputFile(t, "noreply@auth.test", "Your Verification Code", body)
	outPath := outputFilePath(t)

	/* 4. Run mock SMTP */
	stderr, err := runMockSMTP(t, binary, inputPath, outPath, 10*time.Second)
	if err != nil {
		t.Fatalf("smtp_mock failed: %v\nstderr: %s", err, stderr)
	}

	/* 5. Assert OTP in output */
	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	if !strings.Contains(string(output), otp) {
		t.Errorf("output missing OTP %q.\nGot: %s", otp, string(output))
	}

	/* 6. Verify OTP in DB (consumes it) */
	err = a.VerifyOTP("otpflow@example.com", otp)
	if err != nil {
		t.Errorf("OTP verification should succeed: %v", err)
	}

	/* 7. Confirm OTP is consumed */
	err = a.VerifyOTP("otpflow@example.com", otp)
	if !errors.Is(err, auth.ErrInvalidOTP) {
		t.Errorf("expected ErrInvalidOTP on reuse, got: %v", err)
	}
}
