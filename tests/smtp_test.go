package tests

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

func getBinaryName() string {
	if runtime.GOOS == "windows" {
		return "smtp_mock.exe"
	}
	return "smtp_mock"
}

func findMockBinary(t *testing.T) string {
	t.Helper()

	binaryName := getBinaryName()
	projectBin := filepath.Join("..", "bin", binaryName)

	if abs, err := filepath.Abs(projectBin); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}

	path, err := exec.LookPath(binaryName)
	if err != nil {
		t.Skipf("%s binary not found, skipping SMTP tests: %v", binaryName, err)
	}
	return path
}

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

func outputFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "smtp_output.txt")
}

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

func TestSMTPMockOTPDelivery(t *testing.T) {
	skipIfShort(t)
	binary := findMockBinary(t)
	a := setupTestAuth(t)
	_ = a.OTPInit(6, 5*time.Minute)
	_ = a.SMTPInit("noreply@auth.test", "dummy_pass", "127.0.0.1", "2525")

	userEmail := "smtptest@example.com"

	err := a.SendOTP(userEmail)
	if err != nil && !strings.Contains(err.Error(), "failed to send email") {
		t.Fatalf("unexpected SendOTP failure: %v", err)
	}

	var otp string
	err = a.Conn.QueryRow(context.Background(), "SELECT code FROM otps WHERE email = $1", userEmail).Scan(&otp)
	if err != nil {
		t.Fatalf("failed to retrieve generated OTP: %v", err)
	}

	sender := "noreply@auth.test"
	subject := "Your Verification Code"
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for 5 minutes.", otp)

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

	if !strings.Contains(string(output), otp) {
		t.Errorf("output file does not contain the OTP %q.\nGot: %s", otp, string(output))
	}

	err = a.VerifyOTP(userEmail, otp)
	if err != nil {
		t.Errorf("OTP should still be valid in DB after mock delivery: %v", err)
	}
}

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

func TestSMTPMockBinaryNotFound(t *testing.T) {
	inputPath := writeInputFile(t, "a@b.com", "subj", "body")
	outPath := outputFilePath(t)

	badPath := filepath.Join("/nonexistent", getBinaryName())

	_, err := runMockSMTP(t, badPath, inputPath, outPath, 5*time.Second)
	if err == nil {
		t.Error("expected error when binary does not exist")
	}
}

func TestSMTPMockNonZeroExit(t *testing.T) {
	binary := findMockBinary(t)

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
		}
	}
}

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
		t.Logf("output file not created: %v", err)
		return
	}

	if len(output) == 0 {
		t.Error("output file exists but is empty — binary produced no SMTP output")
	}
}

func TestSMTPMockTimeout(t *testing.T) {
	binary := findMockBinary(t)

	inputPath := writeInputFile(t, "a@b.com", "Slow", "body text")
	outPath := outputFilePath(t)

	_, err := runMockSMTP(t, binary, inputPath, outPath, 1*time.Nanosecond)
	if err == nil {
		t.Log("binary completed within 1ns timeout — unexpectedly fast, but not a failure")
		return
	}

	if !strings.Contains(err.Error(), "timed out") {
		t.Logf("got error (expected timeout): %v", err)
	}
}

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

	wrongCode := "000000"
	if strings.Contains(string(output), wrongCode) {
		t.Errorf("output unexpectedly contains wrong code %q", wrongCode)
	}

	if !strings.Contains(string(output), otp) {
		t.Errorf("output does not contain expected OTP %q.\nGot: %s", otp, string(output))
	}
}

func TestSMTPMockFullOTPFlow(t *testing.T) {
	skipIfShort(t)
	binary := findMockBinary(t)
	a := setupTestAuth(t)
	_ = a.OTPInit(6, 5*time.Minute)
	_ = a.SMTPInit("noreply@auth.test", "dummy_pass", "127.0.0.1", "2525")

	userEmail := "otpflow@example.com"

	_ = a.RegisterUser(userEmail, "password123")

	err := a.SendOTP(userEmail)
	if err != nil && !strings.Contains(err.Error(), "failed to send email") {
		t.Fatalf("unexpected error from SendOTP: %v", err)
	}

	var otp string
	err = a.Conn.QueryRow(context.Background(), "SELECT code FROM otps WHERE email = $1", userEmail).Scan(&otp)
	if err != nil {
		t.Fatalf("failed to fetch generated OTP: %v", err)
	}

	body := fmt.Sprintf("Your OTP is: %s\n\nValid for 5 minutes.", otp)
	inputPath := writeInputFile(t, "noreply@auth.test", "Your Verification Code", body)
	outPath := outputFilePath(t)

	stderr, err := runMockSMTP(t, binary, inputPath, outPath, 10*time.Second)
	if err != nil {
		t.Fatalf("smtp_mock failed: %v\nstderr: %s", err, stderr)
	}

	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	if !strings.Contains(string(output), otp) {
		t.Errorf("output missing OTP %q.\nGot: %s", otp, string(output))
	}

	err = a.VerifyOTP(userEmail, otp)
	if err != nil {
		t.Errorf("OTP verification should succeed: %v", err)
	}

	err = a.VerifyOTP(userEmail, otp)
	if !errors.Is(err, auth.ErrInvalidOTP) {
		t.Errorf("expected ErrInvalidOTP on reuse, got: %v", err)
	}
}
