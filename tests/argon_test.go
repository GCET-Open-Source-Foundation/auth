package tests

import (
	auth "github.com/GCET-Open-Source-Foundation/auth"
	"testing"
)

/*
TestHashPasswordDeterministic checks that hashing the same password with
the same salt produces a consistent output.
*/
func TestHashPasswordDeterministic(t *testing.T) {
	a := auth.NewBareAuth()

	hash1 := a.HashPassword("mypassword", "somesalt1234567890")
	hash2 := a.HashPassword("mypassword", "somesalt1234567890")

	if hash1 != hash2 {
		t.Errorf("same password and salt should produce the same hash, got %s and %s", hash1, hash2)
	}
}

/*
TestHashPasswordDifferentSalt verifies that different salts produce different hashes.
*/
func TestHashPasswordDifferentSalt(t *testing.T) {
	a := auth.NewBareAuth()

	hash1 := a.HashPassword("mypassword", "salt_one_1234567890")
	hash2 := a.HashPassword("mypassword", "salt_two_1234567890")

	if hash1 == hash2 {
		t.Error("different salts should produce different hashes")
	}
}

/*
TestHashPasswordDifferentPasswords verifies that different passwords produce different hashes.
*/
func TestHashPasswordDifferentPasswords(t *testing.T) {
	a := auth.NewBareAuth()

	hash1 := a.HashPassword("password1", "same_salt_1234567890")
	hash2 := a.HashPassword("password2", "same_salt_1234567890")

	if hash1 == hash2 {
		t.Error("different passwords should produce different hashes")
	}
}

/*
TestHashPasswordWithPepper verifies that adding a pepper changes the hash output.
*/
func TestHashPasswordWithPepper(t *testing.T) {
	a := auth.NewBareAuth()

	hashWithout := a.HashPassword("mypassword", "somesalt1234567890")

	b := auth.NewBareAuth()
	_ = b.PepperInit("my-secret-pepper")
	hashWith := b.HashPassword("mypassword", "somesalt1234567890")

	if hashWithout == hashWith {
		t.Error("pepper should change the hash output")
	}
}

/*
TestDefaultSaltParameters validates the parameter boundary checking.
*/
func TestDefaultSaltParameters(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.DefaultSaltParameters(0, 64*1024, 4, 32); err == nil {
		t.Error("expected error for time=0")
	}
	if err := a.DefaultSaltParameters(3, 1024, 4, 32); err == nil {
		t.Error("expected error for memory below 8MB")
	}
	if err := a.DefaultSaltParameters(3, 64*1024, 0, 32); err == nil {
		t.Error("expected error for threads=0")
	}
	if err := a.DefaultSaltParameters(3, 64*1024, 4, 8); err == nil {
		t.Error("expected error for keyLen < 16")
	}
	if err := a.DefaultSaltParameters(3, 64*1024, 4, 32); err != nil {
		t.Errorf("expected no error for valid params, got: %v", err)
	}
}

/*
TestPepperInit verifies pepper initialisation and sync.Once idempotency.
*/
func TestPepperInit(t *testing.T) {
	a := auth.NewBareAuth()

	if err := a.PepperInit(""); err == nil {
		t.Error("expected error for empty pepper")
	}

	if err := a.PepperInit("my-pepper"); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	/* Second call should be ignored by sync.Once — hash stays the same */
	_ = a.PepperInit("different-pepper")
	hash := a.HashPassword("test", "salt1234567890123456")

	/* Compare against a fresh instance with the original pepper */
	b := auth.NewBareAuth()
	_ = b.PepperInit("my-pepper")
	expected := b.HashPassword("test", "salt1234567890123456")

	if hash != expected {
		t.Error("pepper should not change after first init (sync.Once)")
	}
}
