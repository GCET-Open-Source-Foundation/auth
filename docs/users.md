# **users.go**
users.go acts as the orchestration layer for user-facing security operations. It doesn't perform raw cryptography itself; instead, it combines the secure password handling of argon.go and the token issuance of jwt.go into high-level flows like registration and login.
It is responsible for generating unique salts for new users, ensuring passwords are hashed before they ever reach the database layer, and issuing JWTs only after successful hash verifications.
```go
// Hypothetical User struct shown for context of interactions
type User struct {
    ID           string
    Email        string
    PasswordHash string // Stores output of argon.go Hash_password
    Salt         string // Stores unique per-user random value
}
```
While users.go might not define the final database model, it expects to interact with a structure that holds these key security elements.
```go
func (a *Auth) Register_user(email, plainPassword string) (*User, error) {
	// 1. Generate a cryptographically random salt
	salt, err := generate_random_salt(16) // Internal helper
	if err != nil {
		return nil, err
	}

	// 2. Delegate hashing to argon.go
	// This applies the salt, the optional global pepper, and Argon2id work parameters.
	hash := a.Hash_password(plainPassword, salt)

	// 3. Prepare user object for persistence layer
	newUser := &User{
		Email:        email,
		Salt:         salt,
		PasswordHash: hash,
		// ID is usually assigned by the database
	}

	// The actual DB save happens outside this library, but this function
	// ensures the data is prepared correctly for storage.
	return newUser, nil
}
```
This method encapsulates the secure user creation flow. It first generates a high-entropy random salt. It then passes the plain-text password and this new salt to a.Hash_password (from argon.go), which handles the intensive work of hashing and peppering. It returns a User struct populated with the safe, hashed data ready to be saved to the database by the application.
```go
func (a *Auth) Login_user(userFromDB *User, suppliedPassword string) (string, error) {
	// 1. Delegate password verification to argon.go
	// Uses the salt and hash stored in the DB against the supplied plain text.
	match := a.compare_passwords(suppliedPassword, userFromDB.Salt, userFromDB.PasswordHash)

	if !match {
		// Return a generic error to avoid leaking whether the user exists vs bad password
		return "", fmt.Errorf("invalid credentials")
	}

	// 2. If password is correct, delegate token creation to jwt.go
	token, err := a.Generate_token(userFromDB.ID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate session token")
	}

	return token, nil
}
```
This method encapsulates the secure login flow. It takes a user struct (fetched from the database by the application) and the plain password just submitted by the user. It calls a.compare_passwords (from argon.go) to perform the secure, constant-time hash comparison. If the password doesn't match, it returns a generic error. If it does match, it immediately calls a.Generate_token (from jwt.go) to create a signed session token for that user's ID and returns the token string.


