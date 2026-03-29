#**argon.go**

argon.go is the part of the auth library which handles the encryption of the password and its secure storage. It hashes the password using the Argon2 algorithm and later checks login attempts against the hash without storing the password. 

It does this using three ideas, a salt, an optional pepper and constant-time comparison.

A salt is a random, unique value generated per password and its stored openly in the db next to the hash. It basically makes every hash unique so that the attackers can’t  out which users have the same password.

A pepper is optional, it’s a secret value controlled by the server. If an attacker steals both the password and the hash (or the db itself) they wouldn’t be able to figure out the password without the pepper. (if implemented the pepper must be stored safely elsewhere).

Constant time comparison is used so that the attackers cannot predict how many characters of the attempted password are right based on how fast the comparison stops.

```go

type argon_parameters struct {
	time    uint32 /* number of iterations */
	memory  uint32 /* in KB */
	threads uint8
	keyLen  uint32
}
```
This struct stores settings for Argon2.​
These basically decide how painful you make each password guess for an attacker.​

time': defines the amount of computation realized and, therefore, the execution time given in a number of iterations.

'memory': A memory cost, which represents memory usage, is given in kibibytes. A “kibibyte” is equal to 1024, or 2^10, bytes.

'threads': A parallelism degree, which defines the number of parallel threads.​

'keyLen': longer hashes give attackers no shortcut like “small output space” to brute‑force; they must attack the password itself.

```go
var global_default_argon = argon_parameters{
	time:    3,
	memory:  64 * 1024,
	threads: 4,
	keyLen:  32,
}
```
These are the default parameters that have been set.

```go
func (a *Auth) Default_salt_parameters(time uint32, memory uint32, threads uint8, keyLen uint32) error {
	
	if time == 0 {
		return fmt.Errorf("time (iterations) cannot be zero")
	}
	if memory < 8*1024 {
		return fmt.Errorf("memory too low: must be at least 8MB")
	}
	if threads == 0 {
		return fmt.Errorf("threads cannot be zero")
	}
	if keyLen < 16 {
		return fmt.Errorf("key length too small: must be at least 16 bytes")
	}

	a.argon_params.time = time
	a.argon_params.memory = memory
	a.argon_params.threads = threads
	a.argon_params.keyLen = keyLen

	return nil
}
```
This method lets you change the default Argon2 settings (iterations, memory, threads, hash length) for this Auth instance.It is an advanced function and **should normally be called once at startup**, right after **auth.Init**, before any API requests are handled.​

For safety, it checks all inputs and rejects unsafe values:

'time': must be > 0 (at least one iteration).

'memory': must be at least 8 MB, or the hash becomes too cheap to compute.​

'threads': must be > 0.

'keyLen': must be at least 16 bytes so the hash isn’t trivially short.

If it passes all the checks, it saves values into **a.argon_params** and returns nil; otherwise, it returns an error explaining what was wrong.

```go
func (a *Auth) Pepper_init(pep string) error {
	if pep == "" {
		return fmt.Errorf("pepper cannot be empty")
	}

	a.pepper_once.Do(func() {
		a.pepper = pep
	})
	return nil
}
```
This method sets a global pepper value. It is basically a secret string that will be mixed into every password before hashing. **It should be called once during application startup (right after auth.Init)** and the pepper must be stored safely outside the db.​

If the provided string is empty it returns an error.

```go
func (a *Auth) Hash_password(password, salt string) string {

	if a.pepper != "" {
		password += a.pepper
	}
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)
	if len(saltBytes) < 16 {
		log.Printf("Warning: salt length is unusually short (%d bytes). Recommended >= 16 bytes.", len(saltBytes))
	}

	hash := argon2.IDKey(passwordBytes, saltBytes, a.argon_params.time, a.argon_params.memory, a.argon_params.threads, a.argon_params.keyLen)

	return hex.EncodeToString(hash)
}
```
This method takes a plain‑text password + salt and returns encoded Argon hashed string suitable for storing in the db.It does not generate the salt itself.Salts are created elsewhere (for example in users.go) and passed inside.

```go
func (a *Auth) compare_passwords(password, salt, storedHash string) bool {
	newHash := a.Hash_password(password, salt)

	return subtle.ConstantTimeCompare([]byte(newHash), []byte(storedHash)) == 1
}
```
This checks whether a password attempt matches an existing hash. It first  rehashes input password and salt by calling Hash_password, using the same parameters (and pepper, if configured) that were used when the password was originally stored.​

It then compares the newHash with the **storedHash** using **subtle.ConstantTimeCompare** protecting against timing attacks. The function returns true only if the two hashes are equal, and false otherwise.