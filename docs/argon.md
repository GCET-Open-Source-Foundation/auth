# **argon.go**

argon.go is the part of the library that securely handles passwords. It turns a plain password into a one‑way scrambled value (a hash) using the **Argon2id** algorithm, and later checks login attempts against that hash without ever storing the real password.​

It does this using three ideas: a salt, an optional pepper, and constant‑time comparison (so attackers cannot learn anything from timing differences when hashes are compared).​

- A salt is a random, unique value generated per password and stored openly in the database next to the hash; its job is to make every hash unique so attackers can’t reuse precomputed tables or see which users share a password.​

- A pepper is a secret value controlled by the server, not stored with user records, and mixed into every password before hashing so that even if an attacker steals all hashes and salts, they still need this extra hidden piece to crack them effectively.​

The use of a global pepper is **optional**; if you enable it, it must be **stored safely** elsewhere because losing it will make all stored passwords effectively **unusable**.

With these concepts in mind, the rest of this document walks through the argon.go source code line by line. 

```go

type argon_parameters struct {
	time    uint32 /* number of iterations */
	memory  uint32 /* in KB */
	threads uint8
	keyLen  uint32
}
```
This struct stores all the tuning settings for Argon2id.​
These knobs decide how painful you make each password guess for an attacker.​

- 'time': higher time = more CPU work per guess, so attackers can try far fewer passwords per second.​

- 'memory': higher memory = more RAM per guess, so attackers need huge, expensive hardware to run many guesses in parallel.​

- 'threads': lets your server use multiple cores to keep hashes reasonably fast for real users while attackers still pay the full time+memory cost for each try.​

- 'keyLen': longer hashes give attackers no shortcut like “small output space” to brute‑force; they must attack the password itself.

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
This method lets you override the default Argon2id settings (iterations, memory, threads, hash length) for this Auth instance. It is an advanced function and **should normally be called once at startup**, right after **auth.Init**, before any API requests are handled.​

For safety, it validates all inputs and rejects clearly unsafe values:

- 'time': must be > 0 (at least one iteration).

- 'memory': must be at least 8 MB, or the hash becomes too cheap to compute.​

- 'threads': must be > 0.

- 'keyLen': must be at least 16 bytes so the hash isn’t trivially short.

If all checks pass, it saves these values into **a.argon_params** and returns nil; otherwise, it returns an error explaining what was wrong.

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
This method sets a global pepper value for this Auth instance: a secret string that will be mixed into every password before hashing for extra security. **It should be called once during application startup (right after auth.Init)** and the pepper must be stored safely outside the database.​

If the provided string is empty, it returns an error. Otherwise, it uses a.pepper_once.Do to assign **a.pepper = pep** exactly once, even if **Pepper_init** is called multiple times or from different goroutines, and then returns nil on success.

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
This method takes a plain‑text password plus a caller‑provided salt and returns a hex‑encoded Argon2id hash string suitable for storing in the database. It does not generate the salt itself; salts are created elsewhere (for example in users.go) and passed in.​

If a global pepper has been configured with Pepper_init, it first appends that pepper to the password so every hash also depends on a secret value kept outside the database. It then converts the combined password and the salt to byte slices, warns via log.Printf if the salt is shorter than **16 bytes** (which is weaker than recommended), and calls **argon2.IDKey** with the current Argon2 parameters (time, memory, threads, keyLen) stored on the Auth struct. The raw hash bytes from Argon2 are finally encoded as a hexadecimal string with **hex.EncodeToString** and returned.

```go
func (a *Auth) compare_passwords(password, salt, storedHash string) bool {
	newHash := a.Hash_password(password, salt)

	return subtle.ConstantTimeCompare([]byte(newHash), []byte(storedHash)) == 1
}
```
This internal helper verifies whether a plain‑text password attempt matches an existing stored hash. It first recomputes the hash for the input password and salt by calling Hash_password, using the same Argon2id parameters (and pepper, if configured) that were used when the password was originally stored.​

It then compares the freshly computed hash (newHash) with the **storedHash** using **subtle.ConstantTimeCompare**, which runs in roughly the same time regardless of where the strings differ, protecting against timing attacks. The function returns true only if the two hashes are exactly equal, and false otherwise.

