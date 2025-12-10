                       # **otp.go**
otp.go manages the lifecycle of One-Time Passwords (OTPs)—short numeric codes typically used for two-factor authentication or verifying actions like password resets.
Unlike passwords handled in argon.go, OTPs are high-entropy but short-lived. Security here relies on randomness, very short expiration windows (e.g., 5 minutes), and strictly enforcing "use-once" semantics to prevent replay attacks.
This file handles generating these random codes, securely storing them temporarily along with their expiration time, and verifying incoming codes from users.
```go
type otp_config struct {
	length int
	expiry time.Duration
}

var global_default_otp = otp_config{
	length: 6,
	expiry: 5 * time.Minute,
}
```
This struct defines the parameters for OTP generation. The defaults are standard for most applications: a 6-digit code that expires 5 minutes after generation.
```go
func (a *Auth) Generate_otp_code() (string, error) {
   // ... crypto/rand implementation ...
}
```

This internal helper function generates a cryptographically secure random numeric string based on the configured length. It ensures the output is uniformly distributed so no specific number combinations are more likely than others.
```go
func (a *Auth) Store_otp(identifier string, purpose string, code string) error {
    // ... internal implementation interacting with storage interface ...
}
```
This method takes a generated code and stores it temporarily. Because OTPs must expire quickly, this is typically implemented using a fast, transient storage mechanism like Redis with a Time-To-Live (TTL) set to the configured expiry. The code is stored keyed by the user's identifier (e.g., email or user ID) and the specific purpose of the OTP (e.g., "login_2fa" or "password_reset") to ensure codes intended for one action cannot be used for another.
```go
func (a *Auth) Verify_otp(identifier string, purpose string, suppliedCode string) (bool, error) {
    // ... internal implementation interacting with storage interface ...
}
```
This method checks a code submitted by a user. It attempts to fetch the stored code associated with the given identifierand purpose. If no code is found, it implies the code either never existed or has already expired. If a code is found, it is compared against the suppliedCode. Crucially, regardless of whether the comparison matches, the stored code should immediately be deleted from storage to ensure it cannot be used a second time. It returns true only if the code existed, hadn't expired, and matched the input.

