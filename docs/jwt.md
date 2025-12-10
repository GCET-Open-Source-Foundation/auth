# **jwt.go**
jwt.go is responsible for handling JSON Web Tokens (JWTs), which are the secure "ID cards" issued to users after they successfully log in. Instead of checking the database on every single request, the server issues a signed token that the client sends back with subsequent requests.
It relies on cryptographic signing (usually HMAC-SHA256) using a secret key known only to the server. This ensures that while anyone can read the contents of the token, nobody can tamper with it or change the user permissions inside without invalidating the signature.
jwt.go handles setting up this secret key, defining how long tokens last, generating new tokens upon login, and validating incoming tokens on protected API routes.
```go
type jwt_config struct {
	secretKey   []byte
	tokenExpiry time.Duration
	issuer      string
}
```
This struct holds the configuration for JWT operations for this Auth instance. 'secretKey': The raw bytes of the secret used to sign tokens. If an attacker gets this, they can forge tokens for any user. 'tokenExpiry': The duration for which a generated token is considered valid (e.g., 1 hour, 24 hours). Shorter expiry is safer but requires users to re-authenticate more often. 'issuer': A string identifying the application issuing the token (the "iss" claim in standard JWTs).
```go
func (a *Auth) JWT_init(secret string, expiryMinutes int, issuer string) error {
	if len(secret) < 32 {
		return fmt.Errorf("jwt secret too short: must be at least 32 bytes for adequate security")
	}
	if expiryMinutes <= 0 {
		return fmt.Errorf("token expiry must be positive")
	}

	a.jwt_config.secretKey = []byte(secret)
	a.jwt_config.tokenExpiry = time.Duration(expiryMinutes) * time.Minute
	a.jwt_config.issuer = issuer

	return nil
}
```
This method initializes the JWT configuration. It must be called during application startup before any tokens can be issued or verified. It enforces security constraints: the signing secret must be at least 32 characters long to prevent brute-forcing the key, and the expiry time must be positive. If valid, it converts the parameters into the internal struct format; otherwise, it returns an error.
```go
func (a *Auth) Generate_token(userID string, customClaims map[string]interface{}) (string, error) {
    // ... internal implementation using external jwt library ...
}
```
This method creates a new, signed JWT string for a specific user. It is typically called by the login function in users.goafter password verification succeeds. It builds a token containing standard claims—specifically the Subject ("sub", set to the userID), the Issuer ("iss"), and the Expiration Time ("exp", calculated using the current time plus tokenExpiry). It also embeds any customClaims provided. Finally, it signs the token using the stored secretKey and returns the encoded string.
```go
func (a *Auth) Validate_token(tokenString string) (jwt.MapClaims, error) {
    // ... internal implementation using external jwt library ...
}
```
This method is the gatekeeper for protected routes. It takes a raw token string coming from a client request and attempts to parse it. Crucially, it verifies the token's signature using the server's secretKey to ensure it hasn't been tampered with. It automatically checks standard claims like expiration time to ensure the token isn't stale. If signature verification fails, or if the token has expired, it returns an error. If valid, it returns the map of claims held within the token so the application can determine who the user is.


