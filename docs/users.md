#**users.go**

**Security Utilities: Salting**

generateSalt(size int)

This is a helper function used whenever a password is created or changed.
What it does: It creates a unique, random string of bytes using a cryptographically secure random number generator (crypto/rand).
Why it's important: "Salting" ensures that if two users have the same password, their stored hashes will look completely different in the database. This prevents attackers from using "Rainbow Tables" to crack passwords.

**The Login Process**

LoginUser(username, password)
This function handles traditional login attempts.
  Database Check: It queries the database for the password_hash and salt associated with the provided username.
  Verification: It calls a helper method a.comparePasswords (defined elsewhere in your package) to see if the user's input, when combined with the stored salt, matches the stored hash.
  Result: Returns true if they match, false otherwise.
LoginJWT(tokenString)
  This is used for Stateless Authentication.
  Instead of checking a database every time, it validates a JSON Web Token (JWT).
  It delegates the actual validation work to another function (a.ValidateToken) located in a different file (jwt.go), keeping the code organized.

**User Management**

RegisterUser(username, password)
This function handles creating new accounts.
  Salt Generation: It generates a fresh 32-byte salt.
  Hashing: It hashes the password using that salt.
  Storage: It inserts the username, the hashed password, and the salt into the users table. 
  Note: It never stores the actual "plain-text" password.
ChangePass(username, newPassword)
Allows a user to update their credentials.
  It generates a completely new salt and a new hash for the new password.
  It updates the database record.
  Error Handling: It specifically checks if the user actually exists using cmdTag.RowsAffected(). If the user doesn't exist, it returns an error.
DeleteUser(username)
Removes a user from the system.
It runs a standard SQL DELETE command based on the user_id.

