#**jwt.go and users.go**

This document covers two files: `jwt.go` and `users.go`.
`jwt.go` handles JWT token generation and validation.
`users.go` handles user registration, login, password changes, and deletion.

Security is the backbone of any application. Together, these modules handle two critical jobs:
1.  **Protecting User Data:** ensuring that even if the database is stolen, user passwords remain unreadable.
2.  **Stateless Authentication:** allowing users to stay logged in without the server needing to remember them (via JWTs), which makes the application faster and easier to scale.

> **Note:** The following functions (`RegisterUser`, `generateSalt`, `LoginUser`, `LoginJWT`, `ChangePass`, `DeleteUser`) are defined in `users.go`, not `jwt.go`.

## 1. Creating an Account (`RegisterUser`)
When a new user signs up, we cannot simply save their password as plain text.
* **The Goal:** Store the password in a way that is unreadable to anyone, including database administrators.
* **The Flow:** The system generates a unique random value called a **salt**, mixes it with the user's password, creates a cryptographic **hash**, and saves the result.

## 2. Secure Storage (`generateSalt`)
This is an internal "defense" mechanism used automatically during registration and password changes.
* **The Purpose:** It ensures that even if two different users choose the exact same password (e.g., "Password123"), their stored data will look completely different in the database. This protects against bulk hacking attempts.

## 3. Logging In (`LoginUser` & `LoginJWT`)
These functions verify the user's identity when they return to the application. 
* **`LoginUser` (Traditional Login):**
   * Used when a user provides their username and password.
   * The system retrieves the user's unique salt, applies it to the password they just typed, and compares the result with the stored hash. If they match, the user is authenticated.

* **`LoginJWT` (Stateless Sessions):**
   * Used for API interactions. Once a user logs in, the server issues a **JSON Web Token (JWT)**, which acts like a digital ID card.
   * For subsequent requests, the user presents this ID card instead of re-entering their password. This function checks if the ID card is valid and hasn't expired.

## 4. Account Maintenance
These functions manage the account after it is active.

* **`ChangePass` (Password Reset):**
   * When a user updates their password, the system doesn't just overwrite the old hash. It generates a **brand new salt** and a new hash to ensure maximum security for the new credentials.

* **`DeleteUser` (Account Deletion):**
   * When a user leaves the platform, this function permanently removes their credentials and data from the `users` table.


