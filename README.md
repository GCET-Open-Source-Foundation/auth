# Auth

Auth. Works with Postgres. Supports multiple auth methods (Password, JWT, OTP), spaces, roles, permissions. Integrates with any API library.

## Installation
`go get github.com/GCET-Open-Source-Foundation/auth`

## Usage

* **`auth.Init(ctx, port, dbUser, dbPass, dbName, host)`** - Sets up the library. Connects to Postgres, prepares internal state, and verifies database schema. Must be called before doing anything else.
* **`auth.JWTInit(secret)`** - Initializes the JWT signing key. Required if you intend to use stateless authentication.
* **`auth.SMTPInit(email, password, host, port)`** - Configures the SMTP client. Required for sending OTP emails.
* **`auth.CreateSpace(name, authority)`** - Creates a new space with the given name. Authority determines control level for the space. Fails if space already exists or Init() was not called.
* **`auth.DeleteSpace(name)`** - Deletes the space with the specified name. Removes all associated permissions. Fails if space does not exist.
* **`auth.CreatePermissions(username, spaceName, role)`** - Assigns a role to a user in a specific space. Roles define what the user can do in that space.
* **`auth.DeletePermission(username, spaceName, role)`** - Removes a user's role in a specific space. After this, the user loses access according to that role.
* You can also handle users with **`auth.RegisterUser()`**, **`auth.LoginUser()`**, **`auth.LoginJWT()`** and **`auth.DeleteUser()`**.
* For roles, use **`auth.CreateRole()`** and **`auth.DeleteRole()`**.

## Contributing
All Pull Requests should be sent directly to this repository (**[emmanuelmj/auth](https://github.com/emmanuelmj/auth)**), not the main `GCETOSF` org repo.

Please follow these guidelines:
1. **Fork & PR:** Fork, branch, and open your Pull Request against the `main` branch here.
2. **Commit Standard:** Commits should follow conventional formats, e.g., `type(scope): description`.
3. **Testing:** All changes must pass tests. Run `go test ./...` before submitting your PR.
4. **Context:** If your PR addresses specific issues or features, ensure you provide properly formatted test data and look at existing implementations for reference.