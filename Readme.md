# Auth

Auth. Works with Postgres. Supports multiple auth methods (Password, JWT, OTP), spaces, roles, permissions. Integrates with any API library.

## Installation
`go get github.com/GCET-Open-Source-Foundation/auth`

## Usage

* **`auth.Init(ctx, port, db_user, db_pass, db_name, host)`** - Sets up the library. Connects to Postgres, prepares internal state, and verifies database schema. Must be called before doing anything else.
* **`auth.JWT_init(secret)`** - Initializes the JWT signing key. Required if you intend to use stateless authentication.
* **`auth.SMTP_init(email, password, host, port)`** - Configures the SMTP client. Required for sending OTP emails.
* **`auth.Create_space(name, authority)`** - Creates a new space with the given name. Authority determines control level for the space. Fails if space already exists or Init() was not called.
* **`auth.Delete_space(name)`** - Deletes the space with the specified name. Removes all associated permissions. Fails if space does not exist.
* **`auth.Create_permissions(username, space_name, role)`** - Assigns a role to a user in a specific space. Roles define what the user can do in that space.
* **`auth.Delete_permission(username, space_name, role)`** - Removes a user's role in a specific space. After this, the user loses access according to that role.
* You can also handle users with **`auth.Register_user()`**, **`auth.Login_user()`**, **`auth.Login_jwt()`** and **`auth.Delete_user()`**.
* For roles, use **`auth.Create_role()`** and **`auth.Delete_role()`**.
* **Google OAuth**: Use **`auth.Google_init(clientID, clientSecret, redirectURL)`** to configure, **`auth.Google_auth_url(state)`** to get the consent URL, **`auth.Google_exchange(code)`** to exchange the authorization code, **`auth.Link_google(guser, userID)`** to link accounts, and **`auth.Login_google(providerID)`** to log in via Google.