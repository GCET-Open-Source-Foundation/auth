Auth. Works with Postgres. Supports multiple auth methods, spaces, roles, permissions. Integrates with any API library.

install with
`go get https://github.com/GCET-Open-Source-Foundation/auth`

auth.Init() - Sets up the library. Connects to Postgres, prepares internal state, and enables other functions. Must be called before doing anything else.

auth.Create_space() error - Creates a new space with the given name. Authority determines control level for the space. Fails if space already exists or Init() was not called.

auth.Delete_space() - Deletes the space with the specified name. Removes all associated permissions. Fails if space does not exist or Init() was not called.

auth.Create_permissions() - Assigns a role to a user in a specific space. Roles define what the user can do in that space. Fails if space or user does not exist.

auth.Delete_permissions() - Removes a user's role in a specific space. After this, the user loses access according to that role. Fails if user or space does not exist.


You can also handle users with
auth.Register_user(),
auth.Login_user() and auth.Delete_user().

For roles, use auth.Create_role() and
auth.Delete_roles().
