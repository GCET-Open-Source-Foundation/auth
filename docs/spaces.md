# **spaces.go**


Space Management
These methods manage "Spaces," which typically represent permission scopes, tenant identifiers, or organizational units within the application.

func (*Auth) Create_space
```Go

func (a *Auth) Create_space(name string, authority int) error
```
Description: Creates a new record in the spaces table. This is used to define a new scope or group within the authentication system.

Parameters:

name (string): The unique name or identifier for the space (e.g., "admin_panel", "user_dashboard").

authority (int): An integer representing the permission level, rank, or specific authority ID associated with this space.

Returns:

error: Returns an error if:

The Auth library has not been initialized via Init() (connection is nil).

The database operation fails (e.g., connection timeout, syntax error, or constraint violation such as a duplicate space name).

Internal Behavior:

Verifies that the database connection (a.conn) is active.

Executes an SQL INSERT statement using context.Background().

Example:

```Go

// Create a space named "moderators" with authority level 2
err := appAuth.Create_space("moderators", 2)
if err != nil {
    log.Printf("Error creating space: %v", err)
}
```
func (*Auth) Delete_space
```Go

func (a *Auth) Delete_space(name string) error
```
Description: Permanently removes a space from the spaces table based on its name.

Parameters:

name (string): The name of the space to be deleted.

Returns:

error: Returns an error if:

The Auth library has not been initialized.

The database execution fails.

Note: This operation executes a hard delete. If other tables reference the spaces table via foreign keys without ON DELETE CASCADE, this operation may fail due to referential integrity constraints.

Example:

```Go

// Remove the "legacy_users" space
err := appAuth.Delete_space("legacy_users")
if err != nil {
    log.Printf("Error deleting space: %v", err)
}
```

