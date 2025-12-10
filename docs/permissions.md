# **permissions.go**
Permissions Management (Auth Package)
This section documents the permission-related methods provided by the Auth struct. These functions allow creating, checking, and deleting user permissions for specific spaces and roles.
Create_permissions(username, space_name, role string) error
Creates a new permission entry for a user.
Parameters:
 username – The user identifier
 space_name – The name of the space in which the permission applies
 role – The role assigned to the user within the space
Behavior:
 Inserts a new record into the permissions table.
 Returns an error if the database connection is not initialized or if the insert operation fails.
 ```go
func (a *Auth) Create_permissions(username, space_name, role string) error {
	if a.conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.conn.Exec(
		context.Background(),
		"INSERT INTO permissions(user_id, space_name, role) VALUES ($1, $2 $3)",
		username, space_name, role,
	)

	if err != nil {
		return err
	}

	return nil
}
```
Check_permissions(username, space_name, role string) bool
Checks whether a user has a specific role in a given space.
Parameters:
 username – The user identifier
 space_name – The space to check against
 role – The role to verify
Behavior:
 Queries the permissions table to check whether a matching entry exists.
 Returns true if the permission exists.
 Returns false if the permission does not exist, the connection is not initialized, or the query fails.
 ```go
func (a *Auth) Check_permissions(username, space_name, role string) bool {
	if a.conn == nil {
		return false
	}

	var exists bool
	query :=  `SELECT EXISTS (
			SELECT 1
			FROM permissions 
			WHERE user_id = $1
			AND space_name = $2
			AND role = $3
		)
	`

	err := a.conn.QueryRow(context.Background(), query, username, space_name, role).Scan(&exists)
	if err != nil {
		return false
	}

	return exists
}
```
Delete_permission(username, space_name, role string) error
Deletes a permission entry for a user.
Parameters:
 username – The user identifier
 space_name – The target space
 role – The role to remove
Behavior:
 Removes the matching entry from the permissions table.
 Returns an error if the connection is not initialized or if the delete operation fails.
 ```go
func (a *Auth) Delete_permission(username, space_name, role string) error {
	if a.conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	query := `
		DELETE FROM permissions
		WHERE user_id = $1
		AND space_name = $2
		AND role = $3
	`

	_, err := a.conn.Exec(context.Background(), query, username, space_name, role)

	if err != nil {
		return err
	}

	return nil
}
```


