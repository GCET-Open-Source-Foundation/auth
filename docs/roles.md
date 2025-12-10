# **roles.go** 
This section documents the role-related methods in the Auth struct. These functions allow creating and deleting roles in the system.
Create_role(name string) error
Creates a new role in the system.
Parameters:
 name – The name of the role to be created.
Behavior:
 Inserts a new entry into the roles table.
 Returns an error if the database connection is not initialized or if the insert operation fails.
 ```go
func (a *Auth) Create_role(name string) error {
	if a.conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.conn.Exec(context.Background(),
		"INSERT INTO roles(role) VALUES ($1)",
		name,
	)

	if err != nil {
		return err
	}

	return nil
}
```
Delete_role(name string) error
Deletes an existing role from the system.
Parameters:
 name – The name of the role to be removed.
Behavior:
 Deletes the matching entry from the roles table.
 Returns an error if the database connection is not initialized or if the delete operation fails.
```go
func (a *Auth) Delete_role(name string) error {
	if a.conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.conn.Exec(
		context.Background(),
		"DELETE FROM roles WHERE role = $1",
		name,
	)

	if err != nil {
		return err
	}

	return nil
}
```

