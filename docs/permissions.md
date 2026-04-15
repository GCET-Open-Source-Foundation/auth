#**permissions.go**
This section explains the permission-related methods in the auth package. These methods are used to create, check, and delete permissions.

**CreatePermissions**
``` go
func (a *Auth) CreatePermissions(username, spaceName, role string) error {
```
The function verifies that the database connection is initialized,
If the database connection does not exist, the function reports an error with the message
"run auth.Init() first as a function outside API calls”

If the database shows any error, it is stored in ‘_, err’.
 
The function executes a SQL command to add a new row in the permissions table. The values ‘$1, $2, $3’ are replaced by username, spaceName and role respectively.
```go
_, err := a.Conn.Exec(
		context.Background(),
		"INSERT INTO permissions(user_id, spaceName, role) VALUES ($1, $2, $3)",
		username, spaceName, role,
	)
```
If there is any error, the function returns the error previously stored in ‘err’, Otherwise it returns nil. 
```go
if err != nil {
		return err
	}

	return nil
}
```

**CheckPermissions**
```go
func (a *Auth) CheckPermissions(username, spaceName, role string) bool
```
The function returns true if the user has the specified role in the
specified  space and returns false if the user does not have the role in the space or if the database connection is not initialized. 

```go
a.Conn == nil {
    return false
}
```
A SQL Command is executed to check if there is atleast one row that meets the following requirements
(i) username = $1
(ii) spaceName = $2
(iii) role = $3
``` go
query := `
		SELECT EXISTS (
			SELECT 1
			FROM permissions 
			WHERE user_id = $1
			AND spaceName = $2
			AND role = $3
		)
```

The function returns true if there is a row matching the requirements and false if there is no such row in the permissions table.

The function executes the SQL query, executes it with the values $1, $2, $3 and stores the result of this query in the address of the variable ‘exists’. 
err := a.Conn.QueryRow(context.Background(), query, username, spaceName, role).Scan(&exists)

If the query fails the function returns false otherwise it returns the result stored in ‘exists’.

```go
if err != nil {
		return false
	}

	return exists
}
```

**Delete_permissions**
```go
func (a *Auth) DeletePermission(username, spaceName, role string) error
```
The function verifies if the database connection exists, if there is no connection an error is reported with the message
"run auth.Init() first as a function outside API calls"

The function executes a SQL Command to remove a row with the following requirements from the permissions table
(i) username = $1
(ii) spaceName = $2
(iii) role = $3

```go
             query := `
		DELETE FROM permissions
		WHERE user_id = $1
		AND spaceName = $2
		AND role = $3 
```
The function executes the SQL command, stores any error that occurs while executing in the variable ‘err’. If there is any error, the function returns the error stored, otherwise the deletion completes successfully and returns nil.

```go
_, err := a.Conn.Exec(context.Background(), query, username, spaceName, role)
 if err != nil {
		return err
	}

	return nil
}
```
return nil indicates that the deletion is successful.
