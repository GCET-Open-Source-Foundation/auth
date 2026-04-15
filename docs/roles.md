# **roles.go** 
This section explains the roles-related methods in the auth package. These methods are used to create and delete roles.
**CreateRole**
The function CreateRole takes the string ‘name’ as input
```go
func (a *Auth) CreateRole(name string) error
```
The function verifies that a database connection exists and if no such connection exists, an error is reported with the message

“run auth.Init() first as a function outside API calls"

A SQL command is executed to add a new row in the ‘roles’ table, the command uses a placeholder $1 which stores the value of the input variable ‘name’. Any occurred error will be stored in the variable ‘err’

```go
        _, err := a.Conn.Exec(context.Background(),
		"INSERT INTO roles(role) VALUES ($1)",
		name,
```
If any error occurs, the function returns the error stored in the variable ‘err’. Otherwise, the function returns nil.

```go
       if err != nil {
		return err
	}

	return nil
}
```
return nil indicates that the Role is created 

**DeleteRole**
The function DeleteRole takes the string ‘name’ as input

```go
func (a *Auth) DeleteRole(name string) error
 ```
The function verifies that a database connection exists and if no such connection exists, an error is reported with the message
run auth.Init() first as a function outside API calls

A SQL command is executed to remove a specific row in the ‘roles’ table. Only the role in the placeholder $1 is removed while the other roles remain untouched.  Any occurred error will be stored in the variable ‘err’.

```  go
             _, err := a.Conn.Exec(
		context.Background(),
		"DELETE FROM roles WHERE role = $1",
		name, 
```
If any error occurs, the function returns the error stored in the variable ‘err’. Otherwise, the function returns nil.

``` go 
          if err != nil {
		return err
	}

	return nil
}
```
 return nil indicates that the role is successfully removed 

