package auth

import (
	"context"
	"fmt"
)

func (a *Auth) CreatePermissions(username, spaceName, role string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.Conn.Exec(
		context.Background(),
		"INSERT INTO permissions(user_id, spaceName, role) VALUES ($1, $2, $3)",
		username, spaceName, role,
	)

	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) CheckPermissions(username, spaceName, role string) bool {
	if a.Conn == nil {
		return false
	}

	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM permissions 
			WHERE user_id = $1
			AND spaceName = $2
			AND role = $3
		)
	`

	err := a.Conn.QueryRow(context.Background(), query, username, spaceName, role).Scan(&exists)
	if err != nil {
		return false
	}

	return exists
}

func (a *Auth) DeletePermission(username, spaceName, role string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	query := `
		DELETE FROM permissions
		WHERE user_id = $1
		AND spaceName = $2
		AND role = $3
	`

	_, err := a.Conn.Exec(context.Background(), query, username, spaceName, role)

	if err != nil {
		return err
	}

	return nil
}
