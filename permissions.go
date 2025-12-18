package auth

import (
	"context"
	"fmt"
)

func (a *Auth) Create_permissions(username, space_name, role string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.Conn.Exec(
		context.Background(),
		"INSERT INTO permissions(user_id, space_name, role) VALUES ($1, $2, $3)",
		username, space_name, role,
	)

	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) Check_permissions(username, space_name, role string) bool {
	if a.Conn == nil {
		return false
	}

	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM permissions 
			WHERE user_id = $1
			AND space_name = $2
			AND role = $3
		)
	`

	err := a.Conn.QueryRow(context.Background(), query, username, space_name, role).Scan(&exists)
	if err != nil {
		return false
	}

	return exists
}

func (a *Auth) Delete_permission(username, space_name, role string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	query := `
		DELETE FROM permissions
		WHERE user_id = $1
		AND space_name = $2
		AND role = $3
	`

	_, err := a.Conn.Exec(context.Background(), query, username, space_name, role)

	if err != nil {
		return err
	}

	return nil
}
