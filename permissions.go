package auth

import (
)

func (a *Auth) CreatePermissions(username, spaceName, role string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	_, err := a.Conn.Exec(
		a.ctx,
		"INSERT INTO permissions(user_id, spaceName, role) VALUES ($1, $2, $3)",
		username, spaceName, role,
	)

	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) CheckPermissions(username, spaceName, role string) error {
	if a.Conn == nil {
		return ErrNotInitialized
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

	err := a.Conn.QueryRow(a.ctx, query, username, spaceName, role).Scan(&exists)
	if err != nil {
		return ErrDatabaseUnavailable
	}

	if !exists {
		return ErrInvalidCredentials
	}

	return nil
}

func (a *Auth) DeletePermission(username, spaceName, role string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	query := `
		DELETE FROM permissions
		WHERE user_id = $1
		AND spaceName = $2
		AND role = $3
	`

	_, err := a.Conn.Exec(a.ctx, query, username, spaceName, role)

	if err != nil {
		return err
	}

	return nil
}
