package auth

import (
	"context"
)

func (a *Auth) CreateRole(name string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	_, err := a.Conn.Exec(context.Background(),
		"INSERT INTO roles(role) VALUES ($1)",
		name,
	)

	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) DeleteRole(name string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	_, err := a.Conn.Exec(
		context.Background(),
		"DELETE FROM roles WHERE role = $1",
		name,
	)

	if err != nil {
		return err
	}

	return nil
}
