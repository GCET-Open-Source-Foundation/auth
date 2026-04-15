package auth

import (
	"context"
	"fmt"
)

func (a *Auth) CreateRole(name string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
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
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
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
