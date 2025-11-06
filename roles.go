package auth

import (
	"context"
	"fmt"
)

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
