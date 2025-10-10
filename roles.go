package auth

import (
	"context"
	"fmt"
)

func Create_role(name string) error {
	if !init_check {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := conn.Exec(context.Background(),
		"INSERT INTO roles(role) VALUES ($1)",
		name,
	)

	if err != nil {
		return err
	}

	return nil
}

func Delete_role(name string) error {
	if !init_check {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := conn.Exec(
		context.Background(),
		"DELETE FROM roles WHERE role = $1",
		name,
	)
	
	if err != nil {
		return err
	}

	return nil
}
