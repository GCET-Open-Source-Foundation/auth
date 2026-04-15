package auth

import (
	"context"
	"fmt"
)

func (a *Auth) CreateSpace(name string, authority int) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.Conn.Exec(context.Background(),
		"INSERT INTO spaces(spaceName, authority) VALUES ($1, $2)",
		name, authority,
	)

	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) DeleteSpace(name string) error {
	if a.Conn == nil {
		return fmt.Errorf("run auth.Init() first as a function outside API calls")
	}

	_, err := a.Conn.Exec(
		context.Background(),
		"DELETE FROM spaces WHERE spaceName = $1",
		name,
	)

	if err != nil {
		return err
	}

	return nil
}
