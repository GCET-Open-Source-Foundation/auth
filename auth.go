package auth

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

/*
db_details is a type, where any database details
can be held, and the global var right below this
is used at Init func to define a main db here.
*/
type db_details struct {
	port          uint16
	username      string
	password      string
	database_name string
}

/*
We do not allow external accses of the global var.
There might be unexpected errors if we let others edit
the db details.
*/
var global db_details

/*
The init_check acts as a guardrail and nothing more than that.
We can easily do if Conn == nil {} and get the details, but this
forms like a just in case variable.
*/
var init_check bool = false

/*
global database connection variable
*/
var conn *pgxpool.Pool

/*
Init configures the global db_details, connects to the database,
and sets db_check_global if successful.
*/
func Init(port uint16, db_user, db_pass, db_name string) error {
	global.port = port
	global.username = db_user
	global.password = db_pass
	global.database_name = db_name

	pool, err := db_connect(&global)
	if err != nil {
		return fmt.Errorf("db connect failed: %w", err)
	}
	if pool == nil {
		return fmt.Errorf("db connect returned nil connection")
	}

	/* No errors in init */
	conn = pool
	init_check = true
	return nil
}
