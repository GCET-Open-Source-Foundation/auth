#**spaces.go**

Before reading this, it is suggested to go through the 2 functions: create_spaces and check_spaces from database.go.
A space is a logical boundary used to group data, users, and rules under a single context. It helps define where actions apply and who is allowed to perform them, instead of relying on hard coded, global permissions. By assigning an authority level to each space, the system can make permission decisions in a clean, data driven way. This makes the application easier to scale, safer to manage, and flexible enough to add new roles or contexts without changing code.

This document explains the purpose and behavior of the Create_space and Delete_space methods. These methods are responsible for managing records in the spaces table.

**Create_space**
It creates a new space entry in the database with a name and authority level and checks whether the database connection is initialized. Then it inserts a new row into the spaces table.
In case of a successful insert i.e when there is no duplicate space name and a database connection is already initialised, the database accepts the row and no error takes place.
In case a duplicate space name is given, Postgres rejects it because space_name is a primary key.
And in case the database is not initialised, no database operation happens at all. An error message "run auth.Init() first as a function outside API calls" returns.

**Delete_space**
This works almost in the same way, but it takes the space name to be deleted.
In case of a successful deletion, if the database connection exists, it runs SQL and the row is deleted.
In case the given space does not exist, SQL still runs successfully but no row gets affected. This is not treated as an error, and no error is returned — the deletion silently succeeds.












