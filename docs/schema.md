The spaces has the following schema

It has the space name of course
and it has the authority level, the more the number the bigger the authority is.

So a string and an int
Note here that, the permission numbers are not unique, but the space name is ofcourse unique.

```
CREATE TABLE spaces (
        space_name TEXT PRIMARY KEY,
        authority INTEGER NOT NULL
);
```

This way the space table exists now and stores the spaces, these spaces should be carefully planned before giving the permission numbers if that is what the application depends on completely.

Coming to the users table, this has multiple info.

One the unique user id ofcourse, and the password they would store.
This can be further compliemented by the Register/Login API itself.

And this unique id be email or phone number that's their wish, and this library
has no single way to reject something that is being inserted in the database, bacause everyone has different preferences, and it should be complimenting accordingly.

The second row however, stores password which is hashed by argon2. We choose argon2 because it is tried and tested and has the best outcome so far.

And we store no other info, because it just slows things down.

```
CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
);
```

Once the users are here there are few more things we should handle.
Roles and permissions are the two things we should handle now.

roles table is something which has all the roles. Now this table only needs a unique string that's it, and has no need of any other data.

```
CREATE TABLE roles (
        role TEXT PRIMARY KEY,
);
```

Now this role can be anything, say super admin.

Now these roles in itself do not mean anything unless the user adds all of these in permissions.

The permissions table has, username, spaces and role.
Only the user which has a role in that space is entered in the permissions table.

```
CREATE TABLE permissions (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    space_name TEXT NOT NULL REFERENCES spaces(space_name) ON DELETE CASCADE,
    role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
    PRIMARY KEY (user_id, space_name, role)
);
```

We are adding ON DELETE CASCADE here, because we need consistency of course.

That's about it, the more things we add, the more complicated it is gonna get,
so let's keep it minimal and complimenting to the people who build APIs.

The table permission can be sharded too again if you reach at good enough volumes you probably can contact us, again it's flexible enough for the API user to use this library in ways which can help the permissions table shard,
the most important table here would be the permissions table.