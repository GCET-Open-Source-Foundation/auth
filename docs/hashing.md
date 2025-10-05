This library uses Argon2 to hash and store passwords.

The default parameters are set automatically when you initialize the library. If you want to change the hashing defaults, you have to do that before any data is already present in the database, the function will check if any data is present in users or not, if you try to force it to setup different parameters in between, We hope you know what you are doing, or you may encounter unexpected problems.

To access the hashing parameters, you can call `auth.Default_salt_parameters()`.

Salts are generated randomly and stored in the users database. This is safe and has been battle-tested; many people use this approach.

If you want to add a pepper, like a global pepper, you need to be very careful because losing the pepper will make all stored passwords unusable.

To use a secret pepper, you can call the `Pepper_init()` function. Make sure to store your secret key somewhere safe, because the library stores it in memory and frees it once the program is executed and does not manage your secret keys.

The pepper feature is completely optional. The global `pepper_available` boolean variable is used to check if a pepper is present. If it is not, the library will skip the pepper functionality entirely.

This is all related to hashing in authentication.
