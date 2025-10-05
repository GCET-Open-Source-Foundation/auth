Before you use this library, there are a few functions that should be called globally.

Luckily, most of these aren’t functions that should be configured by everyone, and are not recommended for all users to configure, unless the person has good technical understanding of what they are doing.

The functions are these:

---

1. **auth.Init()**

* Purpose: Initializes the library, sets all global variables, and validates the database schemas.
* Usage Notes:

  * Should be called globally **before using any other function**.
  * Failing to call this first may result in unexpected errors.
* Recommended For: All users. This is mandatory.

---

2. **auth.Pepper_init(pep string)**

* Purpose: Sets the global secret pepper used in password hashing.
* Usage Notes:

  * Should be called **once at startup**, immediately after `auth.Init()`.
  * Only needed if you want to enable the “pepper” feature.
  * The pepper is stored **in memory only**, never in the database.
  * Losing or changing the pepper will make all existing password hashes invalid.
* Recommended For: Advanced users who understand the risks and want extra server-side secret protection.
* Note: Not recommended for everyone.

---

3. **auth.Default_salt_parameters(time, memory, threads, keyLen)**

* Purpose: Overrides the default Argon2id hashing parameters.
* Usage Notes:

  * Should be called **once at startup**, before any registration or login operations.
  * Validates that the parameters are reasonable:

    * `time` ≥ 1
    * `memory` ≥ 8 MB
    * `threads` ≥ 1
    * `keyLen` ≥ 16 bytes
  * Only configure if you understand the performance and security trade-offs.
  * If you don’t call this function, the library will use safe defaults:

    * Time: 3 iterations
    * Memory: 64 MB
    * Threads: 4
    * KeyLen: 32 bytes
* Recommended For: Advanced users who want to tweak performance and security settings.
* Note: Not recommended for everyone.
