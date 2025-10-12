package auth

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/argon2"
)

type argon_parameters struct {
	time    uint32 /* number of iterations */
	memory  uint32 /* in KB */
	threads uint8
	keyLen  uint32
}

/*
Recommended default values
*/
var global_default_argon = argon_parameters{
	time:    3,
	memory:  64 * 1024,
	threads: 4,
	keyLen:  32,
}

/*
A secret pepper, only stored in memory.
*/
var pepper string

/*
A global variable to know if there is a pepper present,
This is configured in the Pepper_init() func.

This is again tricky to use, please keep a single pepper and also do not
lose your pepper value.
*/

var is_pepper_present bool = false

/*
A function that is not generally recommended to use unless the user have the technically knowledge.
But incase you want to use this, please ensure this is used before any API is validated.
*/
func Default_salt_parameters(time uint32, memory uint32, threads uint8, keyLen uint32) error {
	/*
		Some securtiy measures we ensure, this doesn't allow you to shoot yourself in foot completely
	*/
	if time == 0 {
		return fmt.Errorf("time (iterations) cannot be zero")
	}
	if memory < 8*1024 {
		return fmt.Errorf("memory too low: must be at least 8MB")
	}
	if threads == 0 {
		return fmt.Errorf("threads cannot be zero")
	}
	if keyLen < 16 {
		return fmt.Errorf("key length too small: must be at least 16 bytes")
	}

	global_default_argon.time = time
	global_default_argon.memory = memory
	global_default_argon.threads = threads
	global_default_argon.keyLen = keyLen

	return nil
}

/*
This function should be stricly called in the global call and not between some
random Register API.

Because we only use is_pepper_present() to check, and once the program ends, we free the memory
so therefore, we need to always send the pepper first directly after calling auth.Init().
*/
func Pepper_init(pep string) error {
	if pep == "" {
		return fmt.Errorf("pepper cannot be empty")
	}

	pepper = pep
	is_pepper_present = true
	return nil
}

/*
Although the library holds a lot of control of the functions we are making public.
It does make sense to make a hashing functions specially something that takes a
string and returns an argron2 string public. This is a basic functionality any library should have.

This returns the hashes string and the generated salt.
*/
func Hash_password(password, salt string) string {
	/*
		Screwups are real danger here, imagine some people use
		Pepper_init() in an API call...
		And not globally...

		That's dangerous

		But this is what we could get done for now,
		any fix ups here are welcome.
	*/
	if is_pepper_present {
		password += pepper
	}
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)
	if len(saltBytes) < 16 {
		log.Printf("Warning: salt length is unusually short (%d bytes). Recommended >= 16 bytes.", len(saltBytes))
	}

	hash := argon2.IDKey(passwordBytes, saltBytes, uint32(global_default_argon.time), global_default_argon.memory, global_default_argon.threads, global_default_argon.keyLen)

	return hex.EncodeToString(hash)
}

func compare_passwords(password, salt, storedHash string) bool {
	newHash := Hash_password(password, salt)

	return subtle.ConstantTimeCompare([]byte(newHash), []byte(storedHash)) == 1
}
