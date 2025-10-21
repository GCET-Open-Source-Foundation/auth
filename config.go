package auth

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
)

var secretKey []byte

func init() {
	loadOrCreateSecretKey()
}

func loadOrCreateSecretKey() {
	secretPath := filepath.Join(".", ".auth_secret")

	// If file exists, read existing key
	if data, err := os.ReadFile(secretPath); err == nil {
		secretKey = data
		return
	}

	// Otherwise, generate new random 256-bit key
	newKey := make([]byte, 32)
	_, err := rand.Read(newKey)
	if err != nil {
		log.Fatalf("[auth] failed to generate secret key: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(newKey)
	err = os.WriteFile(secretPath, []byte(encoded), 0600)
	if err != nil {
		log.Fatalf("[auth] failed to save secret key: %v", err)
	}

	secretKey = []byte(encoded)
	log.Println("[auth] Generated new secret key and stored in .auth_secret")
}
