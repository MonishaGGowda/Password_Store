package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"encoding/json"
	"golang.org/x/crypto/scrypt"
)

// Vault structure to hold encrypted passwords
type Vault struct {
	Passwords map[string]string
}

// Derive a key from a master password
func deriveKey(password string) []byte {
	salt := []byte("random_salt") // In production, store this securely
	key, _ := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	return key
}

// Encrypt data
func encrypt(data, password string) string {
	block, _ := aes.NewCipher(deriveKey(password))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Decrypt data
func decrypt(encryptedData, password string) string {
	data, _ := base64.StdEncoding.DecodeString(encryptedData)
	block, _ := aes.NewCipher(deriveKey(password))
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)
	return string(plaintext)
}

// Load vault
func loadVault(filename string) Vault {
	file, err := os.ReadFile(filename)
	if err != nil {
		return Vault{Passwords: make(map[string]string)}
	}
	var vault Vault
	json.Unmarshal(file, &vault)
	return vault
}

// Save vault
func saveVault(vault Vault, filename string) {
	data, _ := json.Marshal(vault)
	os.WriteFile(filename, data, 0600)
}

// Add a password
func addPassword(service, password, master string, vault Vault, filename string) {
	vault.Passwords[service] = encrypt(password, master)
	saveVault(vault, filename)
	fmt.Println("Password saved successfully!")
}

// Retrieve a password
func getPassword(service, master string, vault Vault) {
	if encrypted, found := vault.Passwords[service]; found {
		fmt.Println("Decrypted Password:", decrypt(encrypted, master))
	} else {
		fmt.Println("Service not found in vault!")
	}
}

// CLI Interface
func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  vault add <service> <password>  - Store a password")
		fmt.Println("  vault get <service>             - Retrieve a password")
		return
	}

	command := os.Args[1]
	service := os.Args[2]
	vaultFile := "vault.db"
	vault := loadVault(vaultFile)

	fmt.Print("Enter master password: ")
	var masterPassword string
	fmt.Scanln(&masterPassword)

	switch command {
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Usage: vault add <service> <password>")
			return
		}
		password := os.Args[3]
		addPassword(service, password, masterPassword, vault, vaultFile)

	case "get":
		getPassword(service, masterPassword, vault)

	default:
		fmt.Println("Unknown command!")
	}
}
