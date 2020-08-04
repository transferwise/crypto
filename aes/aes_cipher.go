// Package aes provides wrapper methods on top of the AES GCM cipher for our own usage
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/go-uuid"
)

// Cipher is wrapper of the AES GCM cipher and stores the raw key bytes
type Cipher struct {
	gcm      cipher.AEAD
	KeyBytes []byte
}

// New constructs a new AES GCM cipher using the raw key bytes provided, the raw bytes must be
// either 16, 24, or 32 bytes
func New(keyBytes []byte) (Cipher, error) {
	var err error

	// Setup the cipher
	aesCipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return Cipher{}, err
	}

	// Setup the GCM
	gcmCipher, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return Cipher{}, err
	}

	return Cipher{gcmCipher, keyBytes}, nil
}

// Encrypt takes the UTF-8 encoded plaintext and output Base64 encoded cipher text
func (cipher *Cipher) Encrypt(plaintext string) (string, error) {
	plainBytes := []byte(plaintext)

	nonce, err := uuid.GenerateRandomBytes(cipher.gcm.NonceSize())
	if err != nil {
		return "", errors.New("fail to generate nonce")
	}

	// Prefix nonce to the cipher text
	cipherBytes := cipher.gcm.Seal(nonce, nonce, plainBytes, nil)
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// Decrypt takes the Base64 encoded cipher text and output UTF-8 encoded plaintext
func (cipher *Cipher) Decrypt(ciphertext string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := cipher.gcm.NonceSize()
	nonce, cipherBytesWithoutNonce := cipherBytes[:nonceSize], cipherBytes[nonceSize:]

	plainBytes, err := cipher.gcm.Open(nil, nonce, cipherBytesWithoutNonce, nil)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}
