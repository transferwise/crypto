// Package aes provides wrapper methods on top of the AES GCM cipher for our own usage
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/go-uuid"
)

const keySize = 32

// Cipher is wrapper of the AES GCM cipher and stores the raw key bytes
type Cipher struct {
	gcm      cipher.AEAD
	KeyBytes []byte
}

// New constructs a new AES GCM cipher using the raw key bytes provided, it will generate
// a random key if the input raw key bytes is nil
func New(keyBytes []byte) (Cipher, error) {
	var err error

	if keyBytes == nil {
		if keyBytes, err = uuid.GenerateRandomBytes(keySize); err != nil {
			return Cipher{}, errors.New("fail to generate random key bytes")
		}
	}

	aesCipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return Cipher{}, errors.New("fail to create AES cipher")
	}

	// Using GCM mode
	gcmCipher, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return Cipher{}, errors.New("fail to use GCM mode")
	}

	return Cipher{gcmCipher, keyBytes}, nil
}

func (cipher *Cipher) Encrypt(src string) (string, error) {
	textBytes := []byte(src)

	nonce, err := uuid.GenerateRandomBytes(cipher.gcm.NonceSize())
	if err != nil {
		return "", errors.New("fail to generate nonce")
	}

	encryptedBytes := cipher.gcm.Seal(nonce, nonce, textBytes, nil)
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func (cipher *Cipher) Decrypt(src string) (string, error) {
	textBytes, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}

	nonceSize := cipher.gcm.NonceSize()
	nonce, text := textBytes[:nonceSize], textBytes[nonceSize:]

	decryptedBytes, err := cipher.gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}
