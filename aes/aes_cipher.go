// Package aes provides wrapper methods on top of the AES GCM cipher for our own usage
package aes

import (
	"crypto/aes"
	"crypto/cipher"
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

// Encrypt takes plain bytes and output cipher bytes, the nonce will be prefixed to
// cipher bytes if prefixNonce is true.
func (cipher *Cipher) Encrypt(plainBytes []byte, prefixNonce bool) ([]byte, []byte, error) {
	nonce, err := uuid.GenerateRandomBytes(cipher.gcm.NonceSize())
	if err != nil {
		return nil, nil, errors.New("fail to generate nonce")
	}

	cipherBytes := cipher.gcm.Seal(nil, nonce, plainBytes, nil)
	if prefixNonce {
		cipherBytes = append(nonce, cipherBytes...)
	}

	return cipherBytes, nonce, nil
}

// Decrypt takes cipher bytes and output plain bytes, it is assumed the nonce is prefixed
// to cipher bytes if its value is not being provided
func (cipher *Cipher) Decrypt(cipherBytes []byte, nonce []byte) ([]byte, error) {
	if nonce == nil {
		nonceSize := cipher.gcm.NonceSize()
		nonce, cipherBytes = cipherBytes[:nonceSize], cipherBytes[nonceSize:]
	}

	return cipher.gcm.Open(nil, nonce, cipherBytes, nil)
}
