package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/go-uuid"
)

const aesKeySize = 32

type AESCipher struct {
	gcm      cipher.AEAD
	KeyBytes []byte
}

func NewAESCipher(keyBytes []byte) (AESCipher, error) {
	if keyBytes == nil {
		var err error
		if keyBytes, err = uuid.GenerateRandomBytes(aesKeySize); err != nil {
			return AESCipher{}, errors.New("fail to generate a new random AES key")
		}
	}

	// Using AES-256 GCM mode
	aesCipher, aesError := aes.NewCipher(keyBytes)
	if aesError != nil {
		return AESCipher{}, errors.New("fail to generate AES cipher")
	}

	gcmCipher, gcmError := cipher.NewGCM(aesCipher)
	if gcmError != nil {
		return AESCipher{}, errors.New("fail to use GCM mode")
	}

	return AESCipher{gcmCipher, keyBytes}, nil
}

func (cipher *AESCipher) Encrypt(src string) (string, error) {
	textBytes := []byte(src)

	nonce, nonceError := uuid.GenerateRandomBytes(cipher.gcm.NonceSize())
	if nonceError != nil {
		return "", errors.New("fail to generate a random nonce")
	}

	encryptedBytes := cipher.gcm.Seal(nonce, nonce, textBytes, nil)
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func (cipher *AESCipher) Decrypt(src string) (string, error) {
	textBytes, decodeError := base64.StdEncoding.DecodeString(src)
	if decodeError != nil {
		return "", decodeError
	}

	nonceSize := cipher.gcm.NonceSize()
	nonce, text := textBytes[:nonceSize], textBytes[nonceSize:]

	decryptedBytes, decryptionError := cipher.gcm.Open(nil, nonce, text, nil)
	if decryptionError != nil {
		return "", decryptionError
	}
	return string(decryptedBytes), nil
}
