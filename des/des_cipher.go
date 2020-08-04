package des

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var keyCheckValuePlainText8Bytes = []byte{0, 0, 0, 0, 0, 0, 0, 0}

// Cipher is wrapper of the DES or 3DES cipher and stores the raw key bytes
type Cipher struct {
	KeyBlock cipher.Block
	KeyBytes []byte
}

func (cipher *Cipher) Encrypt(plainBytes []byte) ([]byte, error) {
	blockSize := cipher.KeyBlock.BlockSize()
	if len(plainBytes)%blockSize != 0 {
		return nil, fmt.Errorf("input length %d is not a multiplier of block size %d", len(plainBytes), blockSize)
	}

	cipherBytes := make([]byte, len(plainBytes))
	for start := 0; start+blockSize <= len(plainBytes); start += blockSize {
		cipher.KeyBlock.Encrypt(cipherBytes[start:], plainBytes[start:])
	}
	return cipherBytes, nil
}

func (cipher *Cipher) EncryptHex(plaintext string) ([]byte, error) {
	plainBytes, err := hex.DecodeString(plaintext)
	if err != nil {
		return nil, errors.New("input is not in correct hex format")
	}
	return cipher.Encrypt(plainBytes)
}

func (cipher *Cipher) Decrypt(cipherBytes []byte) ([]byte, error) {
	blockSize := cipher.KeyBlock.BlockSize()
	if len(cipherBytes)%blockSize != 0 {
		return nil, fmt.Errorf("input length %d is not a multiplier of block size %d", len(cipherBytes), blockSize)
	}

	plainBytes := make([]byte, len(cipherBytes))
	for start := 0; start+blockSize <= len(cipherBytes); start += blockSize {
		cipher.KeyBlock.Decrypt(plainBytes[start:], cipherBytes[start:])
	}
	return plainBytes, nil
}

func (cipher *Cipher) DecryptHex(ciphertext string) ([]byte, error) {
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, errors.New("input is not in correct hex format")
	}
	return cipher.Decrypt(cipherBytes)
}

func (cipher *Cipher) VerifyCheckValue(checkValue string) bool {
	cipherBytes, err := cipher.Encrypt(keyCheckValuePlainText8Bytes)
	if err != nil {
		return false
	}
	derivedCheckValue := hex.EncodeToString(cipherBytes[:3])
	return strings.EqualFold(derivedCheckValue, checkValue)
}
