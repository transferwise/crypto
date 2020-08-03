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

func (cipher *Cipher) Encrypt(src []byte) ([]byte, error) {
	blockSize := cipher.KeyBlock.BlockSize()
	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("input length %d is not a multiplier of block size %d", len(src), blockSize)
	}

	dst := make([]byte, len(src))
	for start := 0; start+blockSize <= len(src); start += blockSize {
		cipher.KeyBlock.Encrypt(dst[start:], src[start:])
	}
	return dst, nil
}

func (cipher *Cipher) EncryptHex(src string) ([]byte, error) {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		return nil, errors.New("input is not in correct hex format")
	}
	return cipher.Encrypt(bytes)
}

func (cipher *Cipher) Decrypt(src []byte) ([]byte, error) {
	blockSize := cipher.KeyBlock.BlockSize()
	if len(src)%blockSize != 0 {
		return nil, fmt.Errorf("input length %d is not a multiplier of block size %d", len(src), blockSize)
	}

	dst := make([]byte, len(src))
	for start := 0; start+blockSize <= len(src); start += blockSize {
		cipher.KeyBlock.Decrypt(dst[start:], src[start:])
	}
	return dst, nil
}

func (cipher *Cipher) DecryptHex(src string) ([]byte, error) {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		return nil, errors.New("input is not in correct hex format")
	}
	return cipher.Decrypt(bytes)
}

func (cipher *Cipher) VerifyCheckValue(checkValue string) bool {
	encryptedBytes, err := cipher.Encrypt(keyCheckValuePlainText8Bytes)
	if err != nil {
		return false
	}
	derivedCheckValue := hex.EncodeToString(encryptedBytes[:3])
	return strings.EqualFold(derivedCheckValue, checkValue)
}
