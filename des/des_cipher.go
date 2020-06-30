package des

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var keyCheckValuePlainText8Bytes = []byte{0, 0, 0, 0, 0, 0, 0, 0}

type DESCipher struct {
	KeyBlock cipher.Block
	KeyBytes []byte
}

func (cipher *DESCipher) Encrypt(src []byte) ([]byte, error) {
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

func (cipher *DESCipher) EncryptHex(src string) ([]byte, error) {
	bytes, error := hex.DecodeString(src)
	if error != nil {
		return nil, errors.New("input is not in correct hex format")
	}
	return cipher.Encrypt(bytes)
}

func (cipher *DESCipher) Decrypt(src []byte) ([]byte, error) {
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

func (cipher *DESCipher) DecryptHex(src string) ([]byte, error) {
	bytes, error := hex.DecodeString(src)
	if error != nil {
		return nil, errors.New("input is not in correct hex format")
	}
	return cipher.Decrypt(bytes)
}

func (cipher *DESCipher) VerifyCheckValue(checkValue string) bool {
	encryptedBytes, err := cipher.Encrypt(keyCheckValuePlainText8Bytes)
	if err != nil {
		return false
	}
	derivedCheckValue := hex.EncodeToString(encryptedBytes[:3])
	return strings.EqualFold(derivedCheckValue, checkValue)
}
