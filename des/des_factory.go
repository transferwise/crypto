// Package des provides wrapper methods on top of the DES cipher for our own usage
package des

import (
	"crypto/des"
	"encoding/hex"
	"errors"
)

func CreateFromDESKeyBytes(keyBytes []byte) (Cipher, error) {
	if len(keyBytes) != 8 {
		return Cipher{}, errors.New("DES key must be 8 bytes")
	}

	keyBlock, err := des.NewCipher(keyBytes)
	if err != nil {
		return Cipher{}, errors.New("invalid DES keyBlock")
	}
	return Cipher{keyBlock, keyBytes}, nil
}

func CreateFromDESKeyString(key string) (Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return Cipher{}, errors.New("DES key is not in correct hex format")
	}
	return CreateFromDESKeyBytes(keyBytes)
}

func CreateFromTripleDESKeyBytes(keyBytes []byte) (Cipher, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 24 {
		return Cipher{}, errors.New("3DES key must be either 16 or 24 bytes")
	}

	if len(keyBytes) == 16 {
		keyBytes = append(keyBytes[0:16], keyBytes[0:8]...)
	}

	keyBlock, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		return Cipher{}, errors.New("invalid 3DES keyBlock")
	}
	return Cipher{keyBlock, keyBytes}, nil
}

func CreateFromTripleDESKeyString(key string) (Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return Cipher{}, errors.New("3DES key is not in correct hex format")
	}
	return CreateFromTripleDESKeyBytes(keyBytes)
}
