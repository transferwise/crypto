package des

import (
	"crypto/des"
	"encoding/hex"
	"errors"
)

func CreateFromDESKeyBytes(keyBytes []byte) (DESCipher, error) {
	if len(keyBytes) != 8 {
		return DESCipher{}, errors.New("DES key must be 8 bytes")
	}

	keyBlock, err := des.NewCipher(keyBytes)
	if err != nil {
		return DESCipher{}, errors.New("invalid DES keyBlock")
	}
	return DESCipher{keyBlock, keyBytes}, nil
}

func CreateFromDESKeyString(key string) (DESCipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return DESCipher{}, errors.New("DES key is not in correct hex format")
	}
	return CreateFromDESKeyBytes(keyBytes)
}

func CreateFromTripleDESKeyBytes(keyBytes []byte) (DESCipher, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 24 {
		return DESCipher{}, errors.New("3DES key must be either 16 or 24 bytes")
	}

	if len(keyBytes) == 16 {
		keyBytes = append(keyBytes[0:16], keyBytes[0:8]...)
	}

	keyBlock, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		return DESCipher{}, errors.New("invalid 3DES keyBlock")
	}
	return DESCipher{keyBlock, keyBytes}, nil
}

func CreateFromTripleDESKeyString(key string) (DESCipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return DESCipher{}, errors.New("3DES key is not in correct hex format")
	}
	return CreateFromTripleDESKeyBytes(keyBytes)
}
