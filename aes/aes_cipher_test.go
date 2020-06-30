package aes

import (
	"encoding/hex"
	"testing"

	"github.com/hashicorp/go-uuid"
)

func TestNewAESCipher_GenerateRandomKey(t *testing.T) {
	cipher, err := NewAESCipher(nil)
	if err != nil {
		t.Errorf("Did not expect an error but got %q", err)
	}

	if len(cipher.KeyBytes) != aesKeySize {
		t.Errorf("Expected key size %d but get %d", aesKeySize, len(cipher.KeyBytes))
	}
}

func TestNewAESCipher_UseExistingKey(t *testing.T) {
	keyBytes, _ := uuid.GenerateRandomBytes(aesKeySize)

	cipher, err := NewAESCipher(keyBytes)
	if err != nil {
		t.Errorf("Did not expect an error but got %q", err)
	}

	if hex.EncodeToString(cipher.KeyBytes) != hex.EncodeToString(keyBytes) {
		t.Errorf("Expected key %s but get %s", hex.EncodeToString(keyBytes), hex.EncodeToString(cipher.KeyBytes))
	}
}

func TestAESCipher_EncryptAndDecrypt(t *testing.T) {
	cipher, _ := NewAESCipher(nil)

	testDatas := []string{
		"my secret 1234",
		"123456789",
	}

	for _, testData := range testDatas {
		encryptedData, encryptionError := cipher.Encrypt(testData)
		if encryptionError != nil {
			t.Errorf("Did not expect an encryption error but got %q", encryptionError)
		}

		decryptedData, decryptionError := cipher.Decrypt(encryptedData)
		if decryptionError != nil {
			t.Errorf("Did not expect a decryption error but got %q", decryptionError)
		}

		if testData != decryptedData {
			t.Errorf("Expected %s but get %s", testData, decryptedData)
		}
	}
}
