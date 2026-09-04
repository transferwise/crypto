/*
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// NIST SP 800-38A appendix F.2 uses the same plaintext and IV for each key size.
const (
	nistIV        = "000102030405060708090a0b0c0d0e0f"
	nistPlaintext = "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
)

var nistCBCVectors = []struct {
	name       string
	key        string
	ciphertext string
}{
	{
		// F.2.1 / F.2.2 CBC-AES128
		name: "AES-128",
		key:  "2b7e151628aed2a6abf7158809cf4f3c",
		ciphertext: "7649abac8119b246cee98e9b12e9197d" +
			"5086cb9b507219ee95db113a917678b2" +
			"73bed6b8e3c1743b7116e69e22229516" +
			"3ff1caa1681fac09120eca307586e1a7",
	},
	{
		// F.2.3 / F.2.4 CBC-AES192
		name: "AES-192",
		key:  "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		ciphertext: "4f021db243bc633d7178183a9fa071e8" +
			"b4d9ada9ad7dedf4e5e738763f69145a" +
			"571b242012fb7ae07fa9baac3df102e0" +
			"08b0e27988598881d920a9e64f5615cd",
	},
	{
		// F.2.5 / F.2.6 CBC-AES256
		name: "AES-256",
		key:  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
			"9cfc4e967edb808d679f777bc6702c7d" +
			"39f23369a9d9bacfa530e26304231461" +
			"b2eb05e2c39be9fcda6c19078c6a9d1b",
	},
}

func TestAESCBCCipher_EncryptMatchesNISTVectors(t *testing.T) {
	iv, _ := hex.DecodeString(nistIV)
	plainBytes, _ := hex.DecodeString(nistPlaintext)

	for _, vector := range nistCBCVectors {
		t.Run(vector.name, func(t *testing.T) {
			cipher, err := CreateCBCFromKeyString(vector.key)
			if err != nil {
				t.Fatalf("Did not expect an error but got %q", err)
			}

			cipherBytes, err := cipher.Encrypt(plainBytes, iv)
			if err != nil {
				t.Fatalf("Did not expect an encryption error but got %q", err)
			}

			if hex.EncodeToString(cipherBytes) != vector.ciphertext {
				t.Errorf("Expected %s but get %s", vector.ciphertext, hex.EncodeToString(cipherBytes))
			}
		})
	}
}

func TestAESCBCCipher_DecryptMatchesNISTVectors(t *testing.T) {
	iv, _ := hex.DecodeString(nistIV)

	for _, vector := range nistCBCVectors {
		t.Run(vector.name, func(t *testing.T) {
			cipher, err := CreateCBCFromKeyString(vector.key)
			if err != nil {
				t.Fatalf("Did not expect an error but got %q", err)
			}
			cipherBytes, _ := hex.DecodeString(vector.ciphertext)

			plainBytes, err := cipher.Decrypt(cipherBytes, iv)
			if err != nil {
				t.Fatalf("Did not expect a decryption error but got %q", err)
			}

			if hex.EncodeToString(plainBytes) != nistPlaintext {
				t.Errorf("Expected %s but get %s", nistPlaintext, hex.EncodeToString(plainBytes))
			}
		})
	}
}

func TestAESCBCCipher_EncryptRejectsInvalidInputLength(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString(nistCBCVectors[0].key)
	iv, _ := hex.DecodeString(nistIV)

	testCases := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"one byte", 1},
		{"one byte short of a block", 15},
		{"one byte over a block", 17},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := cipher.Encrypt(make([]byte, testCase.length), iv); err == nil {
				t.Error("Expected an error but got none")
			}
			if _, err := cipher.Decrypt(make([]byte, testCase.length), iv); err == nil {
				t.Error("Expected an error but got none")
			}
		})
	}
}

func TestAESCBCCipher_RejectsInvalidIVLength(t *testing.T) {
	plainBytes, _ := hex.DecodeString(nistPlaintext)

	// An AES IV is always 16 bytes, regardless of key size.
	for _, vector := range nistCBCVectors {
		cipher, _ := CreateCBCFromKeyString(vector.key)

		for _, ivLength := range []int{0, 8, 15, 17, 24, 32} {
			iv := make([]byte, ivLength)

			if _, err := cipher.Encrypt(plainBytes, iv); err == nil {
				t.Errorf("%s: expected Encrypt to reject a %d byte IV", vector.name, ivLength)
			}
			if _, err := cipher.Decrypt(plainBytes, iv); err == nil {
				t.Errorf("%s: expected Decrypt to reject a %d byte IV", vector.name, ivLength)
			}
			if _, err := cipher.EncryptISO9797M2Padded(plainBytes, iv); err == nil {
				t.Errorf("%s: expected EncryptISO9797M2Padded to reject a %d byte IV", vector.name, ivLength)
			}
			if _, err := cipher.DecryptISO9797M2Padded(plainBytes, iv); err == nil {
				t.Errorf("%s: expected DecryptISO9797M2Padded to reject a %d byte IV", vector.name, ivLength)
			}
		}

		if _, err := cipher.Encrypt(plainBytes, nil); err == nil {
			t.Errorf("%s: expected Encrypt to reject a nil IV", vector.name)
		}
	}
}

func TestAESCBCCipher_EncryptAndDecryptISO9797M2PaddedRoundTrip(t *testing.T) {
	iv, _ := hex.DecodeString(nistIV)

	for _, vector := range nistCBCVectors {
		t.Run(vector.name, func(t *testing.T) {
			cipher, _ := CreateCBCFromKeyString(vector.key)

			// Cover both sides of two block boundaries.
			for length := 0; length <= 33; length++ {
				plainBytes := make([]byte, length)
				for i := range plainBytes {
					plainBytes[i] = byte(i)
				}

				cipherBytes, err := cipher.EncryptISO9797M2Padded(plainBytes, iv)
				if err != nil {
					t.Errorf("Did not expect an encryption error for length %d but got %q", length, err)
					continue
				}
				if len(cipherBytes)%16 != 0 || len(cipherBytes) <= length {
					t.Errorf("Expected padded ciphertext longer than %d and block aligned but get %d", length, len(cipherBytes))
				}

				decryptedBytes, err := cipher.DecryptISO9797M2Padded(cipherBytes, iv)
				if err != nil {
					t.Errorf("Did not expect a decryption error for length %d but got %q", length, err)
					continue
				}

				if !bytes.Equal(plainBytes, decryptedBytes) {
					t.Errorf("Expected %s but get %s", hex.EncodeToString(plainBytes), hex.EncodeToString(decryptedBytes))
				}
			}
		})
	}
}

// A trailing padding block must not change the preceding NIST ciphertext blocks.
func TestAESCBCCipher_EncryptISO9797M2PaddedMatchesNISTVectors(t *testing.T) {
	iv, _ := hex.DecodeString(nistIV)
	plainBytes, _ := hex.DecodeString(nistPlaintext)

	for _, vector := range nistCBCVectors {
		t.Run(vector.name, func(t *testing.T) {
			cipher, _ := CreateCBCFromKeyString(vector.key)
			expectedBytes, _ := hex.DecodeString(vector.ciphertext)

			cipherBytes, err := cipher.EncryptISO9797M2Padded(plainBytes, iv)
			if err != nil {
				t.Fatalf("Did not expect an encryption error but got %q", err)
			}

			if len(cipherBytes) != len(expectedBytes)+16 {
				t.Fatalf("Expected %d bytes of ciphertext but got %d", len(expectedBytes)+16, len(cipherBytes))
			}
			if !bytes.Equal(cipherBytes[:len(expectedBytes)], expectedBytes) {
				t.Errorf("Expected leading blocks %s but get %s", hex.EncodeToString(expectedBytes), hex.EncodeToString(cipherBytes[:len(expectedBytes)]))
			}
		})
	}
}

func TestAESCBCCipher_DecryptISO9797M2PaddedRejectsMalformedPadding(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString(nistCBCVectors[0].key)
	iv, _ := hex.DecodeString(nistIV)

	// Encrypt malformed padded plaintext to exercise the public decrypt path.
	testCases := []struct {
		name  string
		block string
	}{
		{
			name:  "final byte is neither the marker nor zero filler",
			block: "000102030405060708090a0b0c0d0e01",
		},
		{
			name:  "zero filler runs back to a non marker byte",
			block: "000102030405060708090a0b0c0d0e00",
		},
		{
			name:  "block is all zeroes so the marker is missing",
			block: "00000000000000000000000000000000",
		},
		{
			name:  "PKCS#7 padding is not accepted in place of the marker",
			block: "000102030405060708090a0b0c0d0202",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			unpaddableBlock, _ := hex.DecodeString(testCase.block)

			cipherBytes, err := cipher.Encrypt(unpaddableBlock, iv)
			if err != nil {
				t.Fatalf("Did not expect an encryption error but got %q", err)
			}

			if _, err := cipher.DecryptISO9797M2Padded(cipherBytes, iv); err == nil {
				t.Error("Expected DecryptISO9797M2Padded to reject malformed padding but got no error")
			}

			// Raw decryption does not validate padding.
			plainBytes, err := cipher.Decrypt(cipherBytes, iv)
			if err != nil {
				t.Errorf("Did not expect a raw decryption error but got %q", err)
			}
			if !bytes.Equal(plainBytes, unpaddableBlock) {
				t.Errorf("Expected %s but get %s", hex.EncodeToString(unpaddableBlock), hex.EncodeToString(plainBytes))
			}
		})
	}
}

// CBC decryption cannot detect ciphertext changes.
func TestAESCBCCipher_DecryptDoesNotDetectModifiedCiphertext(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString(nistCBCVectors[0].key)
	iv, _ := hex.DecodeString(nistIV)
	plainBytes, _ := hex.DecodeString(nistPlaintext)

	cipherBytes, err := cipher.Encrypt(plainBytes, iv)
	if err != nil {
		t.Fatalf("Did not expect an encryption error but got %q", err)
	}

	modifiedCipherBytes := cloneBytes(cipherBytes)
	modifiedCipherBytes[0] ^= 0x01

	decryptedBytes, err := cipher.Decrypt(modifiedCipherBytes, iv)
	if err != nil {
		t.Errorf("Expected a modified ciphertext to still decrypt without error but got %q", err)
	}
	if bytes.Equal(decryptedBytes, plainBytes) {
		t.Error("Expected the recovered plaintext to differ from the original")
	}
}

// Changing the IV changes the first plaintext block without invalidating padding.
func TestAESCBCCipher_DecryptISO9797M2PaddedDoesNotDetectModifiedIV(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString(nistCBCVectors[0].key)
	iv, _ := hex.DecodeString(nistIV)
	plainBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Padding occupies a separate block.
	cipherBytes, err := cipher.EncryptISO9797M2Padded(plainBytes, iv)
	if err != nil {
		t.Fatalf("Did not expect an encryption error but got %q", err)
	}

	modifiedIV := cloneBytes(iv)
	modifiedIV[0] ^= 0xff

	decryptedBytes, err := cipher.DecryptISO9797M2Padded(cipherBytes, modifiedIV)
	if err != nil {
		t.Fatalf("Expected a modified IV to still decrypt without error but got %q", err)
	}

	expectedBytes := cloneBytes(plainBytes)
	expectedBytes[0] ^= 0xff
	if !bytes.Equal(decryptedBytes, expectedBytes) {
		t.Errorf("Expected the attacker chosen plaintext %s but get %s", hex.EncodeToString(expectedBytes), hex.EncodeToString(decryptedBytes))
	}
}

func TestAESCBCCipher_DoesNotModifyInputs(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString(nistCBCVectors[0].key)
	iv, _ := hex.DecodeString(nistIV)
	plainBytes, _ := hex.DecodeString(nistPlaintext)
	cipherBytes, _ := hex.DecodeString(nistCBCVectors[0].ciphertext)
	paddedCipherBytes, _ := cipher.EncryptISO9797M2Padded(plainBytes, iv)

	operations := []struct {
		name  string
		input []byte
		run   func(input []byte, iv []byte) ([]byte, error)
	}{
		{"Encrypt", plainBytes, cipher.Encrypt},
		{"Decrypt", cipherBytes, cipher.Decrypt},
		{"EncryptISO9797M2Padded", plainBytes, cipher.EncryptISO9797M2Padded},
		{"DecryptISO9797M2Padded", paddedCipherBytes, cipher.DecryptISO9797M2Padded},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			input := cloneBytes(operation.input)
			operationIV := cloneBytes(iv)

			if _, err := operation.run(input, operationIV); err != nil {
				t.Fatalf("Did not expect an error but got %q", err)
			}

			if !bytes.Equal(input, operation.input) {
				t.Errorf("Expected input to be left as %s but get %s", hex.EncodeToString(operation.input), hex.EncodeToString(input))
			}
			if !bytes.Equal(operationIV, iv) {
				t.Errorf("Expected IV to be left as %s but get %s", hex.EncodeToString(iv), hex.EncodeToString(operationIV))
			}
		})
	}
}

func TestAESCBCCipher_DifferentIVsProduceDifferentCiphertext(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString(nistCBCVectors[0].key)
	plainBytes, _ := hex.DecodeString(nistPlaintext)

	firstIV, err := GenerateCBCIV()
	if err != nil {
		t.Fatalf("Did not expect an error but got %q", err)
	}
	secondIV, err := GenerateCBCIV()
	if err != nil {
		t.Fatalf("Did not expect an error but got %q", err)
	}

	firstCipherBytes, _ := cipher.Encrypt(plainBytes, firstIV)
	secondCipherBytes, _ := cipher.Encrypt(plainBytes, secondIV)

	if bytes.Equal(firstCipherBytes, secondCipherBytes) {
		t.Error("Expected the same plaintext under different IVs to produce different ciphertext")
	}

	for _, testCase := range []struct {
		cipherBytes []byte
		iv          []byte
	}{{firstCipherBytes, firstIV}, {secondCipherBytes, secondIV}} {
		decryptedBytes, err := cipher.Decrypt(testCase.cipherBytes, testCase.iv)
		if err != nil {
			t.Errorf("Did not expect a decryption error but got %q", err)
			continue
		}
		if !bytes.Equal(decryptedBytes, plainBytes) {
			t.Errorf("Expected %s but get %s", nistPlaintext, hex.EncodeToString(decryptedBytes))
		}
	}
}

func TestGenerateCBCIV(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 32; i++ {
		iv, err := GenerateCBCIV()
		if err != nil {
			t.Fatalf("Did not expect an error but got %q", err)
		}
		if len(iv) != 16 {
			t.Errorf("Expected a 16 byte IV but get %d", len(iv))
		}

		encodedIV := hex.EncodeToString(iv)
		if seen[encodedIV] {
			t.Errorf("Expected every generated IV to be unique but %s repeated", encodedIV)
		}
		seen[encodedIV] = true
	}
}

func TestCreateCBCFromKeyBytes(t *testing.T) {
	for _, keyLength := range []int{16, 24, 32} {
		keyBytes := make([]byte, keyLength)

		cipher, err := CreateCBCFromKeyBytes(keyBytes)
		if err != nil {
			t.Errorf("Did not expect an error for a %d byte key but got %q", keyLength, err)
			continue
		}
		if !bytes.Equal(cipher.KeyBytes, keyBytes) {
			t.Errorf("Expected key %s but get %s", hex.EncodeToString(keyBytes), hex.EncodeToString(cipher.KeyBytes))
		}
	}

	for _, keyLength := range []int{0, 8, 15, 17, 23, 25, 31, 33, 64} {
		if _, err := CreateCBCFromKeyBytes(make([]byte, keyLength)); err == nil {
			t.Errorf("Expected a %d byte key to be rejected", keyLength)
		}
	}
}

func TestCreateCBCFromKeyString(t *testing.T) {
	cipher, err := CreateCBCFromKeyString(nistCBCVectors[0].key)
	if err != nil {
		t.Fatalf("Did not expect an error but got %q", err)
	}
	if hex.EncodeToString(cipher.KeyBytes) != nistCBCVectors[0].key {
		t.Errorf("Expected key %s but get %s", nistCBCVectors[0].key, hex.EncodeToString(cipher.KeyBytes))
	}

	if _, err := CreateCBCFromKeyString("not hex"); err == nil {
		t.Error("Expected a non hex key to be rejected")
	}
	if _, err := CreateCBCFromKeyString("2b7e151628aed2a6abf7158809cf4f"); err == nil {
		t.Error("Expected a hex key of the wrong length to be rejected")
	}
}

// A KCV depends on the key, not the AES mode.
func TestAESCBCCheckValueMatchesGCMCipher(t *testing.T) {
	keyBytes, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")

	cbcCipher, _ := CreateCBCFromKeyBytes(keyBytes)
	gcmCipher, _ := CreateFromKeyBytes(keyBytes)

	if cbcCipher.CheckValue() != "7df76b" {
		t.Errorf("Expected check value 7df76b but got %s", cbcCipher.CheckValue())
	}
	if cbcCipher.CheckValue() != gcmCipher.CheckValue() {
		t.Errorf("Expected check value %s but got %s", gcmCipher.CheckValue(), cbcCipher.CheckValue())
	}
}

func TestAESCBCVerifyCheckValue(t *testing.T) {
	cipher, _ := CreateCBCFromKeyString("2b7e151628aed2a6abf7158809cf4f3c")

	if !cipher.VerifyCheckValue("7df76b") {
		t.Error("Expected check value to verify successfully")
	}
	if !cipher.VerifyCheckValue("7DF76B") {
		t.Error("Expected check value verification to be case insensitive")
	}
	if cipher.VerifyCheckValue("abcdef") {
		t.Error("Expected wrong check value to fail verification")
	}
	if cipher.VerifyCheckValue("") {
		t.Error("Expected empty check value to fail verification")
	}
}
