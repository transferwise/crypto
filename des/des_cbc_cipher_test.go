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
package des

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTripleDESDecryptCBC(t *testing.T) {
	// Independent Python cryptography/OpenSSL vectors: plaintext bytes 00..1f,
	// no padding. The first two cases use double-length 3DES (K1, K2, K1).
	tests := []struct {
		name, key, iv, ciphertext string
	}{
		{"double-length zero IV", "0123456789ABCDEFFEDCBA9876543210", "0000000000000000", "52c5c0705d9089e1fd2f0cf61dd3bc0ac0a3e54b8860076a1ec9453c5a31bf0f"},
		{"double-length nonzero IV", "0123456789ABCDEFFEDCBA9876543210", "1234567890abcdef", "188508514eeb60d24f8e125f9c2754e977bcc79e1c71911de0f7ed47b084f209"},
		{"triple-length zero IV", "0123456789ABCDEFFEDCBA987654321089ABCDEF01234567", "0000000000000000", "98f447d72bee8df72fc757753238f778ad817caff7455eadc9121c8a11c8ad16"},
		{"triple-length nonzero IV", "0123456789ABCDEFFEDCBA987654321089ABCDEF01234567", "1234567890abcdef", "dab10e76a31ef60dda6931da2244e63db6eec753a1774b4e7a6663c9805ff5f6"},
	}
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = byte(i)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := CreateFromTripleDESKeyString(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			iv, _ := hex.DecodeString(tt.iv)
			ciphertext, _ := hex.DecodeString(tt.ciphertext)
			for i := 0; i < 2; i++ {
				plaintext, err := c.DecryptCBC(ciphertext, iv)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(plaintext, expected) {
					t.Fatal("plaintext does not match the independent vector")
				}
			}
			if hex.EncodeToString(ciphertext) != tt.ciphertext || hex.EncodeToString(iv) != tt.iv {
				t.Fatal("decryption modified the ciphertext or IV")
			}
		})
	}
}

func TestDecryptCBCRejectsInvalidInput(t *testing.T) {
	c, err := CreateFromTripleDESKeyString("0123456789ABCDEFFEDCBA9876543210")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		ciphertext, iv []byte
	}{
		{"missing IV", make([]byte, 8), nil},
		{"short IV", make([]byte, 8), make([]byte, 7)},
		{"long IV", make([]byte, 8), make([]byte, 9)},
		{"empty ciphertext", nil, make([]byte, 8)},
		{"unaligned ciphertext", make([]byte, 9), make([]byte, 8)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if plaintext, err := c.DecryptCBC(tt.ciphertext, tt.iv); err == nil || plaintext != nil {
				t.Fatal("expected an error and no plaintext")
			}
		})
	}
}
