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
	stdaes "crypto/aes"
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 4493 test vectors using AES-128 key 2b7e151628aed2a6abf7158809cf4f3c
var rfc4493Key = mustDecodeHex("2b7e151628aed2a6abf7158809cf4f3c")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCMACSubkeyGeneration(t *testing.T) {
	block, err := stdaes.NewCipher(rfc4493Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	k1 := generateSubkey(block)
	expectedK1 := "fbeed618357133667c85e08f7236a8de"
	if !strings.EqualFold(hex.EncodeToString(k1), expectedK1) {
		t.Fatalf("expected K1 %s but got %s", expectedK1, hex.EncodeToString(k1))
	}
}

func TestCMACTwoBlocks(t *testing.T) {
	block, err := stdaes.NewCipher(rfc4493Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	message := mustDecodeHex(
		"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51")
	expected := "ce0cbf1738f4df6428b1d93bf12081c9"

	result := cmac(block, message)
	if !strings.EqualFold(hex.EncodeToString(result), expected) {
		t.Fatalf("expected %s but got %s", expected, hex.EncodeToString(result))
	}
}

func TestCMACOneBlock(t *testing.T) {
	block, err := stdaes.NewCipher(rfc4493Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	// RFC 4493 Example 2: len = 16 (one complete block)
	message := mustDecodeHex("6bc1bee22e409f96e93d7e117393172a")
	expected := "070a16b46b4d4144f79bdd9dd04a287c"

	result := cmac(block, message)
	if !strings.EqualFold(hex.EncodeToString(result), expected) {
		t.Fatalf("expected %s but got %s", expected, hex.EncodeToString(result))
	}
}

func TestCMACFourBlocks(t *testing.T) {
	block, err := stdaes.NewCipher(rfc4493Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	// RFC 4493 Example 4: len = 64 (four complete blocks)
	message := mustDecodeHex(
		"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411e5fbc1191a0a52ef" +
			"f69f2445df4f9b17ad2b417be66c3710")
	expected := "51f0bebf7e3b9d92fc49741779363cfe"

	result := cmac(block, message)
	if !strings.EqualFold(hex.EncodeToString(result), expected) {
		t.Fatalf("expected %s but got %s", expected, hex.EncodeToString(result))
	}
}

func TestCMACZeroBlock(t *testing.T) {
	block, err := stdaes.NewCipher(rfc4493Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	// CMAC over 16 zero bytes — the KCV use case
	zeros := make([]byte, 16)
	result := cmac(block, zeros)

	expected := "7ad386c3760fb3498361a1cb5563bd70"
	if !strings.EqualFold(hex.EncodeToString(result), expected) {
		t.Fatalf("expected %s but got %s", expected, hex.EncodeToString(result))
	}
}
