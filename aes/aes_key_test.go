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
	"encoding/hex"
	"strings"
	"testing"
)

const testKeyHex = "702E73B9230ECADBB8F120BDE3870493"

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestECBCheckValue(t *testing.T) {
	key, err := CreateKeyFromString(testKeyHex, KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	expected := "A3DB34"
	if !strings.EqualFold(key.CheckValue(), expected) {
		t.Fatalf("expected ECB KCV %s but got %s", expected, key.CheckValue())
	}
}

func TestECBVerifyCheckValue(t *testing.T) {
	key, err := CreateKeyFromString(testKeyHex, KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	if !key.VerifyCheckValue("A3DB34") {
		t.Fatal("ECB KCV verification should pass")
	}
	if key.VerifyCheckValue("000000") {
		t.Fatal("ECB KCV verification should fail with wrong value")
	}
}

func TestVerifyCheckValueCaseInsensitive(t *testing.T) {
	key, err := CreateKeyFromString(testKeyHex, KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	if !key.VerifyCheckValue("a3db34") {
		t.Fatal("KCV verification should be case insensitive")
	}
}

func TestVerifyCheckValueTooShort(t *testing.T) {
	key, err := CreateKeyFromString(testKeyHex, KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	if key.VerifyCheckValue("A3") {
		t.Fatal("KCV with less than 2 bytes should fail")
	}
}

func TestGetKeyBytes(t *testing.T) {
	key, err := CreateKeyFromBytes(mustDecodeHex(testKeyHex), KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	if len(key.GetKeyBytes()) != 16 {
		t.Fatalf("expected 16 bytes but got %d", len(key.GetKeyBytes()))
	}
}
