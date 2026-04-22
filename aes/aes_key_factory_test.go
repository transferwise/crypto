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
	"testing"
)

func TestCreateKeyFromStringInvalidHex(t *testing.T) {
	_, err := CreateKeyFromString("not-hex", KCVMethodECB)
	if err == nil {
		t.Fatal("should fail with invalid hex")
	}
}

func TestCreateKeyFromStringWrongLength(t *testing.T) {
	_, err := CreateKeyFromString("AABBCCDD", KCVMethodECB)
	if err == nil {
		t.Fatal("should fail with wrong key length")
	}
}

func TestCreateKeyFromBytesWrongLength(t *testing.T) {
	_, err := CreateKeyFromBytes([]byte{1, 2, 3}, KCVMethodECB)
	if err == nil {
		t.Fatal("should fail with wrong key length")
	}
}

func TestCreateKeyFromBytes16(t *testing.T) {
	key, err := CreateKeyFromBytes(make([]byte, 16), KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create AES-128 key: %v", err)
	}
	if len(key.KeyBytes) != 16 {
		t.Fatalf("expected 16 bytes but got %d", len(key.KeyBytes))
	}
}

func TestCreateKeyFromBytes24(t *testing.T) {
	key, err := CreateKeyFromBytes(make([]byte, 24), KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create AES-192 key: %v", err)
	}
	if len(key.KeyBytes) != 24 {
		t.Fatalf("expected 24 bytes but got %d", len(key.KeyBytes))
	}
}

func TestCreateKeyFromBytes32(t *testing.T) {
	key, err := CreateKeyFromBytes(make([]byte, 32), KCVMethodECB)
	if err != nil {
		t.Fatalf("failed to create AES-256 key: %v", err)
	}
	if len(key.KeyBytes) != 32 {
		t.Fatalf("expected 32 bytes but got %d", len(key.KeyBytes))
	}
}

func TestCreateKeyFromStringValid(t *testing.T) {
	key, err := CreateKeyFromString("702E73B9230ECADBB8F120BDE3870493", KCVMethodCMAC)
	if err != nil {
		t.Fatalf("failed to create key from hex string: %v", err)
	}
	if len(key.KeyBytes) != 16 {
		t.Fatalf("expected 16 bytes but got %d", len(key.KeyBytes))
	}
	if key.kcvMethod != KCVMethodCMAC {
		t.Fatal("expected CMAC KCV method")
	}
}
