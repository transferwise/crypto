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

func TestInvalidAESKeyStrings(t *testing.T) {
	invalidKeys := []string{
		"",
		"sme",
		"844e5fb5-96d1-4b19-9ce0-b90f252ea370",
		"        naksn",
		"2b7e1516",
		"2b7e151628aed2a6abf71588",
	}

	for _, key := range invalidKeys {
		if _, err := CreateFromKeyString(key); err == nil {
			t.Errorf("Expecting AES key %s to be invalid", key)
		}
	}
}

func TestValidAES128KeyStrings(t *testing.T) {
	validKeys := []string{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
	}

	for _, key := range validKeys {
		if _, err := CreateFromKeyString(key); err != nil {
			t.Errorf("Expecting AES-128 key %s to be valid but got %v", key, err)
		}
	}
}

func TestValidAES192KeyStrings(t *testing.T) {
	validKeys := []string{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
	}

	for _, key := range validKeys {
		if _, err := CreateFromKeyString(key); err != nil {
			t.Errorf("Expecting AES-192 key %s to be valid but got %v", key, err)
		}
	}
}

func TestValidAES256KeyStrings(t *testing.T) {
	validKeys := []string{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	}

	for _, key := range validKeys {
		if _, err := CreateFromKeyString(key); err != nil {
			t.Errorf("Expecting AES-256 key %s to be valid but got %v", key, err)
		}
	}
}

func TestInvalidAESKeyBytes(t *testing.T) {
	invalidLengths := []int{0, 7, 15, 17, 23, 25, 31, 33}

	for _, length := range invalidLengths {
		keyBytes := make([]byte, length)
		if _, err := CreateFromKeyBytes(keyBytes); err == nil {
			t.Errorf("Expecting AES key of length %d bytes to be invalid", length)
		}
	}
}
