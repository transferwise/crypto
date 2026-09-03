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

const testBlockSize = 16

func TestPKCS7Pad(t *testing.T) {
	testCases := []struct {
		name     string
		plain    string
		expected string
	}{
		// RFC 5652 section 6.3: block aligned input gains a whole extra block,
		// so an empty input pads to a single full block.
		{"empty", "", "10101010101010101010101010101010"},
		{"one byte", "00", "000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"},
		{"fifteen bytes", "000102030405060708090a0b0c0d0e", "000102030405060708090a0b0c0d0e01"},
		{"one full block", "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f10101010101010101010101010101010"},
		{"one block plus one byte", "000102030405060708090a0b0c0d0e0f10", "000102030405060708090a0b0c0d0e0f100f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"},
		{"two full blocks", "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f10101010101010101010101010101010"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			plainBytes, _ := hex.DecodeString(testCase.plain)

			padded := hex.EncodeToString(pad(plainBytes, testBlockSize))
			if padded != testCase.expected {
				t.Errorf("Expected %s but get %s", testCase.expected, padded)
			}
		})
	}
}

func TestPKCS7PadDoesNotModifyInput(t *testing.T) {
	plainBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	original := hex.EncodeToString(plainBytes)

	pad(plainBytes, testBlockSize)

	if hex.EncodeToString(plainBytes) != original {
		t.Errorf("Expected input to be left as %s but get %s", original, hex.EncodeToString(plainBytes))
	}
}

func TestPKCS7Unpad(t *testing.T) {
	testCases := []struct {
		name     string
		padded   string
		expected string
	}{
		{"empty plaintext", "10101010101010101010101010101010", ""},
		{"one byte", "000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "00"},
		{"fifteen bytes", "000102030405060708090a0b0c0d0e01", "000102030405060708090a0b0c0d0e"},
		{"one full block", "000102030405060708090a0b0c0d0e0f10101010101010101010101010101010", "000102030405060708090a0b0c0d0e0f"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			paddedBytes, _ := hex.DecodeString(testCase.padded)

			plainBytes, err := unpad(paddedBytes, testBlockSize)
			if err != nil {
				t.Errorf("Did not expect an error but got %q", err)
			}

			if hex.EncodeToString(plainBytes) != testCase.expected {
				t.Errorf("Expected %s but get %s", testCase.expected, hex.EncodeToString(plainBytes))
			}
		})
	}
}

func TestPKCS7UnpadRejectsMalformedPadding(t *testing.T) {
	testCases := []struct {
		name   string
		padded string
	}{
		{"empty input", ""},
		{"length not a multiple of the block size", "000102030405060708090a0b0c0d0e"},
		{"pad byte of zero", "000102030405060708090a0b0c0d0e00"},
		{"pad byte larger than the block size", "000102030405060708090a0b0c0d0e11"},
		{"inconsistent pad bytes", "000102030405060708090a0b0c0d0203"},
		{"pad bytes not repeated for the full length", "0001020304050607080900000000ff04"},
		{"padding claims the whole block but is not uniform", "0102030405060708090a0b0c0d0e0f10"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			paddedBytes, _ := hex.DecodeString(testCase.padded)

			if _, err := unpad(paddedBytes, testBlockSize); err == nil {
				t.Error("Expected an error but got none")
			}
		})
	}
}

func TestPKCS7UnpadDoesNotModifyInput(t *testing.T) {
	paddedBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e01")
	original := hex.EncodeToString(paddedBytes)

	if _, err := unpad(paddedBytes, testBlockSize); err != nil {
		t.Errorf("Did not expect an error but got %q", err)
	}

	if hex.EncodeToString(paddedBytes) != original {
		t.Errorf("Expected input to be left as %s but get %s", original, hex.EncodeToString(paddedBytes))
	}
}

func TestPKCS7UnpadReturnsCopyOfInput(t *testing.T) {
	paddedBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e01")

	plainBytes, err := unpad(paddedBytes, testBlockSize)
	if err != nil {
		t.Errorf("Did not expect an error but got %q", err)
	}

	plainBytes[0] = 0xff
	if paddedBytes[0] == 0xff {
		t.Error("Expected the returned slice not to alias the input")
	}
}

func TestPKCS7RoundTrip(t *testing.T) {
	for length := 0; length <= 48; length++ {
		plainBytes := make([]byte, length)
		for i := range plainBytes {
			plainBytes[i] = byte(i)
		}

		padded := pad(plainBytes, testBlockSize)
		if len(padded)%testBlockSize != 0 {
			t.Errorf("Expected padded length to be a multiplier of %d but get %d", testBlockSize, len(padded))
		}
		if len(padded) <= length {
			t.Errorf("Expected padded length to be greater than %d but get %d", length, len(padded))
		}

		unpadded, err := unpad(padded, testBlockSize)
		if err != nil {
			t.Errorf("Did not expect an error for length %d but got %q", length, err)
			continue
		}

		if !bytes.Equal(plainBytes, unpadded) {
			t.Errorf("Expected %s but get %s", hex.EncodeToString(plainBytes), hex.EncodeToString(unpadded))
		}
	}
}
