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

func TestISO9797M2Pad(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty input gains a whole block",
			input:    "",
			expected: "80000000000000000000000000000000",
		},
		{
			name:     "one byte short of a block gains only the marker",
			input:    "000102030405060708090a0b0c0d0e",
			expected: "000102030405060708090a0b0c0d0e80",
		},
		{
			name:     "block aligned input gains a whole extra block",
			input:    "000102030405060708090a0b0c0d0e0f",
			expected: "000102030405060708090a0b0c0d0e0f" + "80000000000000000000000000000000",
		},
		{
			name:     "single byte gains marker and fourteen zeroes",
			input:    "ff",
			expected: "ff800000000000000000000000000000",
		},
		{
			name:     "input ending in the marker byte is still unambiguous",
			input:    "0080",
			expected: "00808000000000000000000000000000",
		},
		{
			name:     "input ending in zeroes is still unambiguous",
			input:    "ff0000",
			expected: "ff000080000000000000000000000000",
		},
		{
			name:     "input spanning more than one block",
			input:    "000102030405060708090a0b0c0d0e0f" + "1011",
			expected: "000102030405060708090a0b0c0d0e0f" + "10118000000000000000000000000000",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			inputBytes := mustDecodeHex(t, testCase.input)
			expectedBytes := mustDecodeHex(t, testCase.expected)

			padded := padISO9797M2(inputBytes, testBlockSize)

			if !bytes.Equal(padded, expectedBytes) {
				t.Fatalf("padded = %x, want %x", padded, expectedBytes)
			}
			if len(padded)%testBlockSize != 0 {
				t.Fatalf("padded length %d is not a multiple of %d", len(padded), testBlockSize)
			}
			if len(padded) <= len(inputBytes) {
				t.Fatalf("padding must always add at least one byte, input %d padded %d", len(inputBytes), len(padded))
			}
		})
	}
}

func TestISO9797M2PadAlwaysAddsBetweenOneAndBlockSizeBytes(t *testing.T) {
	for inputLen := 0; inputLen <= 3*testBlockSize; inputLen++ {
		inputBytes := make([]byte, inputLen)
		padded := padISO9797M2(inputBytes, testBlockSize)

		padLen := len(padded) - inputLen
		if padLen < 1 || padLen > testBlockSize {
			t.Fatalf("input length %d: padding of %d bytes is out of range 1..%d", inputLen, padLen, testBlockSize)
		}
		if padded[inputLen] != iso9797M2Marker {
			t.Fatalf("input length %d: marker byte = %#x, want %#x", inputLen, padded[inputLen], iso9797M2Marker)
		}
		for i, padByte := range padded[inputLen+1:] {
			if padByte != 0x00 {
				t.Fatalf("input length %d: filler byte %d = %#x, want 0x00", inputLen, i, padByte)
			}
		}
	}
}

func TestISO9797M2PadDoesNotModifyInput(t *testing.T) {
	inputBytes := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f1011")
	original := append([]byte(nil), inputBytes...)

	padISO9797M2(inputBytes, testBlockSize)

	if !bytes.Equal(inputBytes, original) {
		t.Fatalf("input was modified: got %x, want %x", inputBytes, original)
	}
}

func TestISO9797M2Unpad(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "whole block of padding yields empty output",
			input:    "80000000000000000000000000000000",
			expected: "",
		},
		{
			name:     "marker only",
			input:    "000102030405060708090a0b0c0d0e80",
			expected: "000102030405060708090a0b0c0d0e",
		},
		{
			name:     "extra block of padding after block aligned message",
			input:    "000102030405060708090a0b0c0d0e0f" + "80000000000000000000000000000000",
			expected: "000102030405060708090a0b0c0d0e0f",
		},
		{
			name:     "message ending in the marker byte",
			input:    "00808000000000000000000000000000",
			expected: "0080",
		},
		{
			name:     "message ending in zeroes",
			input:    "ff000080000000000000000000000000",
			expected: "ff0000",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			inputBytes := mustDecodeHex(t, testCase.input)
			expectedBytes := mustDecodeHex(t, testCase.expected)

			unpadded, err := unpadISO9797M2(inputBytes, testBlockSize)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(unpadded, expectedBytes) {
				t.Fatalf("unpadded = %x, want %x", unpadded, expectedBytes)
			}
		})
	}
}

func TestISO9797M2UnpadRejectsMalformedPadding(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "input not a multiple of the block size",
			input: "000102030405060708090a0b0c0d0e",
		},
		{
			name:  "no marker at all",
			input: "000102030405060708090a0b0c0d0e0f",
		},
		{
			name:  "trailing byte is neither marker nor zero",
			input: "000102030405060708090a0b0c0d0e01",
		},
		{
			name:  "all zeroes, so the marker is missing",
			input: "00000000000000000000000000000000",
		},
		{
			name:  "final block is all zeroes with the marker too far back",
			input: "000102030405060708090a0b0c0d0e80" + "00000000000000000000000000000000",
		},
		{
			name:  "PKCS#7 padding is rejected rather than silently accepted",
			input: "000102030405060708090a0b0c0d" + "0202",
		},
		{
			name:  "PKCS#7 whole block of padding is rejected",
			input: "10101010101010101010101010101010",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			inputBytes := mustDecodeHex(t, testCase.input)

			unpadded, err := unpadISO9797M2(inputBytes, testBlockSize)
			if err == nil {
				t.Fatalf("expected an error but got output %x", unpadded)
			}
			if unpadded != nil {
				t.Fatalf("expected nil output alongside the error but got %x", unpadded)
			}
		})
	}
}

func TestISO9797M2UnpadDoesNotModifyInput(t *testing.T) {
	inputBytes := mustDecodeHex(t, "ff000080000000000000000000000000")
	original := append([]byte(nil), inputBytes...)

	if _, err := unpadISO9797M2(inputBytes, testBlockSize); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(inputBytes, original) {
		t.Fatalf("input was modified: got %x, want %x", inputBytes, original)
	}
}

func TestISO9797M2UnpadReturnsCopyOfInput(t *testing.T) {
	inputBytes := mustDecodeHex(t, "ff112280000000000000000000000000")

	unpadded, err := unpadISO9797M2(inputBytes, testBlockSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	unpadded[0] = 0x00
	if inputBytes[0] != 0xff {
		t.Fatal("mutating the returned slice also mutated the input")
	}
}

func TestISO9797M2RoundTrip(t *testing.T) {
	for inputLen := 0; inputLen <= 3*testBlockSize; inputLen++ {
		inputBytes := make([]byte, inputLen)
		for i := range inputBytes {
			inputBytes[i] = byte(i)
		}

		padded := padISO9797M2(inputBytes, testBlockSize)
		unpadded, err := unpadISO9797M2(padded, testBlockSize)
		if err != nil {
			t.Fatalf("input length %d: unexpected error: %v", inputLen, err)
		}
		if !bytes.Equal(unpadded, inputBytes) {
			t.Fatalf("input length %d: round trip gave %x, want %x", inputLen, unpadded, inputBytes)
		}
	}
}

func TestISO9797M2RoundTripWithTrailingMarkerAndZeroBytes(t *testing.T) {
	// Padding remains unambiguous when plaintext ends in 0x80 or 0x00.
	testCases := []string{
		"80",
		"00",
		"8000",
		"0080",
		"800000000000000000000000000000",
		"00000000000000000000000000000080",
		"ff" + "00000000000000000000000000000000",
		"ff" + "80000000000000000000000000000000",
	}

	for _, testCase := range testCases {
		t.Run(testCase, func(t *testing.T) {
			inputBytes := mustDecodeHex(t, testCase)

			padded := padISO9797M2(inputBytes, testBlockSize)
			unpadded, err := unpadISO9797M2(padded, testBlockSize)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(unpadded, inputBytes) {
				t.Fatalf("round trip gave %x, want %x", unpadded, inputBytes)
			}
		})
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("could not decode hex %q: %v", s, err)
	}
	return decoded
}
