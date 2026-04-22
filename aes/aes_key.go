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
	"crypto/cipher"
	"encoding/hex"
	"strings"
)

const (
	checkValueDefaultBytes = 3
	checkValueMinimumBytes = 2
)

// KCVMethod determines how Key Check Values are computed.
type KCVMethod int

const (
	// KCVMethodECB computes KCV by AES-ECB encrypting a block of zero bytes.
	KCVMethodECB KCVMethod = iota
	// KCVMethodCMAC computes KCV using AES-CMAC over a block of zero bytes per RFC 4493.
	KCVMethodCMAC
)

// Key wraps an AES key and supports Key Check Value verification.
type Key struct {
	keyBlock  cipher.Block
	KeyBytes  []byte
	kcvMethod KCVMethod
}

func (k *Key) VerifyCheckValue(checkValue string) bool {
	checkValueBytes := len(checkValue) / 2
	if checkValueBytes < checkValueMinimumBytes || checkValueBytes > k.keyBlock.BlockSize() {
		return false
	}

	kcvBytes := k.computeKCV()
	derivedCheckValue := hex.EncodeToString(kcvBytes[:checkValueBytes])
	return strings.EqualFold(derivedCheckValue, checkValue)
}

func (k *Key) CheckValue() string {
	kcvBytes := k.computeKCV()
	return hex.EncodeToString(kcvBytes[:checkValueDefaultBytes])
}

func (k *Key) GetKeyBytes() []byte {
	return k.KeyBytes
}

func (k *Key) computeKCV() []byte {
	zeros := make([]byte, k.keyBlock.BlockSize())

	switch k.kcvMethod {
	case KCVMethodCMAC:
		return cmac(k.keyBlock, zeros)
	default:
		encrypted := make([]byte, k.keyBlock.BlockSize())
		k.keyBlock.Encrypt(encrypted, zeros)
		return encrypted
	}
}
