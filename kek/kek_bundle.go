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
// package kek helps construct a key encryption key from a list of components
package kek

import (
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/xor"
	"github.com/transferwise/crypto/aes"
	"github.com/transferwise/crypto/des"
)

type KeyType string

const (
	KeyTypeTripleDES KeyType = "TripleDES"
	KeyTypeAES       KeyType = "AES"
)

// Bundle is the in memory data structure to help construct a KEK from a list of components
type Bundle struct {
	// name of the key
	Name string
	// unique index of this key
	Index int
	// expected components number
	Size int
	// result key check value
	CheckValue string
	// key type (TripleDES or AES)
	KeyType KeyType
	// imported components index value map
	Components map[int][]byte
}

// New creates a new KEK Bundle for TripleDES
// Deprecated: Use NewWithKeyType instead
func New(name string, index int, size int, checkValue string) *Bundle {
	return NewWithKeyType(name, index, size, checkValue, KeyTypeTripleDES)
}

// NewWithKeyType creates a new KEK Bundle with the specified key type
func NewWithKeyType(name string, index int, size int, checkValue string, keyType KeyType) *Bundle {
	return &Bundle{
		Name:       name,
		Index:      index,
		Size:       size,
		CheckValue: checkValue,
		KeyType:    keyType,
		Components: make(map[int][]byte),
	}
}

// IsComplete returns whether all components have been imported
func (b *Bundle) IsComplete() bool {
	return len(b.Components) == b.Size
}

// AddComponent add a new component to the Bundle
func (b *Bundle) AddComponent(componentIndex int, componentValue string, componentCheckValue string) error {
	switch b.KeyType {
	case KeyTypeAES:
		cipher, err := aes.CreateFromKeyString(componentValue)
		if err != nil {
			return errors.New("invalid component")
		}
		if !cipher.VerifyCheckValue(componentCheckValue) {
			return errors.New("component check value does not tally")
		}
		b.Components[componentIndex] = cipher.KeyBytes
	case KeyTypeTripleDES:
		cipher, err := des.CreateFromTripleDESKeyString(componentValue)
		if err != nil {
			return errors.New("invalid component")
		}
		if !cipher.VerifyCheckValue(componentCheckValue) {
			return errors.New("component check value does not tally")
		}
		b.Components[componentIndex] = cipher.KeyBytes
	default:
		return fmt.Errorf("unsupported key type: %s", b.KeyType)
	}
	return nil
}

// Merge tries to build the result TripleDES key from all the imported components
//
// Deprecated: Use MergeTripleDESKey instead.
func (b *Bundle) Merge() (des.Cipher, error) {
	return b.MergeTripleDESKey()
}

// MergeTripleDESKey tries to build the result TripleDES key from all the imported components
func (b *Bundle) MergeTripleDESKey() (des.Cipher, error) {
	kekBytes := make([]byte, 24)
	for _, component := range b.Components {
		kekBytes, _ = xor.XORBytes(kekBytes, component)
	}

	kekCipher, err := des.CreateFromTripleDESKeyBytes(kekBytes)
	if err != nil {
		return des.Cipher{}, err
	}
	if !kekCipher.VerifyCheckValue(b.CheckValue) {
		return des.Cipher{}, errors.New("derived key check value does not tally")
	}

	return kekCipher, nil
}

// MergeAESKey tries to build the result AES key from all the imported components
func (b *Bundle) MergeAESKey() (aes.Cipher, error) {
	var keyLen int
	for _, component := range b.Components {
		if keyLen == 0 {
			keyLen = len(component)
		} else if len(component) != keyLen {
			return aes.Cipher{}, fmt.Errorf("component length mismatch: expected %d bytes but got %d", keyLen, len(component))
		}
	}
	if keyLen == 0 {
		return aes.Cipher{}, errors.New("no components to merge")
	}

	kekBytes := make([]byte, keyLen)
	for _, component := range b.Components {
		var err error
		kekBytes, err = xor.XORBytes(kekBytes, component)
		if err != nil {
			return aes.Cipher{}, fmt.Errorf("failed to XOR components: %w", err)
		}
	}

	kekCipher, err := aes.CreateFromKeyBytes(kekBytes)
	if err != nil {
		return aes.Cipher{}, err
	}
	if !kekCipher.VerifyCheckValue(b.CheckValue) {
		return aes.Cipher{}, errors.New("derived key check value does not tally")
	}

	return kekCipher, nil
}
