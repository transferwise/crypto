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

	"github.com/hashicorp/vault/sdk/helper/xor"
	"github.com/transferwise/crypto/aes"
	"github.com/transferwise/crypto/des"
)

// Algorithm determines the cipher type and KCV method used by the Bundle.
type Algorithm string

const (
	TripleDES Algorithm = "3DES"
	AES_ECB   Algorithm = "AES_ECB"
	AES_CMAC  Algorithm = "AES_CMAC"
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
	// imported components index value map
	Components map[int][]byte
	// algorithm for this KEK
	Algorithm Algorithm
}

func New(name string, index int, size int, checkValue string, algorithm Algorithm) *Bundle {
	return &Bundle{
		Name:       name,
		Index:      index,
		Size:       size,
		CheckValue: checkValue,
		Components: make(map[int][]byte),
		Algorithm:  algorithm,
	}
}

// IsComplete returns whether all components have been imported
func (b *Bundle) IsComplete() bool {
	return len(b.Components) == b.Size
}

// AddComponent add a new component to the Bundle
func (b *Bundle) AddComponent(componentIndex int, componentValue string, componentCheckValue string) error {
	switch b.Algorithm {
	case AES_ECB:
		return b.addAESComponent(componentIndex, componentValue, componentCheckValue, aes.KCVMethodECB)
	case AES_CMAC:
		return b.addAESComponent(componentIndex, componentValue, componentCheckValue, aes.KCVMethodCMAC)
	default:
		return b.addTripleDESComponent(componentIndex, componentValue, componentCheckValue)
	}
}

func (b *Bundle) addTripleDESComponent(componentIndex int, componentValue string, componentCheckValue string) error {
	cipher, err := des.CreateFromTripleDESKeyString(componentValue)
	if err != nil {
		return errors.New("invalid component")
	}
	if !cipher.VerifyCheckValue(componentCheckValue) {
		return errors.New("component check value does not tally")
	}
	b.Components[componentIndex] = cipher.KeyBytes
	return nil
}

func (b *Bundle) addAESComponent(componentIndex int, componentValue string, componentCheckValue string, kcvMethod aes.KCVMethod) error {
	key, err := aes.CreateKeyFromString(componentValue, kcvMethod)
	if err != nil {
		return errors.New("invalid component")
	}
	if !key.VerifyCheckValue(componentCheckValue) {
		return errors.New("component check value does not tally")
	}
	b.Components[componentIndex] = key.KeyBytes
	return nil
}

// Merge tries to build the result key from all the imported components
func (b *Bundle) Merge() (KeyCipher, error) {
	kekBytes := make([]byte, b.keySize())
	for _, component := range b.Components {
		kekBytes, _ = xor.XORBytes(kekBytes, component)
	}

	switch b.Algorithm {
	case AES_ECB:
		return b.mergeAES(kekBytes, aes.KCVMethodECB)
	case AES_CMAC:
		return b.mergeAES(kekBytes, aes.KCVMethodCMAC)
	default:
		return b.mergeTripleDES(kekBytes)
	}
}

func (b *Bundle) mergeTripleDES(kekBytes []byte) (KeyCipher, error) {
	kekCipher, err := des.CreateFromTripleDESKeyBytes(kekBytes)
	if err != nil {
		return nil, err
	}
	if !kekCipher.VerifyCheckValue(b.CheckValue) {
		return nil, errors.New("derived key check value does not tally")
	}
	return &kekCipher, nil
}

func (b *Bundle) mergeAES(kekBytes []byte, kcvMethod aes.KCVMethod) (KeyCipher, error) {
	kekKey, err := aes.CreateKeyFromBytes(kekBytes, kcvMethod)
	if err != nil {
		return nil, err
	}
	if !kekKey.VerifyCheckValue(b.CheckValue) {
		return nil, errors.New("derived key check value does not tally")
	}
	return &kekKey, nil
}

func (b *Bundle) keySize() int {
	for _, v := range b.Components {
		return len(v)
	}
	return 24
}
