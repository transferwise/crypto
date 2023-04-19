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
// package kek helps construct an 3DES key encryption key from a list of components
package kek

import (
	"errors"

	"github.com/hashicorp/vault/sdk/helper/xor"
	"github.com/transferwise/crypto/des"
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
}

func New(name string, index int, size int, checkValue string) *Bundle {
	return &Bundle{
		Name:       name,
		Index:      index,
		Size:       size,
		CheckValue: checkValue,
		Components: make(map[int][]byte),
	}
}

// IsComplete returns whether all components have been imported
func (b *Bundle) IsComplete() bool {
	return len(b.Components) == b.Size
}

// AddComponent add a new component to the Bundle
func (b *Bundle) AddComponent(componentIndex int, componentValue string, componentCheckValue string) error {
	cipher, err := des.CreateFromTripleDESKeyString(componentValue)
	if err != nil {
		return errors.New("invalid component")
	}
	if !cipher.VerifyCheckValue(componentCheckValue) {
		return errors.New("component check value does not tally")
	}

	// Override the previous value if the same component is imported again
	b.Components[componentIndex] = cipher.KeyBytes
	return nil
}

// Merge tries to build the result 3DES key from all the imported components
func (b *Bundle) Merge() (des.Cipher, error) {
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
