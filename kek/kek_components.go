package kek

import (
	"errors"

	"github.com/hashicorp/vault/helper/xor"
	"github.com/transferwise/crypto/des"
)

type KEKComponents struct {
	scheme     string
	keyIndex   int
	size       int
	checkValue string
	components map[int][]byte
}

func NewKEKComponents(scheme string, keyIndex int, size int, checkValue string) *KEKComponents {
	return &KEKComponents{
		scheme:     scheme,
		keyIndex:   keyIndex,
		size:       size,
		checkValue: checkValue,
		components: make(map[int][]byte),
	}
}

func (c *KEKComponents) IsComplete() bool {
	return len(c.components) == c.size
}

func (c *KEKComponents) AddComponent(componentIndex int, componentValue string, componentCheckValue string) error {
	cipher, err := des.CreateFromTripleDESKeyString(componentValue)
	if err != nil {
		return errors.New("invalid component")
	}
	if !cipher.VerifyCheckValue(componentCheckValue) {
		return errors.New("component check value does not tally")
	}

	// Override the previous value if the same component is imported again
	c.components[componentIndex] = cipher.KeyBytes
	return nil
}

func (c *KEKComponents) Merge() (des.DESCipher, error) {
	kekBytes := make([]byte, 24)
	for _, component := range c.components {
		kekBytes, _ = xor.XORBytes(kekBytes, component)
	}

	kekCipher, err := des.CreateFromTripleDESKeyBytes(kekBytes)
	if err != nil {
		return des.DESCipher{}, err
	}
	if !kekCipher.VerifyCheckValue(c.checkValue) {
		return des.DESCipher{}, errors.New("derived key check value does not tally")
	}

	return kekCipher, nil
}
