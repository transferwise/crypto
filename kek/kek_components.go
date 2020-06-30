package kek

import (
	"errors"

	"github.com/hashicorp/vault/helper/xor"
	"github.com/transferwise/crypto/des"
)

type ZMKComponents struct {
	scheme     string
	keyIndex   int
	size       int
	checkValue string
	components map[int][]byte
}

func NewZMKComponents(scheme string, keyIndex int, size int, checkValue string) *ZMKComponents {
	return &ZMKComponents{
		scheme:     scheme,
		keyIndex:   keyIndex,
		size:       size,
		checkValue: checkValue,
		components: make(map[int][]byte),
	}
}

func (c *ZMKComponents) IsComplete() bool {
	return len(c.components) == c.size
}

func (c *ZMKComponents) AddComponent(componentIndex int, componentValue string, componentCheckValue string) error {
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

func (c *ZMKComponents) Merge() (des.DESCipher, error) {
	zmkBytes := make([]byte, 24)
	for _, component := range c.components {
		zmkBytes, _ = xor.XORBytes(zmkBytes, component)
	}

	zmkCipher, err := des.CreateFromTripleDESKeyBytes(zmkBytes)
	if err != nil {
		return des.DESCipher{}, err
	}
	if !zmkCipher.VerifyCheckValue(c.checkValue) {
		return des.DESCipher{}, errors.New("derived ZMK check value does not tally")
	}

	return zmkCipher, nil
}
