package kek

import (
	"errors"

	"github.com/hashicorp/vault/helper/xor"
	"github.com/transferwise/crypto/des"
)

type Bundle struct {
	Name     string
	Index   int
	Size       int
	CheckValue string
	Components map[int][]byte
}

func NewBundle(scheme string, index int, size int, checkValue string) *Bundle {
	return &Bundle{
		Name:     scheme,
		Index:   index,
		Size:       size,
		CheckValue: checkValue,
		Components: make(map[int][]byte),
	}
}

func (b *Bundle) IsComplete() bool {
	return len(b.Components) == b.Size
}

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

func (b *Bundle) Merge() (des.DESCipher, error) {
	kekBytes := make([]byte, 24)
	for _, component := range b.Components {
		kekBytes, _ = xor.XORBytes(kekBytes, component)
	}

	kekCipher, err := des.CreateFromTripleDESKeyBytes(kekBytes)
	if err != nil {
		return des.DESCipher{}, err
	}
	if !kekCipher.VerifyCheckValue(b.CheckValue) {
		return des.DESCipher{}, errors.New("derived key check value does not tally")
	}

	return kekCipher, nil
}
