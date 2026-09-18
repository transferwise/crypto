package des

import (
	"crypto/cipher"
	"fmt"
)

// DecryptCBC decrypts non-empty, block-aligned ciphertext using the supplied IV.
// It does not remove padding or authenticate the ciphertext.
func (c *Cipher) DecryptCBC(cipherBytes, iv []byte) ([]byte, error) {
	blockSize := c.KeyBlock.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV must be %d bytes", blockSize)
	}
	if len(cipherBytes) == 0 || len(cipherBytes)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext must be a non-empty multiple of %d bytes", blockSize)
	}

	plainBytes := make([]byte, len(cipherBytes))
	cipher.NewCBCDecrypter(c.KeyBlock, iv).CryptBlocks(plainBytes, cipherBytes)
	return plainBytes, nil
}
