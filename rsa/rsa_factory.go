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
package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKeyPair generates a RSA key pair for the provided bit size.
// Recommended bit size is 4096
func GenerateRSAKeyPair(bitSize int) (*pem.Block, *pem.Block, error) {
	reader := rand.Reader

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	publicKey := key.PublicKey

	asn1Bytes, err := asn1.Marshal(publicKey)
	pemkeyPublic := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pemkeyPublic, privateKey, nil
}

// EvalHash generates a SHA256 hash key for the provided pem block
func EvalHash(pem *pem.Block) [32]byte {
	return sha256.Sum256(pem.Bytes)
}

// EncodePem converts a pem block to a slice of bytes, ready to be serialized
// To deserialize back into a pem Block, use DecodePem
func EncodePem(p *pem.Block) ([]byte, error) {
	var buf bytes.Buffer
	err := pem.Encode(&buf, p)
	return buf.Bytes(), err
}

// DecodePem converts a slice of bytes to a pem block, useful for deserialization
func DecodePem(key []byte) (*pem.Block, error) {
	pem, _ := pem.Decode(key)
	if pem == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}
	return pem, nil
}
