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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// GenerateRSAKeyPair generates a RSA key pair for the provided bit size.
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	reader := rand.Reader
	return rsa.GenerateKey(reader, 4096)
}

// EvalHash generates a SHA256 hash as string for the provided pem block
func EvalHash(p *rsa.PublicKey) string {
	b := x509.MarshalPKCS1PublicKey(p)
	h := sha256.Sum256(b)
	b64 := base64.StdEncoding.EncodeToString(h[:])
	return b64
}

// Encode converts a rsa.PublicKey to a base64 encoded pkcs1 string
func Encode(p *rsa.PublicKey) string {
	b := x509.MarshalPKCS1PublicKey(p)
	s := base64.StdEncoding.EncodeToString(b)
	return s
}

// Decode converts a base64 encoded pkcs1 string to a *rsa.PublicKey
func Decode(s string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(der)
}

// Decrypt decrypts a message with the provided rsa.PrivateKey
func Decrypt(p *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, p, cipher, nil)
}

// Encrypt encrypts a message with the provided rsa.PublicKey
func Encrypt(p *rsa.PublicKey, cipher []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, p, cipher, nil)
}
