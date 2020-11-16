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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestRSAGeneration(t *testing.T) {
	_, err := GenerateRSAKeyPair()

	if err != nil {
		t.Fatal("Failed to generate a RSA key pair ", err)
	}
}

func TestEvalHash(t *testing.T) {

	pub, err := readPublicKey("testdata/public.pem")
	if err != nil {
		t.Fatal("Failed to read public key", err)
	}

	hash := EvalHash(pub)
	if hash != "BTx5GBFv1S8yMqehO5TvvgoKk5om7FcFIkSJlMtXGiw=" {
		t.Fail()
	}
}

func TestEncodeDecode(t *testing.T) {
	s, err := readPublicKey("testdata/public.pem")
	if err != nil {
		t.Fatal("Failed to read public key", err)
	}
	pub := Encode(s)
	new, err := Decode(pub)
	if err != nil {
		t.Fatal("Failed to decode public key")
	}
	if new.N.Cmp(s.N) != 0 {
		t.Fatal("Encoded and decoded keys don't match")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair")
	}

	text := "Secret text"
	enc, err := Encrypt(&priv.PublicKey, []byte(text))
	if err != nil {
		t.Fatal("Failed to encrypt text")
	}
	dec, err := Decrypt(priv, enc)
	if err != nil {
		t.Fatal("Failed to decrypt text")
	}

	if string(dec) != text {
		t.Fatal("Decrypted text does not match")
	}
}

func readPublicKey(filename string) (*rsa.PublicKey, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(f)

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Parsed key not of the RSA")
	}
	return pubKey, nil
}
