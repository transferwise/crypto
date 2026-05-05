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
package pgp

import (
	"os"
	"testing"
)

func TestEvalHash(t *testing.T) {
	public, err := readKey("testdata/public.pgp")
	if err != nil {
		t.Fatal("Failed to read public key", err)
	}

	pgp := ArmoredKeyPair{
		PublicKey: public,
	}

	hash := pgp.EvalHash()
	if hash != "f6c8bf3371502b21e4f43f5bde9277a682fbc4d3" {
		t.Fatalf("hash does not match: %s", hash)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	public, err := readKey("testdata/public.pgp")
	if err != nil {
		t.Fatal("Failed to read public key", err)
	}

	private, err := readKey("testdata/private.pgp")
	if err != nil {
		t.Fatal("Failed to read private key", err)
	}

	pgp := ArmoredKeyPair{
		PublicKey:  public,
		PrivateKey: private,
	}

	text := "Secret text"
	enc, err := pgp.Encrypt([]byte(text))
	if err != nil {
		t.Fatalf("Failed to encrypt text: %v", err)
	}
	dec, err := pgp.Decrypt(enc, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt text: %v", err)
	}

	if string(dec) != text {
		t.Fatalf("Decrypted text does not match: %s", string(dec))
	}
}

func readKey(filename string) (string, error) {
	f, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(f), nil
}
