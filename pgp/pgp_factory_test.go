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
	"io/ioutil"
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
	if hash != "e14e2ac4eb71a116767bccd45b2ed52e758b1c41" {
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
		t.Fatal("Failed to encrypt text")
	}
	dec, err := pgp.Decrypt(enc, nil)
	if err != nil {
		t.Fatal("Failed to decrypt text")
	}

	if string(dec) != text {
		t.Fatal("Decrypted text does not match")
	}
}

func readKey(filename string) (string, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(f), nil
}
