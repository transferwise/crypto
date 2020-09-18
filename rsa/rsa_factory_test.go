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
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func TestRSAGeneration(t *testing.T) {
	_, _, err := GenerateRSAKeyPair(4096)

	if err != nil {
		t.Fatal("Failed to generate a RSA key pair ", err)
	}
}

func TestEvalHash(t *testing.T) {
	priv, err := readKey("testdata/private.pem")
	if err != nil {
		t.Fatal("Failed to read private key", err)
	}

	//A silly test that verifies the hash remains the same
	h := EvalHash(priv)
	e, err := EncodePem(priv)
	if err != nil {
		t.Fail()
	} else {
		priv, _ = DecodePem(e)
		if EvalHash(priv) != h {
			t.Fail()
		}
	}

	pub, err := readKey("testdata/public.pem")
	if err != nil {
		t.Fatal("Failed to read public key", err)
	}

	h = EvalHash(pub)
	e, err = EncodePem(pub)
	if err != nil {
		t.Fail()
	} else {
		pub, _ = DecodePem(e)
		if EvalHash(pub) != h {
			t.Fail()
		}
	}
}

func TestDecodePemNegative(t *testing.T) {
	_, err := DecodePem([]byte("invalid key"))
	if err == nil {
		t.Fail()
	}
}

func readKey(filename string) (*pem.Block, error) {
	priv, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	//Decode the PEM
	block, _ := pem.Decode(priv)
	return block, nil
}
