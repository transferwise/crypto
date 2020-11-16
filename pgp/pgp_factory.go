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
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

type ArmoredKeyPair struct {
	PrivateKey string
	PublicKey  string
}

// EvalHash generates a SHA256 hash as string for the public key
func (pgp *ArmoredKeyPair) EvalHash() string {
	publicKeyObj, err := crypto.NewKeyFromArmored(pgp.PublicKey)
	if err != nil {
		return ""
	}
	return publicKeyObj.GetFingerprint()
}

// Encrypt encrypts a message with the given public key and output an armored PGP message
func (pgp *ArmoredKeyPair) Encrypt(plainBytes []byte) (string, error) {
	return helper.EncryptBinaryMessageArmored(pgp.PublicKey, plainBytes)
}

// Decrypt decrypts an armored PGP message with the given private key and passphrase
func (pgp *ArmoredKeyPair) Decrypt(ciphertext string, passphrase []byte) ([]byte, error) {
	return helper.DecryptBinaryMessageArmored(pgp.PrivateKey, passphrase, ciphertext)
}
