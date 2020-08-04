This repo provides a list of utility modules that are currently used by [payment plugin](https://github.com/transferwise/vault-plugin-secrets-payment) 
and [manufacturing plugin](https://github.com/transferwise/vault-plugin-secrets-manufacturing).

### AES
* factory methods to construct an AES-GCM cipher with a 96-bit nonce from the input raw key bytes
* encrypt & decrypt methods, the output ciphertext is prefixed with the random nonce.

### DES
* factory methods to construct an DES or 3DES cipher from the raw key bytes or hex text
* encrypt & decrypt methods
* verify the constructed cipher against the check value

### KEK Bundle
Helper class to construct a 3DES key encryption key from a list of components. 

