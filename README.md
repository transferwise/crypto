This repo provides a list of utility modules for common crypto operations.

### AES

- factory methods to construct an AES-GCM cipher with a 96-bit nonce from the input raw key bytes or hex text
- encrypt & decrypt methods, the output ciphertext is prefixed with the random nonce.
- verify the constructed cipher against the check value

### AES-CBC

- factory methods to construct an AES-CBC cipher from the raw key bytes or hex text
- encrypt & decrypt methods for block-aligned or ISO/IEC 9797-1 method 2 padded input
- generate a random 16-byte initialisation vector
- verify the constructed cipher against the check value

AES-CBC does not authenticate ciphertext. Callers must authenticate the initialisation vector and ciphertext separately.

### DES

- factory methods to construct an DES or 3DES cipher from the raw key bytes or hex text
- encrypt & decrypt methods
- verify the constructed cipher against the check value

### KEK Bundle

Helper class to construct a TripleDES or AES key encryption key from a list of components.

### RSA

Common RSA operations for plugins to use. Targeting use-cases such as key extraction.

## Release

Releases are triggered with tagging. A sample release cycle would follow the following steps:

1. Bump the version in `VERSION.txt` file and push to master
2. Execute `git tag x.x.x` (same as the version in VERSION.txt) and `git push origin x.x.x`
