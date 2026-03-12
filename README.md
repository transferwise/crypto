This repo provides a list of utility modules for common crypto operations.

### AES

- factory methods to construct an AES-GCM cipher with a 96-bit nonce from the input raw key bytes
- encrypt & decrypt methods, the output ciphertext is prefixed with the random nonce.

### DES

- factory methods to construct an DES or 3DES cipher from the raw key bytes or hex text
- encrypt & decrypt methods
- verify the constructed cipher against the check value

### KEK Bundle

Helper class to construct a 3DES key encryption key from a list of components.

### RSA

Common RSA operations for plugins to use. Targeting use-cases such as key extraction.

## Release

Releases are triggered with tagging. A sample release cycle would follow the following steps:

1. Bump the version in `VERSION.txt` file and push to master
2. Execute `git tag x.x.x` (same as the version in VERSION.txt) and `git push origin x.x.x`
