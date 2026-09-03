This repo provides a list of utility modules for common crypto operations.

### AES

- factory methods to construct an AES-GCM cipher with a 96-bit nonce from the input raw key bytes or hex text
- encrypt & decrypt methods, the output ciphertext is prefixed with the random nonce.
- verify the constructed cipher against the check value

Prefer AES-GCM. Only reach for AES-CBC below when an external protocol mandates it.

### AES-CBC

`CBCCipher` is provided for interoperability with external protocols that mandate
CBC. It is a separate type from the AES-GCM `Cipher` because it offers a
materially weaker guarantee.

> **AES-CBC provides confidentiality only. It is not authenticated.**
>
> - A modified initialisation vector or ciphertext will usually still decrypt
>   **without error**, producing attacker-influenced plaintext. Decryption
>   succeeding is not evidence that a message is genuine.
> - Callers **must** authenticate the initialisation vector together with the
>   ciphertext by separate means (for example an HMAC over both) and **must**
>   verify it before decrypting.
> - A PKCS#7 padding error is **not** an integrity check. Never surface padding
>   failures to an untrusted caller: doing so exposes a
>   [padding oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack) that
>   can be used to recover plaintext.

- factory methods to construct an AES-CBC cipher from the raw key bytes or hex text
- `Encrypt` / `Decrypt` operate on block-aligned input with no padding
- `EncryptPadded` / `DecryptPadded` apply and remove PKCS#7 padding (RFC 5652 §6.3)
- `GenerateCBCIV` returns a random 16-byte initialisation vector
- verify the constructed cipher against the check value; the value depends only
  on the key, so it matches the one `Cipher` reports for the same key

Parameters:

| Parameter | Requirement |
| --- | --- |
| Key | 16, 24, or 32 bytes |
| Initialisation vector | Always exactly 16 bytes, for every key size |
| Input to `Encrypt` / `Decrypt` | Non-zero multiple of 16 bytes |
| Input to `EncryptPadded` | Any length, including empty |
| Padding | PKCS#7 via the `*Padded` methods, otherwise agreed by the protocol |
| Authentication | Not provided. Supplied separately by the caller |

The initialisation vector is always supplied by the caller and is never prefixed
to, or stripped from, the ciphertext. How it is transported or derived is a
property of the surrounding protocol, so that framing is left to the caller.

Generate a fresh initialisation vector for every message with `GenerateCBCIV`.
NIST SP 800-38A requires it to be unpredictable; reusing one under the same key
leaks whether two messages share a leading block. It need not be secret and may
travel beside the ciphertext, but it must be integrity protected along with it.

A fixed or all-zero initialisation vector is accepted only because an external
protocol may mandate one. That is an exception to the requirement above, not an
option to pick freely, and it should be justified by the protocol specification.

```go
cipher, err := aes.CreateCBCFromKeyString(hexKey)
iv, err := aes.GenerateCBCIV()
cipherBytes, err := cipher.EncryptPadded(plainBytes, iv)
// Now authenticate iv and cipherBytes together, and transmit the tag alongside.
```

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
