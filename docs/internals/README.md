# Dhole-Cryptography Internals

## Primitives and Constructions

### Asymmetric

* Key Exchange
  * Birationally equivalent X25519 keys derived from Ed25519 
  * X25519 + BLAKE2b (see `crypto_kx()` from libsodium)
* Seal
  * X25519 + BLAKE2b
  * Symmetric Encryption with ephemeral public key as AAD
* Encryption
  * Sign then Seal,
  * Unseal then Verify; only return plaintext if signature passes
* Signatures
  * Ed25519 with additional 32 bytes of randomness so other
    implementations can resist fault attacks

### Symmetric

* Authentication
  * Subkey derived with BLAKE2b-MAC with the key set to the domain separation
    constant, `DHOLEcrypto-Domain5eparatorConstant`.
  * HMAC-SHA512 truncated to 256 bits
* Encryption (AEAD)
  * XChaCha20-Poly1305
