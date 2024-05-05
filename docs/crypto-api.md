# API Reference

## libsodium

**Description:** libsodium is a modern, easy-to-use software library for encryption, decryption, signatures, password hashing, and more.

### Elliptic Curve Cryptography (ECC)

**API:** libsodium provides functions for elliptic curve cryptography operations using various curves including Curve25519.

**Functions:**
- `crypto_box_keypair()`: Generate a pair of public and secret keys for asymmetric encryption.
- `crypto_box_easy()`: Encrypt a message using the recipient's public key.
- `crypto_box_open_easy()`: Decrypt a message using the recipient's secret key.
- `crypto_sign_keypair()`: Generate a pair of public and secret keys for digital signatures.
- `crypto_sign()`: Create a digital signature for a message using the sender's secret key.
- `crypto_sign_open()`: Verify the digital signature using the sender's public key.

### Asymmetric Encryption

**API:** libsodium supports asymmetric encryption using public-private key pairs.

**Functions:**
- `crypto_box_seal()`: Encrypt a message for a recipient using their public key.
- `crypto_box_seal_open()`: Decrypt a message using the recipient's secret key.

### Symmetric Encryption

**API:** libsodium provides functions for symmetric encryption using shared secret keys.

**Functions:**
- `crypto_secretbox_keygen()`: Generate a secret key.
- `crypto_secretbox_easy()`: Encrypt a message using a secret key.
- `crypto_secretbox_open_easy()`: Decrypt a message using the same secret key.

### One-Way Hashing (SHA-512)

**API:** libsodium includes functions for one-way hashing using SHA-512.

**Functions:**
- `crypto_hash_sha512()`: Compute the SHA-512 hash of a message.

---

This API reference document outlines the usage of libsodium for various security purposes including elliptic curve cryptography, asymmetric encryption, symmetric encryption, and one-way hashing using SHA-512. Each section describes the relevant functions provided by the libsodium library for performing these operations.
