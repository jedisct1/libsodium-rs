# libsodium-rs

<div align="center">

[![Crates.io](https://img.shields.io/crates/v/libsodium-rs.svg)](https://crates.io/crates/libsodium-rs)
[![Documentation](https://docs.rs/libsodium-rs/badge.svg)](https://docs.rs/libsodium-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

A comprehensive, idiomatic Rust wrapper for [libsodium](https://libsodium.org), providing a safe and ergonomic API for cryptographic operations.

## Features

- **Complete Coverage**: Implements the entire libsodium API for Rust
- **Memory Safety**: Ensures secure memory handling with automatic clearing of sensitive data
- **Type Safety**: Leverages Rust's type system to prevent misuse of cryptographic primitives
- **Extensive Testing**: Comprehensive test suite covering all functionality
- **Minimal Dependencies**: Uses only a small set of carefully selected dependencies beyond libsodium itself

## Supported Cryptographic Operations

_Note: This is a non-exhaustive list of the supported algorithms and operations_

- **Public-key Cryptography**: Encryption, signatures, and key exchange
  - X25519, Ed25519, Curve25519, Ristretto255
  - XSalsa20-Poly1305, XChaCha20-Poly1305
  - Key exchange with X25519 and Ed25519 conversions
- **Secret-key Cryptography**: Authenticated encryption
  - ChaCha20-Poly1305, XChaCha20-Poly1305
  - AES-256-GCM
  - AEGIS-128L and AEGIS-256
- **Message Authentication**: HMAC and Poly1305
- **Hashing**: SHA-256, SHA-512, BLAKE2b
- **Password Hashing**: Argon2, Scrypt
- **Key Derivation**: HKDF, BLAKE2b-based KDF
- **Random Number Generation**: Secure random bytes
- **Secret Stream**: XChaCha20-Poly1305 based streaming encryption
- **One-time Authentication**: Poly1305
- **Stream Ciphers**: ChaCha20, Salsa20, XSalsa20
- **Secure Memory Management**: Memory locking, secure zeroing, and protected vectors for sensitive data

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
libsodium-rs = "0.2"
```

This crate requires libsodium to be installed on your system. Installation instructions for various platforms:

### Linux

```bash
# Debian/Ubuntu
sudo apt-get install libsodium-dev

# Fedora
sudo dnf install libsodium-devel

# Arch Linux
sudo pacman -S libsodium
```

### macOS

```bash
brew install libsodium
```

### Windows

Install libsodium using [vcpkg](https://github.com/microsoft/vcpkg):

```bash
vcpkg install libsodium:x64-windows-static
```

## Usage Examples

### Authenticated Encryption

```rust
use libsodium_rs::{self, ensure_init};
use libsodium_rs::crypto_aead::xchacha20poly1305;

fn main() {
    // Initialize libsodium
    ensure_init().expect("Failed to initialize libsodium");

    // Generate a random key
    let key = xchacha20poly1305::Key::generate();

    // Generate a random nonce
    let nonce = xchacha20poly1305::Nonce::generate();

    // Message to encrypt
    let message = b"Hello, libsodium!";

    // Optional additional authenticated data
    let additional_data = b"Important metadata";

    // Encrypt the message
    let ciphertext = xchacha20poly1305::encrypt(
        message,
        Some(additional_data),
        &nonce,
        &key,
    ).unwrap();

    // Decrypt the message
    let decrypted = xchacha20poly1305::decrypt(
        &ciphertext,
        Some(additional_data),
        &nonce,
        &key,
    ).unwrap();

    assert_eq!(message, &decrypted[..]);
}
```

### Public-key Cryptography

```rust
use libsodium_rs::{self, ensure_init};
use libsodium_rs::crypto_box;

fn main() {
    // Initialize libsodium
    ensure_init().expect("Failed to initialize libsodium");

    // Generate key pairs for Alice and Bob
    let alice_keypair = crypto_box::KeyPair::generate().unwrap();
    let alice_pk = alice_keypair.public_key;
    let alice_sk = alice_keypair.secret_key;
    let bob_keypair = crypto_box::KeyPair::generate().unwrap();
    let bob_pk = bob_keypair.public_key;
    let bob_sk = bob_keypair.secret_key;

    // Generate a random nonce
    let nonce = crypto_box::Nonce::generate();

    // Alice encrypts a message for Bob
    let message = b"Secret message for Bob";
    let ciphertext = crypto_box::seal(message, &nonce, &bob_pk, &alice_sk).unwrap();

    // Bob decrypts the message from Alice
    let decrypted = crypto_box::open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();

    assert_eq!(message, &decrypted[..]);
}
```

### Digital Signatures with Ed25519

```rust
use libsodium_rs::{self, ensure_init};
use libsodium_rs::crypto_sign;

fn main() {
    // Initialize libsodium
    ensure_init().expect("Failed to initialize libsodium");

    // Generate a signing key pair
    let keypair = crypto_sign::KeyPair::generate().unwrap();
    let public_key = keypair.public_key;
    let secret_key = keypair.secret_key;

    // Message to sign
    let message = b"Sign this message";

    // Sign the message
    let signed_message = crypto_sign::sign(message, &secret_key).unwrap();

    // Verify the signature and get the original message
    let verified_message = crypto_sign::verify(&signed_message, &public_key).unwrap();

    assert_eq!(message, &verified_message[..]);

    // Alternatively, use detached signatures
    let signature = crypto_sign::sign_detached(message, &secret_key).unwrap();

    // Verify the detached signature
    let is_valid = crypto_sign::verify_detached(&signature, message, &public_key);
    assert!(is_valid);
}
```

### Key Exchange with X25519

```rust
use libsodium_rs as sodium;
use sodium::crypto_scalarmult::curve25519;
use sodium::ensure_init;
use sodium::crypto_hash::blake2b;

fn main() {
    // Initialize libsodium
    ensure_init().expect("Failed to initialize libsodium");

    // Generate key pairs for Alice and Bob
    let alice_secret = curve25519::scalar_random().unwrap();
    let alice_public = curve25519::scalarmult_base(&alice_secret).unwrap();

    let bob_secret = curve25519::scalar_random().unwrap();
    let bob_public = curve25519::scalarmult_base(&bob_secret).unwrap();

    // Alice computes shared secret
    let alice_shared = curve25519::scalarmult(&alice_secret, &bob_public).unwrap();

    // Bob computes shared secret
    let bob_shared = curve25519::scalarmult(&bob_secret, &alice_public).unwrap();

    // IMPORTANT: Always hash the shared secret before using it as a key
    // Use a cryptographically secure hash function like BLAKE2b
    let alice_key = blake2b::hash(32, &alice_shared, None, None).unwrap();
    let bob_key = blake2b::hash(32, &bob_shared, None, None).unwrap();

    assert_eq!(alice_key, bob_key);
}
```

### Secure Memory Management

```rust
use libsodium_rs::{self, ensure_init};
use libsodium_rs::utils::vec_utils;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize libsodium
    ensure_init()?;

    // Create a secure vector for sensitive data (e.g., a cryptographic key)
    let mut secure_key = vec_utils::secure_vec::<u8>(32)?;

    // Fill it with some data
    for i in 0..secure_key.len() {
        secure_key[i] = i as u8;
    }

    // Use the secure key for operations...

    // Explicitly clear the memory if needed before deallocation
    secure_key.clear();

    // When secure_key goes out of scope, memory is automatically zeroed
    // and freed, preventing sensitive data from remaining in memory
    Ok(())
}
```

## Documentation

For detailed documentation, visit [docs.rs/libsodium-rs](https://docs.rs/libsodium-rs).

## Testing

This library includes an extensive test suite that covers all functionality. Run the tests with:

```bash
cargo test
```

Each cryptographic primitive has its own set of tests, including:

- Correctness tests for encryption/decryption
- Compatibility tests with NaCl
- Edge case handling
- Key and nonce generation
- Type safety and trait implementations

## Security

This library is a wrapper around libsodium, which is widely regarded as a secure, audited cryptographic library. However, please note:

- Always keep private keys secure
- Use unique nonces for each encryption operation (use the provided `Nonce::generate()` methods)
- Never reuse nonces with the same key
- Always hash the output of scalar multiplication functions before using them as cryptographic keys
- Be aware of the cofactor issues when using Ed25519 and Curve25519 (cofactor of 8)
- For protocols requiring a prime-order group, consider using Ristretto255
- Always use cryptographically secure random values for secret keys
- Ed25519 signatures are deterministic, eliminating the need for a secure random number generator during signing
- The shared secret established through X25519 is automatically hashed before being used as an encryption key in crypto_box
- When implementing key exchange protocols manually, always hash the shared secret before using it as a key
- Verify that public keys are on the correct curve before using them
- Follow best practices for cryptographic implementations
- Report security issues responsibly

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
