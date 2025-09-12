//! Curve25519-XChaCha20-Poly1305 Public-Key Authenticated Encryption
//!
//! This module provides public-key authenticated encryption using the Curve25519-XChaCha20-Poly1305
//! algorithm. It combines the Curve25519 elliptic curve key exchange with the XChaCha20 stream cipher
//! and the Poly1305 message authentication code.
//!
//! ## Features
//!
//! - **Public-key cryptography**: Allows secure communication without a pre-shared secret
//! - **Authenticated encryption**: Provides both confidentiality and integrity
//! - **High security**: Uses 256-bit keys and 192-bit nonces
//! - **Large nonce size**: 192-bit nonces make random nonce generation safe
//! - **Modern cipher**: Uses XChaCha20 instead of XSalsa20 for improved performance
//!
//! ## Security Considerations
//!
//! - Always use a unique nonce for each encryption with the same key pair
//! - The nonce can be public, but must never be reused with the same key pair
//! - Keep secret keys secure and never share them
//! - Public keys can be freely distributed
//!
//! ## Example Usage
//!
//! ```
//! # use libsodium_rs::crypto_box::curve25519xchacha20poly1305;
//! # use libsodium_rs::ensure_init;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # ensure_init()?;
//! // Generate a key pair for Alice
//! let alice_keypair = curve25519xchacha20poly1305::KeyPair::generate()?;
//!
//! // Generate a key pair for Bob
//! let bob_keypair = curve25519xchacha20poly1305::KeyPair::generate()?;
//!
//! // Generate a nonce
//! let nonce = curve25519xchacha20poly1305::Nonce::generate();
//!
//! // Alice encrypts a message for Bob using Bob's public key
//! let message = b"Hello, Bob!";
//! let ciphertext = curve25519xchacha20poly1305::encrypt(
//!     message,
//!     &nonce,
//!     &bob_keypair.public_key,
//!     &alice_keypair.secret_key,
//! )?;
//!
//! // Bob decrypts the message using his secret key and Alice's public key
//! let decrypted = curve25519xchacha20poly1305::decrypt(
//!     &ciphertext,
//!     &nonce,
//!     &alice_keypair.public_key,
//!     &bob_keypair.secret_key,
//! )?;
//!
//! assert_eq!(message, &decrypted[..]);
//! # Ok(())
//! # }
//! ```

use crate::{Result, SodiumError};
use libc;
use std::convert::TryFrom;

/// Number of bytes in a public key
pub const PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize;
/// Number of bytes in a secret key
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize;
/// Number of bytes in a nonce
pub const NONCEBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;

/// A nonce (number used once) for curve25519xchacha20poly1305 operations
///
/// This struct represents a nonce for use with the curve25519xchacha20poly1305 encryption.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// curve25519xchacha20poly1305 uses a 192-bit (24-byte) nonce, which makes it suitable for
/// randomly generated nonces as the probability of collision is extremely low.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    /// Generate a random nonce for use with curve25519xchacha20poly1305 functions
    ///
    /// This method generates a random nonce of the appropriate size (NONCEBYTES)
    /// for use with the encryption and decryption functions in this module.
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A random nonce
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCEBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from a byte array of the correct length
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A byte array of length NONCEBYTES
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A nonce initialized with the provided bytes
    pub fn from_bytes(bytes: [u8; NONCEBYTES]) -> Self {
        Self(bytes)
    }

    /// Create a nonce from a slice, checking that the length is correct
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A slice of bytes
    ///
    /// ## Returns
    ///
    /// * `Result<Nonce>` - A nonce or an error if the slice has the wrong length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NONCEBYTES {
            return Err(SodiumError::InvalidNonce(format!(
                "nonce must be exactly {NONCEBYTES} bytes"
            )));
        }

        let mut nonce_bytes = [0u8; NONCEBYTES];
        nonce_bytes.copy_from_slice(bytes);
        Ok(Self(nonce_bytes))
    }

    /// Get the underlying bytes of the nonce
    ///
    /// ## Returns
    ///
    /// * `&[u8; NONCEBYTES]` - A reference to the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NONCEBYTES] {
        &self.0
    }

    /// Get a mutable reference to the underlying byte array
    ///
    /// ## Returns
    ///
    /// * `&mut [u8; NONCEBYTES]` - A mutable reference to the nonce bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; NONCEBYTES] {
        &mut self.0
    }

    /// Create a nonce from a fixed-size byte array
    ///
    /// ## Arguments
    ///
    /// * `bytes` - Byte array of exactly NONCEBYTES length
    ///
    /// ## Returns
    ///
    /// * `Self` - A new nonce
    pub const fn from_bytes_exact(bytes: [u8; NONCEBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from_slice(slice)
    }
}

impl From<[u8; NONCEBYTES]> for Nonce {
    fn from(bytes: [u8; NONCEBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Nonce> for [u8; NONCEBYTES] {
    fn from(nonce: Nonce) -> [u8; NONCEBYTES] {
        nonce.0
    }
}

/// Number of bytes in a MAC (message authentication code)
pub const MACBYTES: usize = libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;
/// Number of bytes in a seed
pub const SEEDBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize;
/// Number of additional bytes for a sealed box
pub const SEALBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize;

/// A public key for curve25519xchacha20poly1305 encryption
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

impl PublicKey {
    /// Create a public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLICKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "public key must be exactly {PUBLICKEYBYTES} bytes"
            )));
        }

        let mut pk = [0u8; PUBLICKEYBYTES];
        pk.copy_from_slice(bytes);
        Ok(PublicKey(pk))
    }

    /// Get the bytes of the public key
    ///
    /// # Returns
    /// * `&[u8; PUBLICKEYBYTES]` - A reference to the public key bytes
    pub fn as_bytes(&self) -> &[u8; PUBLICKEYBYTES] {
        &self.0
    }

    /// Create a public key from a fixed-size byte array
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly PUBLICKEYBYTES length
    ///
    /// # Returns
    /// * `Self` - A new public key
    pub const fn from_bytes_exact(bytes: [u8; PUBLICKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; PUBLICKEYBYTES]> for PublicKey {
    fn from(bytes: [u8; PUBLICKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; PUBLICKEYBYTES] {
    fn from(key: PublicKey) -> [u8; PUBLICKEYBYTES] {
        key.0
    }
}

/// A secret key for curve25519xchacha20poly1305 encryption
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

impl SecretKey {
    /// Create a secret key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRETKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "secret key must be exactly {SECRETKEYBYTES} bytes"
            )));
        }

        let mut sk = [0u8; SECRETKEYBYTES];
        sk.copy_from_slice(bytes);
        Ok(SecretKey(sk))
    }

    /// Get the bytes of the secret key
    ///
    /// # Returns
    /// * `&[u8; SECRETKEYBYTES]` - A reference to the secret key bytes
    pub fn as_bytes(&self) -> &[u8; SECRETKEYBYTES] {
        &self.0
    }

    /// Create a secret key from a fixed-size byte array
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly SECRETKEYBYTES length
    ///
    /// # Returns
    /// * `Self` - A new secret key
    pub const fn from_bytes_exact(bytes: [u8; SECRETKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; SECRETKEYBYTES]> for SecretKey {
    fn from(bytes: [u8; SECRETKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<SecretKey> for [u8; SECRETKEYBYTES] {
    fn from(key: SecretKey) -> [u8; SECRETKEYBYTES] {
        key.0
    }
}

/// A key pair for curve25519xchacha20poly1305 encryption
///
/// This struct represents a public key and secret key pair for use with the
/// curve25519xchacha20poly1305 authenticated encryption algorithm.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Create a new key pair from a public key and a secret key
    ///
    /// # Arguments
    /// * `public_key` - The public key
    /// * `secret_key` - The secret key
    ///
    /// # Returns
    /// * `KeyPair` - A new key pair
    pub fn new(public_key: PublicKey, secret_key: SecretKey) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    /// Generate a random key pair
    ///
    /// # Returns
    /// * `Result<KeyPair>` - A randomly generated key pair or an error
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        let result = unsafe {
            libsodium_sys::crypto_box_curve25519xchacha20poly1305_keypair(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError("key generation failed".into()));
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Generate a key pair from a seed
    ///
    /// This method generates a deterministic key pair from a 32-byte seed.
    /// The same seed will always produce the same key pair.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != SEEDBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "seed must be exactly {SEEDBYTES} bytes"
            )));
        }

        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        unsafe {
            let ret = libsodium_sys::crypto_box_curve25519xchacha20poly1305_seed_keypair(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
                seed.as_ptr(),
            );
            if ret != 0 {
                return Err(SodiumError::OperationError(
                    "key generation from seed failed".into(),
                ));
            }
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Encrypt a message using XChaCha20-Poly1305 with a nonce
    ///
    /// This method encrypts a message for a recipient using the sender's secret key
    /// and the recipient's public key.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt
    /// * `nonce` - The nonce to use for encryption
    /// * `recipient_pk` - The recipient's public key
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The encrypted message or an error
    pub fn encrypt(
        &self,
        message: &[u8],
        nonce: &Nonce,
        recipient_pk: &PublicKey,
    ) -> Result<Vec<u8>> {
        encrypt(message, nonce, recipient_pk, &self.secret_key)
    }

    /// Decrypt a message using XChaCha20-Poly1305 with a nonce
    ///
    /// This method decrypts a message from a sender using the recipient's secret key
    /// and the sender's public key.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message
    /// * `nonce` - The nonce used for encryption
    /// * `sender_pk` - The sender's public key
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The decrypted message or an error
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce,
        sender_pk: &PublicKey,
    ) -> Result<Vec<u8>> {
        decrypt(ciphertext, nonce, sender_pk, &self.secret_key)
    }

    /// Encrypt a message using XChaCha20-Poly1305 with a detached MAC
    ///
    /// This method encrypts a message for a recipient using the sender's secret key
    /// and the recipient's public key, returning the ciphertext and MAC separately.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt
    /// * `nonce` - The nonce to use for encryption
    /// * `recipient_pk` - The recipient's public key
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, [u8; MACBYTES])>` - The encrypted message and MAC, or an error
    pub fn encrypt_detached(
        &self,
        message: &[u8],
        nonce: &Nonce,
        recipient_pk: &PublicKey,
    ) -> Result<(Vec<u8>, [u8; MACBYTES])> {
        encrypt_detached(message, nonce, recipient_pk, &self.secret_key)
    }

    /// Decrypt a message using XChaCha20-Poly1305 with a detached MAC
    ///
    /// This method decrypts a message from a sender using the recipient's secret key
    /// and the sender's public key, with a separately provided MAC.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message
    /// * `mac` - The MAC for authentication
    /// * `nonce` - The nonce used for encryption
    /// * `sender_pk` - The sender's public key
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The decrypted message or an error
    pub fn decrypt_detached(
        &self,
        ciphertext: &[u8],
        mac: &[u8; MACBYTES],
        nonce: &Nonce,
        sender_pk: &PublicKey,
    ) -> Result<Vec<u8>> {
        decrypt_detached(ciphertext, mac, nonce, sender_pk, &self.secret_key)
    }

    /// Encrypt a message using XChaCha20-Poly1305 without requiring the sender's public key (anonymous sender)
    ///
    /// This method encrypts a message for a recipient without revealing the sender's identity.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The sealed box or an error
    pub fn seal(&self, message: &[u8]) -> Result<Vec<u8>> {
        seal(message, &self.public_key)
    }

    /// Decrypt a message using XChaCha20-Poly1305 without requiring the sender's public key (anonymous sender)
    ///
    /// This method decrypts a message that was encrypted without revealing the sender's identity.
    ///
    /// # Arguments
    /// * `sealed_box` - The sealed box to decrypt
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The decrypted message or an error
    pub fn seal_open(&self, sealed_box: &[u8]) -> Result<Vec<u8>> {
        seal_open(sealed_box, &self.public_key, &self.secret_key)
    }
}

/// Encrypt a message using XChaCha20-Poly1305 with a nonce
pub fn encrypt(
    message: &[u8],
    nonce: &Nonce,
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
) -> Result<Vec<u8>> {
    let mut ciphertext = vec![0u8; message.len() + MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            recipient_pk.as_bytes().as_ptr(),
            sender_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok(ciphertext)
}

/// Decrypt a message using XChaCha20-Poly1305 with a nonce
pub fn decrypt(
    ciphertext: &[u8],
    nonce: &Nonce,
    sender_pk: &PublicKey,
    recipient_sk: &SecretKey,
) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            sender_pk.as_bytes().as_ptr(),
            recipient_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// Encrypt a message using XChaCha20-Poly1305 with detached MAC
pub fn encrypt_detached(
    message: &[u8],
    nonce: &Nonce,
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
) -> Result<(Vec<u8>, [u8; MACBYTES])> {
    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = [0u8; MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            recipient_pk.as_bytes().as_ptr(),
            sender_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok((ciphertext, mac))
}

/// Decrypt a message using XChaCha20-Poly1305 with detached MAC
pub fn decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8; MACBYTES],
    nonce: &Nonce,
    sender_pk: &PublicKey,
    recipient_sk: &SecretKey,
) -> Result<Vec<u8>> {
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_open_detached(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            sender_pk.as_bytes().as_ptr(),
            recipient_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// Encrypt a message using XChaCha20-Poly1305 without requiring the sender's secret key (anonymous sender)
pub fn seal(message: &[u8], recipient_pk: &PublicKey) -> Result<Vec<u8>> {
    let mut sealed_box = vec![0u8; message.len() + SEALBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_seal(
            sealed_box.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            recipient_pk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "sealed box encryption failed".into(),
        ));
    }

    Ok(sealed_box)
}

/// Decrypt a message using XChaCha20-Poly1305 without requiring the sender's public key (anonymous sender)
pub fn seal_open(
    sealed_box: &[u8],
    recipient_pk: &PublicKey,
    recipient_sk: &SecretKey,
) -> Result<Vec<u8>> {
    if sealed_box.len() < SEALBYTES {
        return Err(SodiumError::InvalidInput("sealed box too short".into()));
    }

    let mut message = vec![0u8; sealed_box.len() - SEALBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_seal_open(
            message.as_mut_ptr(),
            sealed_box.as_ptr(),
            sealed_box.len() as libc::c_ulonglong,
            recipient_pk.as_bytes().as_ptr(),
            recipient_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "sealed box decryption failed".into(),
        ));
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Random is used in other test functions

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), PUBLICKEYBYTES);
        assert_eq!(keypair.secret_key.as_bytes().len(), SECRETKEYBYTES);
    }

    #[test]
    fn test_seed_keypair() {
        let mut seed = [0u8; SEEDBYTES];
        crate::random::fill_bytes(&mut seed);
        let keypair1 = KeyPair::from_seed(&seed).unwrap();
        let keypair2 = KeyPair::from_seed(&seed).unwrap();

        // Same seed should produce the same key pair
        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.secret_key, keypair2.secret_key);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let nonce = Nonce::generate();
        let message = b"Hello, XChaCha20-Poly1305!";

        // Alice encrypts a message for Bob
        let ciphertext = encrypt(message, &nonce, &bob.public_key, &alice.secret_key).unwrap();

        // Bob decrypts the message from Alice
        let decrypted = decrypt(&ciphertext, &nonce, &alice.public_key, &bob.secret_key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_decrypt_detached() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let nonce = Nonce::generate();
        let message = b"Hello, XChaCha20-Poly1305 with detached MAC!";

        // Alice encrypts a message for Bob with detached MAC
        let (ciphertext, mac) =
            encrypt_detached(message, &nonce, &bob.public_key, &alice.secret_key).unwrap();

        // Bob decrypts the message from Alice with detached MAC
        let decrypted = decrypt_detached(
            &ciphertext,
            &mac,
            &nonce,
            &alice.public_key,
            &bob.secret_key,
        )
        .unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_seal_open() {
        let bob = KeyPair::generate().unwrap();
        let message = b"Anonymous message for Bob!";

        // Anonymous sender encrypts a message for Bob
        let sealed_box = seal(message, &bob.public_key).unwrap();

        // Bob decrypts the anonymous message
        let decrypted = seal_open(&sealed_box, &bob.public_key, &bob.secret_key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_nonce_traits() {
        // Test TryFrom<&[u8]>
        let bytes = [0x42; NONCEBYTES];
        let nonce = Nonce::try_from(&bytes[..]).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; NONCEBYTES - 1];
        assert!(Nonce::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; NONCEBYTES]>
        let bytes = [0x43; NONCEBYTES];
        let nonce2 = Nonce::from(bytes);
        assert_eq!(nonce2.as_bytes(), &bytes);

        // Test From<Nonce> for [u8; NONCEBYTES]
        let extracted: [u8; NONCEBYTES] = nonce2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let nonce3 = Nonce::generate();
        let slice_ref: &[u8] = nonce3.as_ref();
        assert_eq!(slice_ref.len(), NONCEBYTES);
    }

    #[test]
    fn test_publickey_traits() {
        // Test TryFrom<&[u8]>
        let bytes = [0x42; PUBLICKEYBYTES];
        let key = PublicKey::try_from(&bytes[..]).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; PUBLICKEYBYTES - 1];
        assert!(PublicKey::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; PUBLICKEYBYTES]>
        let bytes = [0x43; PUBLICKEYBYTES];
        let key2 = PublicKey::from(bytes);
        assert_eq!(key2.as_bytes(), &bytes);

        // Test From<PublicKey> for [u8; PUBLICKEYBYTES]
        let extracted: [u8; PUBLICKEYBYTES] = key2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let keypair = KeyPair::generate().unwrap();
        let slice_ref: &[u8] = keypair.public_key.as_ref();
        assert_eq!(slice_ref.len(), PUBLICKEYBYTES);
    }

    #[test]
    fn test_secretkey_traits() {
        // Test TryFrom<&[u8]>
        let bytes = [0x42; SECRETKEYBYTES];
        let key = SecretKey::try_from(&bytes[..]).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; SECRETKEYBYTES - 1];
        assert!(SecretKey::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; SECRETKEYBYTES]>
        let bytes = [0x43; SECRETKEYBYTES];
        let key2 = SecretKey::from(bytes);
        assert_eq!(key2.as_bytes(), &bytes);

        // Test From<SecretKey> for [u8; SECRETKEYBYTES]
        let extracted: [u8; SECRETKEYBYTES] = key2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let keypair = KeyPair::generate().unwrap();
        let slice_ref: &[u8] = keypair.secret_key.as_ref();
        assert_eq!(slice_ref.len(), SECRETKEYBYTES);
    }
}
