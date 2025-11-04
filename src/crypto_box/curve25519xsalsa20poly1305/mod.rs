//! Curve25519-XSalsa20-Poly1305 Public-Key Authenticated Encryption
//!
//! This module provides public-key authenticated encryption using the Curve25519-XSalsa20-Poly1305
//! algorithm. It combines the Curve25519 elliptic curve key exchange with the XSalsa20 stream cipher
//! and the Poly1305 message authentication code.
//!
//! ## Features
//!
//! - **Public-key cryptography**: Allows secure communication without a pre-shared secret
//! - **Authenticated encryption**: Provides both confidentiality and integrity
//! - **High security**: Uses 256-bit keys and 192-bit nonces
//! - **NaCl compatibility**: Compatible with the original NaCl crypto_box implementation
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
//! # use libsodium_rs::crypto_box::curve25519xsalsa20poly1305;
//! # use libsodium_rs::ensure_init;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # ensure_init()?;
//! // Generate a key pair for Alice
//! let alice_keypair = curve25519xsalsa20poly1305::KeyPair::generate()?;
//!
//! // Generate a key pair for Bob
//! let bob_keypair = curve25519xsalsa20poly1305::KeyPair::generate()?;
//!
//! // Generate a nonce
//! let nonce = curve25519xsalsa20poly1305::Nonce::generate();
//!
//! // Alice encrypts a message for Bob using Bob's public key
//! let message = b"Hello, Bob!";
//! let ciphertext = curve25519xsalsa20poly1305::encrypt(
//!     message,
//!     &nonce,
//!     &bob_keypair.public_key,
//!     &alice_keypair.secret_key,
//! )?;
//!
//! // Bob decrypts the message using his secret key and Alice's public key
//! let decrypted = curve25519xsalsa20poly1305::decrypt(
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
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES as usize;
/// Number of bytes in a secret key
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES as usize;
/// Number of bytes in a nonce
pub const NONCEBYTES: usize =
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_NONCEBYTES as usize;

/// A nonce (number used once) for curve25519xsalsa20poly1305 operations
///
/// This struct represents a nonce for use with the curve25519xsalsa20poly1305 encryption.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// curve25519xsalsa20poly1305 uses a 192-bit (24-byte) nonce, which makes it suitable for
/// randomly generated nonces as the probability of collision is extremely low.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    /// Generate a random nonce for use with curve25519xsalsa20poly1305 functions
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

impl AsRef<Nonce> for Nonce {
    fn as_ref(&self) -> &Nonce {
        self
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
pub const MACBYTES: usize = libsodium_sys::crypto_box_curve25519xsalsa20poly1305_MACBYTES as usize;
/// Number of bytes in a seed
pub const SEEDBYTES: usize =
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_SEEDBYTES as usize;
/// Number of bytes in a precomputed key
pub const BEFORENMBYTES: usize =
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES as usize;
/// Number of zero bytes required for NaCl compatibility
pub const ZEROBYTES: usize =
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_ZEROBYTES as usize;
/// Number of zero bytes required in ciphertext for NaCl compatibility
pub const BOXZEROBYTES: usize =
    libsodium_sys::crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES as usize;

/// A public key for curve25519xsalsa20poly1305 encryption
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

impl PublicKey {
    /// Create a public key from bytes
    ///
    /// # Arguments
    /// * `bytes` - The bytes to create the public key from
    ///
    /// # Returns
    /// * `Result<PublicKey>` - A public key or an error if the bytes have the wrong length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLICKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "public key must be exactly {PUBLICKEYBYTES} bytes"
            )));
        }

        let mut pk = [0u8; PUBLICKEYBYTES];
        pk.copy_from_slice(bytes);
        Ok(Self(pk))
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

impl AsRef<PublicKey> for PublicKey {
    fn as_ref(&self) -> &PublicKey {
        self
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

/// A secret key for curve25519xsalsa20poly1305 encryption
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

impl SecretKey {
    /// Create a secret key from bytes
    ///
    /// # Arguments
    /// * `bytes` - The bytes to create the secret key from
    ///
    /// # Returns
    /// * `Result<SecretKey>` - A secret key or an error if the bytes have the wrong length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRETKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "secret key must be exactly {SECRETKEYBYTES} bytes"
            )));
        }

        let mut sk = [0u8; SECRETKEYBYTES];
        sk.copy_from_slice(bytes);
        Ok(Self(sk))
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

impl AsRef<SecretKey> for SecretKey {
    fn as_ref(&self) -> &SecretKey {
        self
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

/// A precomputed shared key for curve25519xsalsa20poly1305 encryption
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PrecomputedKey([u8; BEFORENMBYTES]);

impl PrecomputedKey {
    /// Create a precomputed key from bytes
    ///
    /// # Arguments
    /// * `bytes` - The bytes to create the precomputed key from
    ///
    /// # Returns
    /// * `Result<PrecomputedKey>` - A precomputed key or an error if the bytes have the wrong length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BEFORENMBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "precomputed key must be exactly {BEFORENMBYTES} bytes"
            )));
        }

        let mut k = [0u8; BEFORENMBYTES];
        k.copy_from_slice(bytes);
        Ok(Self(k))
    }

    /// Get the bytes of the precomputed key
    ///
    /// # Returns
    /// * `&[u8; BEFORENMBYTES]` - A reference to the precomputed key bytes
    pub fn as_bytes(&self) -> &[u8; BEFORENMBYTES] {
        &self.0
    }

    /// Create a precomputed key from a fixed-size byte array
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly BEFORENMBYTES length
    ///
    /// # Returns
    /// * `Self` - A new precomputed key
    pub const fn from_bytes_exact(bytes: [u8; BEFORENMBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<PrecomputedKey> for PrecomputedKey {
    fn as_ref(&self) -> &PrecomputedKey {
        self
    }
}

impl AsRef<[u8]> for PrecomputedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PrecomputedKey {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; BEFORENMBYTES]> for PrecomputedKey {
    fn from(bytes: [u8; BEFORENMBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<PrecomputedKey> for [u8; BEFORENMBYTES] {
    fn from(key: PrecomputedKey) -> [u8; BEFORENMBYTES] {
        key.0
    }
}

/// A key pair for curve25519xsalsa20poly1305 encryption
///
/// This struct represents a public key and secret key pair for use with the
/// curve25519xsalsa20poly1305 authenticated encryption algorithm.
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
            libsodium_sys::crypto_box_curve25519xsalsa20poly1305_keypair(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "keypair generation failed".into(),
            ));
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
            let ret = libsodium_sys::crypto_box_curve25519xsalsa20poly1305_seed_keypair(
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

    /// Encrypt a message for another party using this key pair
    ///
    /// # Arguments
    /// * `message` - The message to encrypt
    /// * `nonce` - The nonce to use for encryption
    /// * `recipient_public_key` - The recipient's public key
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The encrypted message or an error
    pub fn encrypt(
        &self,
        message: &[u8],
        nonce: impl AsRef<Nonce>,
        recipient_public_key: impl AsRef<PublicKey>,
    ) -> Result<Vec<u8>> {
        encrypt(message, nonce, recipient_public_key, &self.secret_key)
    }

    /// Decrypt a message sent to this key pair
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message
    /// * `nonce` - The nonce used for encryption
    /// * `sender_public_key` - The sender's public key
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The decrypted message or an error
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: impl AsRef<Nonce>,
        sender_public_key: impl AsRef<PublicKey>,
    ) -> Result<Vec<u8>> {
        decrypt(ciphertext, nonce, sender_public_key, &self.secret_key)
    }
}

impl From<(PublicKey, SecretKey)> for KeyPair {
    fn from((public_key, secret_key): (PublicKey, SecretKey)) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }
}

impl From<KeyPair> for (PublicKey, SecretKey) {
    fn from(val: KeyPair) -> Self {
        (val.public_key, val.secret_key)
    }
}

/// Precompute a shared key from a public key and a secret key
///
/// This function performs the key exchange operation and returns a shared key
/// that can be used for multiple encryption/decryption operations, improving performance.
///
/// # Arguments
/// * `public_key` - The public key of the other party
/// * `secret_key` - Your secret key
///
/// # Returns
/// * `Result<PrecomputedKey>` - The precomputed shared key or an error
pub fn beforenm(public_key: &PublicKey, secret_key: &SecretKey) -> Result<PrecomputedKey> {
    let mut k = [0u8; BEFORENMBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xsalsa20poly1305_beforenm(
            k.as_mut_ptr(),
            public_key.as_bytes().as_ptr(),
            secret_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "precomputed key generation failed".into(),
        ));
    }

    Ok(PrecomputedKey(k))
}

/// Encrypt a message using XSalsa20-Poly1305 with a precomputed key
///
/// This function is more efficient when encrypting multiple messages for the same recipient.
/// It uses a precomputed shared key to improve performance when sending multiple messages
/// to the same recipient.
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption (must be unique for each message with the same key)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message with authentication tag
///
/// # Errors
/// Returns an error if the encryption operation fails
///
/// # Security Considerations
/// * The nonce must be unique for each message encrypted with the same key
/// * For random nonces, use `Nonce::generate()`
pub fn encrypt_afternm(
    message: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    let ciphertext_len = message.len() + MACBYTES;
    let mut ciphertext = vec![0u8; ciphertext_len];

    let result = unsafe {
        libsodium_sys::crypto_box_easy_afternm(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "XSalsa20-Poly1305 encryption with precomputed key failed".into(),
        ));
    }

    Ok(ciphertext)
}

/// Decrypt a message using XSalsa20-Poly1305 with a precomputed key
///
/// This function is more efficient when decrypting multiple messages from the same sender.
/// It uses a precomputed shared key to improve performance when receiving multiple messages
/// from the same sender.
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt (with authentication tag)
/// * `nonce` - Nonce used for encryption (must be the same as used for encryption)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message
///
/// # Errors
/// Returns an error if:
/// * The ciphertext is too short (less than MACBYTES)
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt_afternm(
    ciphertext: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "ciphertext must be at least {MACBYTES} bytes"
        )));
    }

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_open_easy_afternm(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::DecryptionError(
            "XSalsa20-Poly1305 authentication with precomputed key failed".into(),
        ));
    }

    Ok(message)
}

/// Encrypt a message using XSalsa20-Poly1305 with a nonce
///
/// This function encrypts a message using the XSalsa20-Poly1305 authenticated encryption
/// algorithm. It provides both confidentiality and authenticity for the message.
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption (must be unique for each message with the same key pair)
/// * `recipient_pk` - Recipient's public key
/// * `sender_sk` - Sender's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message with authentication tag
///
/// # Errors
/// Returns an error if the encryption operation fails
///
/// # Security Considerations
/// * The nonce must be unique for each message encrypted with the same key pair
/// * For random nonces, use `Nonce::generate()`
pub fn encrypt(
    message: &[u8],
    nonce: impl AsRef<Nonce>,
    recipient_pk: impl AsRef<PublicKey>,
    sender_sk: impl AsRef<SecretKey>,
) -> Result<Vec<u8>> {
    let nonce = nonce.as_ref();
    let recipient_pk = recipient_pk.as_ref();
    let sender_sk = sender_sk.as_ref();

    let ciphertext_len = message.len() + MACBYTES;
    let mut ciphertext = vec![0u8; ciphertext_len];

    let result = unsafe {
        libsodium_sys::crypto_box_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            recipient_pk.as_bytes().as_ptr(),
            sender_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "XSalsa20-Poly1305 encryption failed".into(),
        ));
    }

    Ok(ciphertext)
}

/// Decrypt a message using XSalsa20-Poly1305 with a nonce
///
/// This function decrypts a message that was encrypted using the XSalsa20-Poly1305
/// authenticated encryption algorithm. It verifies the authenticity of the ciphertext
/// before returning the decrypted message.
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt (with authentication tag)
/// * `nonce` - Nonce used for encryption (must be the same as used for encryption)
/// * `sender_pk` - Sender's public key
/// * `recipient_sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message
///
/// # Errors
/// Returns an error if:
/// * The ciphertext is too short (less than MACBYTES)
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt(
    ciphertext: &[u8],
    nonce: impl AsRef<Nonce>,
    sender_pk: impl AsRef<PublicKey>,
    recipient_sk: impl AsRef<SecretKey>,
) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "ciphertext must be at least {MACBYTES} bytes"
        )));
    }

    let nonce = nonce.as_ref();
    let sender_pk = sender_pk.as_ref();
    let recipient_sk = recipient_sk.as_ref();

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            sender_pk.as_bytes().as_ptr(),
            recipient_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::DecryptionError(
            "XSalsa20-Poly1305 authentication failed".into(),
        ));
    }

    Ok(message)
}

/// NaCl compatibility: Encrypt a message using XSalsa20-Poly1305 with zero padding
///
/// This function is provided for compatibility with the NaCl API.
/// It requires the message to be padded with ZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_message` - Message to encrypt, with ZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce for encryption
/// * `recipient_pk` - Recipient's public key
/// * `sender_sk` - Sender's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message (with BOXZEROBYTES zero bytes at the beginning) or an error
pub fn encrypt_nacl(
    padded_message: &[u8],
    nonce: &Nonce,
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
) -> Result<Vec<u8>> {
    if padded_message.len() < ZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded message must be at least {ZEROBYTES} bytes"
        )));
    }

    // Verify that the first ZEROBYTES bytes of the message are all 0
    if padded_message.iter().take(ZEROBYTES).any(|&byte| byte != 0) {
        return Err(SodiumError::InvalidInput(format!(
            "first {ZEROBYTES} bytes of padded message must be zero"
        )));
    }

    let mut ciphertext = vec![0u8; padded_message.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xsalsa20poly1305(
            ciphertext.as_mut_ptr(),
            padded_message.as_ptr(),
            padded_message.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            recipient_pk.as_bytes().as_ptr(),
            sender_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok(ciphertext)
}

/// NaCl compatibility: Decrypt a message using XSalsa20-Poly1305 with zero padding
///
/// This function is provided for compatibility with the NaCl API.
/// The ciphertext must have BOXZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_ciphertext` - Ciphertext to decrypt, with BOXZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce used for encryption
/// * `sender_pk` - Sender's public key
/// * `recipient_sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message (with ZEROBYTES zero bytes at the beginning) or an error
pub fn decrypt_nacl(
    padded_ciphertext: &[u8],
    nonce: &Nonce,
    sender_pk: &PublicKey,
    recipient_sk: &SecretKey,
) -> Result<Vec<u8>> {
    if padded_ciphertext.len() < BOXZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded ciphertext must be at least {BOXZEROBYTES} bytes"
        )));
    }

    // Verify that the first BOXZEROBYTES bytes of the ciphertext are all 0
    if padded_ciphertext
        .iter()
        .take(BOXZEROBYTES)
        .any(|&byte| byte != 0)
    {
        return Err(SodiumError::InvalidInput(format!(
            "first {BOXZEROBYTES} bytes of padded ciphertext must be zero"
        )));
    }

    let mut message = vec![0u8; padded_ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xsalsa20poly1305_open(
            message.as_mut_ptr(),
            padded_ciphertext.as_ptr(),
            padded_ciphertext.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            sender_pk.as_bytes().as_ptr(),
            recipient_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// NaCl compatibility: Encrypt a message using XSalsa20-Poly1305 with zero padding and a precomputed key
///
/// This function is provided for compatibility with the NaCl API.
/// It requires the message to be padded with ZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_message` - Message to encrypt, with ZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce for encryption
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message (with BOXZEROBYTES zero bytes at the beginning) or an error
pub fn encrypt_nacl_afternm(
    padded_message: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    if padded_message.len() < ZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded message must be at least {ZEROBYTES} bytes"
        )));
    }

    // Verify that the first ZEROBYTES bytes of the message are all 0
    if padded_message.iter().take(ZEROBYTES).any(|&byte| byte != 0) {
        return Err(SodiumError::InvalidInput(format!(
            "first {ZEROBYTES} bytes of padded message must be zero"
        )));
    }

    let mut ciphertext = vec![0u8; padded_message.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xsalsa20poly1305_afternm(
            ciphertext.as_mut_ptr(),
            padded_message.as_ptr(),
            padded_message.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok(ciphertext)
}

/// NaCl compatibility: Decrypt a message using XSalsa20-Poly1305 with zero padding and a precomputed key
///
/// This function is provided for compatibility with the NaCl API.
/// The ciphertext must have BOXZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_ciphertext` - Ciphertext to decrypt, with BOXZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce used for encryption
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message (with ZEROBYTES zero bytes at the beginning) or an error
pub fn decrypt_nacl_afternm(
    padded_ciphertext: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    if padded_ciphertext.len() < BOXZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded ciphertext must be at least {BOXZEROBYTES} bytes"
        )));
    }

    // Verify that the first BOXZEROBYTES bytes of the ciphertext are all 0
    if padded_ciphertext
        .iter()
        .take(BOXZEROBYTES)
        .any(|&byte| byte != 0)
    {
        return Err(SodiumError::InvalidInput(format!(
            "first {BOXZEROBYTES} bytes of padded ciphertext must be zero"
        )));
    }

    let mut message = vec![0u8; padded_ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_curve25519xsalsa20poly1305_open_afternm(
            message.as_mut_ptr(),
            padded_ciphertext.as_ptr(),
            padded_ciphertext.len() as libc::c_ulonglong,
            nonce.as_bytes().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
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
        assert_eq!(
            keypair1.public_key.as_bytes(),
            keypair2.public_key.as_bytes()
        );
        assert_eq!(
            keypair1.secret_key.as_bytes(),
            keypair2.secret_key.as_bytes()
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let nonce = Nonce::generate();
        let message = b"Hello, XSalsa20-Poly1305!";

        // Alice encrypts a message for Bob
        let ciphertext = encrypt(message, &nonce, &bob.public_key, &alice.secret_key).unwrap();

        // Bob decrypts the message from Alice
        let decrypted = decrypt(&ciphertext, &nonce, &alice.public_key, &bob.secret_key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_beforenm_afternm() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let nonce = Nonce::generate();
        let message = b"Hello, precomputed key!";

        // Alice precomputes a shared key with Bob
        let alice_precomputed = beforenm(&bob.public_key, &alice.secret_key).unwrap();

        // Bob precomputes a shared key with Alice
        let bob_precomputed = beforenm(&alice.public_key, &bob.secret_key).unwrap();

        // Alice encrypts a message for Bob using the precomputed key
        let ciphertext = encrypt_afternm(message, &nonce, &alice_precomputed).unwrap();

        // Bob decrypts the message from Alice using the precomputed key
        let decrypted = decrypt_afternm(&ciphertext, &nonce, &bob_precomputed).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_nacl_compatibility() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let nonce = Nonce::generate();

        // Create a message with ZEROBYTES zero bytes at the beginning
        let message = b"Hello, NaCl!";
        let mut padded_message = vec![0u8; ZEROBYTES + message.len()];
        padded_message[ZEROBYTES..].copy_from_slice(message);

        // Alice encrypts a message for Bob using NaCl compatibility mode
        let padded_ciphertext =
            encrypt_nacl(&padded_message, &nonce, &bob.public_key, &alice.secret_key).unwrap();

        // Bob decrypts the message from Alice using NaCl compatibility mode
        let decrypted_padded = decrypt_nacl(
            &padded_ciphertext,
            &nonce,
            &alice.public_key,
            &bob.secret_key,
        )
        .unwrap();

        assert_eq!(decrypted_padded, padded_message);
    }

    #[test]
    fn test_nacl_compatibility_afternm() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let nonce = Nonce::generate();

        // Create a message with ZEROBYTES zero bytes at the beginning
        let message = b"Hello, NaCl afternm!";
        let mut padded_message = vec![0u8; ZEROBYTES + message.len()];
        padded_message[ZEROBYTES..].copy_from_slice(message);

        // Alice precomputes a shared key with Bob
        let alice_precomputed = beforenm(&bob.public_key, &alice.secret_key).unwrap();

        // Bob precomputes a shared key with Alice
        let bob_precomputed = beforenm(&alice.public_key, &bob.secret_key).unwrap();

        // Alice encrypts a message for Bob using NaCl compatibility mode with precomputed key
        let padded_ciphertext =
            encrypt_nacl_afternm(&padded_message, &nonce, &alice_precomputed).unwrap();

        // Bob decrypts the message from Alice using NaCl compatibility mode with precomputed key
        let decrypted_padded =
            decrypt_nacl_afternm(&padded_ciphertext, &nonce, &bob_precomputed).unwrap();

        assert_eq!(decrypted_padded, padded_message);
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

    #[test]
    fn test_precomputedkey_traits() {
        // First, create a valid precomputed key
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let precomputed = beforenm(&bob.public_key, &alice.secret_key).unwrap();

        // Test AsRef<[u8]>
        let slice_ref: &[u8] = precomputed.as_ref();
        assert_eq!(slice_ref.len(), BEFORENMBYTES);

        // Get bytes for testing
        let bytes_ref = precomputed.as_bytes();

        // Test TryFrom<&[u8]>
        let key = PrecomputedKey::try_from(&bytes_ref[..]).unwrap();
        assert_eq!(key.as_bytes(), bytes_ref);

        // Test invalid length
        let invalid_bytes = [0x42; BEFORENMBYTES - 1];
        assert!(PrecomputedKey::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; BEFORENMBYTES]>
        let mut bytes = [0u8; BEFORENMBYTES];
        bytes.copy_from_slice(bytes_ref);
        let key2 = PrecomputedKey::from(bytes);
        assert_eq!(key2.as_bytes(), &bytes);

        // Test From<PrecomputedKey> for [u8; BEFORENMBYTES]
        let extracted: [u8; BEFORENMBYTES] = key2.into();
        assert_eq!(extracted, bytes);
    }
}
