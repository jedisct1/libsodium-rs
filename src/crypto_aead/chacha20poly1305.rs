//! # ChaCha20-Poly1305-IETF Authenticated Encryption with Associated Data
//!
//! This module provides authenticated encryption and decryption using the
//! ChaCha20-Poly1305-IETF algorithm. This is a widely used AEAD cipher that combines
//! the ChaCha20 stream cipher with the Poly1305 message authentication code.
//! It is standardized in RFC 8439 (formerly RFC 7539).
//!
//! ## Algorithm Details
//!
//! ChaCha20-Poly1305 is a two-part construction:
//!
//! 1. **ChaCha20**: A stream cipher designed by Daniel J. Bernstein
//!    * Uses a 256-bit key for encryption
//!    * Uses a 96-bit nonce (12 bytes) in the IETF variant
//!    * Based on the ARX (Add-Rotate-XOR) design principle
//!    * Operates on 512-bit blocks using a 20-round function
//!
//! 2. **Poly1305**: A fast message authentication code (MAC)
//!    * Produces a 128-bit (16-byte) authentication tag
//!    * Authenticates both the ciphertext and the additional data
//!    * Uses a one-time key derived from the encryption key and nonce
//!
//! ## Features and Advantages
//!
//! - **Standardization**: Formally standardized in RFC 8439, providing interoperability
//! - **High performance**: Optimized for software implementations without requiring specialized hardware
//! - **Cross-platform efficiency**: Works efficiently on all platforms, from embedded devices to servers
//! - **Timing attack resistance**: The algorithm is designed to be constant-time, protecting against timing side-channels
//! - **Simplicity**: The algorithm is relatively simple to implement correctly
//! - **Strong security**: 256-bit keys provide robust protection
//!
//! ## Security Properties
//!
//! - **Confidentiality**: The encrypted message cannot be read without the secret key
//! - **Integrity**: Any modification to the ciphertext will be detected during decryption
//! - **Authenticity**: The receiver can verify that the message was created by someone with the secret key
//! - **Well-analyzed**: ChaCha20-Poly1305 has undergone extensive cryptanalysis and is widely trusted
//!
//! ## Nonce Considerations
//!
//! ChaCha20-Poly1305-IETF uses a 96-bit (12-byte) nonce, which is **NOT** large enough for safe
//! random generation. With a 96-bit nonce, the probability of a collision becomes significant
//! after encrypting approximately 2^32 messages with the same key.
//!
//! For safe nonce handling, use one of these approaches:
//!
//! 1. **Counter-based nonces**: Maintain a strictly increasing counter for each encryption
//!    with the same key. This is the recommended approach for ChaCha20-Poly1305.
//!
//! 2. **Use XChaCha20-Poly1305 instead**: If you need to encrypt many messages with the same key
//!    and cannot reliably maintain a counter, use XChaCha20-Poly1305 which has a 192-bit nonce
//!    that is safe for random generation.
//!
//! ## Security Considerations and Best Practices
//!
//! - **Nonce management**: Never reuse a nonce with the same key. Use a counter-based approach
//!   for generating nonces with ChaCha20-Poly1305.
//!
//! - **Key management**: Protect your secret keys. Consider using key derivation functions (KDFs)
//!   to derive encryption keys from passwords or master keys.
//!
//! - **Additional authenticated data (AAD)**: Not encrypted but is authenticated. Use it for metadata
//!   that doesn't need confidentiality but must be authenticated (e.g., message headers, timestamps).
//!
//! - **Authentication failures**: If authentication fails during decryption, the entire message is
//!   rejected and no plaintext is returned. Treat this as a potential attack.
//!
//! - **Ciphertext expansion**: The ciphertext will be larger than the plaintext by `ABYTES` (16 bytes)
//!   for the authentication tag.
//!
//! - **Detached mode**: For some applications, it may be beneficial to store the authentication tag
//!   separately from the ciphertext. Use the `encrypt_detached` and `decrypt_detached` functions for this.
//!
//! ## When to Use ChaCha20-Poly1305
//!
//! - When you need a standardized AEAD algorithm (RFC 8439)
//! - When you need interoperability with other systems
//! - When you can reliably maintain a counter for nonce generation
//! - When you need an algorithm that works efficiently on all platforms without hardware acceleration
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::chacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = chacha20poly1305::Key::generate();
//!
//! // Create a nonce
//! let nonce = chacha20poly1305::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Additional authenticated data (not encrypted, but authenticated)
//! let additional_data = b"Important metadata";
//!
//! // Encrypt the message
//! let ciphertext = chacha20poly1305::encrypt(
//!     message,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! // Decrypt the message
//! let decrypted = chacha20poly1305::decrypt(
//!     &ciphertext,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! assert_eq!(message, &decrypted[..]);
//! ```

use crate::{Result, SodiumError};
use std::convert::{TryFrom, TryInto};

/// Number of bytes in a secret key (32)
///
/// The secret key is used for both encryption and decryption.
/// It must be kept secret and should be generated using a secure random number generator.
pub const KEYBYTES: usize = libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize;
/// Number of bytes in a nonce (8)
///
/// The nonce must be unique for each encryption operation with the same key.
/// It can be public, but must never be reused with the same key.
pub const NPUBBYTES: usize = libsodium_sys::crypto_aead_chacha20poly1305_NPUBBYTES as usize;

/// A nonce (number used once) for ChaCha20-Poly1305 operations
///
/// This struct represents a nonce for use with the ChaCha20-Poly1305 encryption algorithm.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// ChaCha20-Poly1305 uses a 64-bit nonce, which is relatively small. For applications that
/// need to encrypt many messages with the same key, consider using XChaCha20-Poly1305 instead,
/// which has a larger nonce size (192 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NPUBBYTES]);

impl Nonce {
    /// Generate a random nonce for use with ChaCha20-Poly1305 functions
    ///
    /// This method generates a random nonce of the appropriate size (NPUBBYTES)
    /// for use with the encryption and decryption functions in this module.
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A random nonce
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_aead::chacha20poly1305;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = chacha20poly1305::Nonce::generate();
    /// assert_eq!(nonce.as_bytes().len(), chacha20poly1305::NPUBBYTES);
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; NPUBBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from a byte array of the correct length
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A byte array of length NPUBBYTES
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A nonce initialized with the provided bytes
    pub fn from_bytes(bytes: [u8; NPUBBYTES]) -> Self {
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
        if bytes.len() != NPUBBYTES {
            return Err(SodiumError::InvalidNonce(format!(
                "nonce must be exactly {NPUBBYTES} bytes"
            )));
        }

        let mut nonce_bytes = [0u8; NPUBBYTES];
        nonce_bytes.copy_from_slice(bytes);
        Ok(Self(nonce_bytes))
    }

    /// Get the underlying bytes of the nonce
    ///
    /// ## Returns
    ///
    /// * `&[u8; NPUBBYTES]` - A reference to the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NPUBBYTES] {
        &self.0
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

impl From<[u8; NPUBBYTES]> for Nonce {
    fn from(bytes: [u8; NPUBBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Nonce> for [u8; NPUBBYTES] {
    fn from(nonce: Nonce) -> [u8; NPUBBYTES] {
        nonce.0
    }
}
/// Number of bytes in an authentication tag (16)
///
/// This is the size of the authentication tag that is added to the ciphertext.
pub const ABYTES: usize = libsodium_sys::crypto_aead_chacha20poly1305_ABYTES as usize;

/// Maximum number of bytes in a message
///
/// This is the maximum number of bytes that can be encrypted in a single message.
pub fn messagebytes_max() -> usize {
    unsafe { libsodium_sys::crypto_aead_chacha20poly1305_messagebytes_max() }
}

/// A secret key for ChaCha20-Poly1305 encryption and decryption
///
/// This struct represents a 256-bit (32-byte) secret key used for
/// ChaCha20-Poly1305 authenticated encryption and decryption.
/// The key should be generated using a secure random number generator
/// and kept secret.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::chacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = chacha20poly1305::Key::generate();
///
/// // Create a key from existing bytes
/// let key_bytes = [0x42; chacha20poly1305::KEYBYTES];
/// let key_from_bytes = chacha20poly1305::Key::from_bytes(&key_bytes).unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generate a new key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {KEYBYTES} bytes"
            )));
        }

        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Generate a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; KEYBYTES];
        crate::random::fill_bytes(&mut key);
        Self(key)
    }

    /// Get the bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<Key> for Key {
    fn as_ref(&self) -> &Key {
        self
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; KEYBYTES]> for Key {
    fn from(bytes: [u8; KEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Key> for [u8; KEYBYTES] {
    fn from(key: Key) -> [u8; KEYBYTES] {
        key.0
    }
}

/// Encrypt a message using ChaCha20-Poly1305
///
/// This function encrypts a message using the ChaCha20-Poly1305 algorithm.
/// It provides both confidentiality and authenticity for the message, and also
/// authenticates the additional data if provided.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key to use for encryption
///
/// # Returns
/// * `Result<Vec<u8>>` - The encrypted message with authentication tag
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
/// * For random nonces, use `random::bytes(NPUBBYTES)`
/// * The additional data is authenticated but not encrypted
/// * ChaCha20-Poly1305 uses a 64-bit (8-byte) nonce, which is smaller than XChaCha20-Poly1305
/// * For applications that need to encrypt many messages with the same key,
///   consider using XChaCha20-Poly1305 instead, which has a larger nonce size
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::chacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = chacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = chacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = chacha20poly1305::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
/// ```
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len() + ABYTES];
    let mut ciphertext_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            std::ptr::null(),
            nonce.as_bytes().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    ciphertext.truncate(ciphertext_len as usize);
    Ok(ciphertext)
}

/// Decrypt a message using ChaCha20-Poly1305
///
/// This function decrypts a message that was encrypted using the ChaCha20-Poly1305
/// algorithm. It verifies the authenticity of both the ciphertext and the additional data
/// (if provided) before returning the decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message with authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key used for encryption
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
///
/// # Security Considerations
/// * If authentication fails, the function returns an error and no decryption is performed
/// * The additional data must be the same as used during encryption
/// * The nonce must be the same as used during encryption
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::chacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = chacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = chacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = chacha20poly1305::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message
/// let decrypted = chacha20poly1305::decrypt(
///     &ciphertext,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// assert_eq!(message, &decrypted[..]);
/// ```
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The ciphertext is too short (less than `ABYTES` bytes)
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt(
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    if ciphertext.len() < ABYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len() - ABYTES];
    let mut message_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_decrypt(
            message.as_mut_ptr(),
            &mut message_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            nonce.as_bytes().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    message.truncate(message_len as usize);
    Ok(message)
}

/// Encrypt a message using ChaCha20-Poly1305 with detached authentication tag
///
/// This function encrypts a message using the ChaCha20-Poly1305 algorithm and returns
/// the ciphertext and authentication tag separately. This is useful when you want
/// to store or transmit the ciphertext and tag separately.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key to use for encryption
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>)>` - A tuple containing (ciphertext, authentication_tag)
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
/// * For random nonces, use `random::bytes(NPUBBYTES)`
/// * The additional data is authenticated but not encrypted
/// * ChaCha20-Poly1305 uses a 64-bit (8-byte) nonce, which is smaller than XChaCha20-Poly1305
/// * For applications that need to encrypt many messages with the same key,
///   consider using XChaCha20-Poly1305 instead, which has a larger nonce size
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::chacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = chacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = chacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = chacha20poly1305::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
/// ```
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt_detached(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len()];
    let mut tag = vec![0u8; ABYTES];
    let mut tag_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_encrypt_detached(
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
            &mut tag_len,
            message.as_ptr(),
            message.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            std::ptr::null(),
            nonce.as_bytes().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    tag.truncate(tag_len as usize);
    Ok((ciphertext, tag))
}

/// Decrypt a message using ChaCha20-Poly1305 with detached authentication tag
///
/// This function decrypts a message that was encrypted using the ChaCha20-Poly1305
/// algorithm with a detached authentication tag. It verifies the authenticity of
/// both the ciphertext and the additional data (if provided) before returning the
/// decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message
/// * `tag` - The authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key used for encryption
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
///
/// # Security Considerations
/// * If authentication fails, the function returns an error and no decryption is performed
/// * The additional data must be the same as used during encryption
/// * The nonce must be the same as used during encryption
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::chacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = chacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = chacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = chacha20poly1305::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message with detached authentication tag
/// let decrypted = chacha20poly1305::decrypt_detached(
///     &ciphertext,
///     &tag,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// assert_eq!(message, &decrypted[..]);
/// ```
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The tag is not exactly `ABYTES` bytes
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt_detached(
    ciphertext: &[u8],
    tag: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    if tag.len() != ABYTES {
        return Err(SodiumError::InvalidInput(format!(
            "tag must be exactly {ABYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_decrypt_detached(
            message.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            nonce.as_bytes().as_ptr(),
            key.as_bytes().as_ptr(),
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
    use crate::ensure_init;

    #[test]
    fn test_nonce_generation() {
        ensure_init().expect("Failed to initialize libsodium");

        let nonce = Nonce::generate();
        assert_eq!(nonce.as_bytes().len(), NPUBBYTES);
    }

    #[test]
    fn test_nonce_from_bytes() {
        ensure_init().expect("Failed to initialize libsodium");

        let bytes = [0x42; NPUBBYTES];
        let nonce = Nonce::from_bytes(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_try_from_slice() {
        ensure_init().expect("Failed to initialize libsodium");

        let bytes = [0x42; NPUBBYTES];
        let nonce = Nonce::try_from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Test with invalid length
        let invalid_bytes = [0x42; NPUBBYTES - 1];
        assert!(Nonce::try_from_slice(&invalid_bytes).is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        ensure_init().expect("Failed to initialize libsodium");

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, ChaCha20-Poly1305!";
        let additional_data = b"Important metadata";

        // Encrypt the message
        let ciphertext = encrypt(message, Some(additional_data), &nonce, &key).unwrap();

        // Decrypt the message
        let decrypted = decrypt(&ciphertext, Some(additional_data), &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_decrypt_detached() {
        ensure_init().expect("Failed to initialize libsodium");

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, ChaCha20-Poly1305 with detached MAC!";
        let additional_data = b"Important metadata";

        // Encrypt the message with detached MAC
        let (ciphertext, tag) =
            encrypt_detached(message, Some(additional_data), &nonce, &key).unwrap();

        // Decrypt the message with detached MAC
        let decrypted =
            decrypt_detached(&ciphertext, &tag, Some(additional_data), &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decrypt_failure() {
        ensure_init().expect("Failed to initialize libsodium");

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, ChaCha20-Poly1305!";
        let additional_data = b"Important metadata";

        // Encrypt the message
        let mut ciphertext = encrypt(message, Some(additional_data), &nonce, &key).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        // Decryption should fail
        assert!(decrypt(&ciphertext, Some(additional_data), &nonce, &key).is_err());
    }

    #[test]
    fn test_nonce_traits() {
        ensure_init().expect("Failed to initialize libsodium");

        // Test TryFrom<&[u8]>
        let bytes = [0x42; NPUBBYTES];
        let nonce = Nonce::try_from(&bytes[..]).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; NPUBBYTES - 1];
        assert!(Nonce::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; NPUBBYTES]>
        let array = [0x43; NPUBBYTES];
        let nonce2 = Nonce::from(array);
        assert_eq!(nonce2.as_bytes(), &array);

        // Test From<Nonce> for [u8; NPUBBYTES]
        let extracted: [u8; NPUBBYTES] = nonce2.into();
        assert_eq!(extracted, array);

        // Test AsRef<[u8]>
        let nonce3 = Nonce::generate();
        let slice_ref: &[u8] = nonce3.as_ref();
        assert_eq!(slice_ref.len(), NPUBBYTES);
    }

    #[test]
    fn test_key_traits() {
        ensure_init().expect("Failed to initialize libsodium");

        // Test TryFrom<&[u8]>
        let bytes = [0x42; KEYBYTES];
        let key = Key::try_from(&bytes[..]).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; KEYBYTES - 1];
        assert!(Key::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let array = [0x43; KEYBYTES];
        let key2 = Key::from(array);
        assert_eq!(key2.as_bytes(), &array);

        // Test From<Key> for [u8; KEYBYTES]
        let extracted: [u8; KEYBYTES] = key2.into();
        assert_eq!(extracted, array);

        // Test AsRef<[u8]>
        let key3 = Key::generate();
        let slice_ref: &[u8] = key3.as_ref();
        assert_eq!(slice_ref.len(), KEYBYTES);
    }
}
