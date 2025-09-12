//! # XChaCha20-Poly1305-IETF Authenticated Encryption with Associated Data
//!
//! This module provides authenticated encryption and decryption using the
//! XChaCha20-Poly1305-IETF algorithm. This is a state-of-the-art AEAD cipher
//! that combines the XChaCha20 stream cipher with the Poly1305 message authentication code.
//!
//! ## Algorithm Details
//!
//! XChaCha20-Poly1305 is a two-part construction:
//!
//! 1. **XChaCha20**: An extended nonce variant of the ChaCha20 stream cipher
//!    * Uses a 256-bit key for encryption
//!    * Uses a 192-bit nonce (extended from ChaCha20's 96-bit nonce)
//!    * The extended nonce provides protection against accidental nonce reuse
//!    * Internally uses the HChaCha20 function to derive a subkey from the key and first 128 bits of the nonce
//!
//! 2. **Poly1305**: A fast message authentication code (MAC)
//!    * Produces a 128-bit (16-byte) authentication tag
//!    * Authenticates both the ciphertext and the additional data
//!    * Uses a one-time key derived from the encryption key and nonce
//!
//! ## Features and Advantages
//!
//! - **Strong security**: 256-bit keys and 192-bit nonces provide high security margins
//! - **High performance**: Optimized for software implementations without requiring specialized hardware
//! - **Cross-platform efficiency**: Works efficiently on all platforms, from embedded devices to servers
//! - **Large nonce size**: 192-bit nonces make random nonce generation safe (collision probability is negligible)
//! - **Timing attack resistance**: The algorithm is designed to be constant-time, protecting against timing side-channels
//! - **Misuse resistance**: More forgiving of implementation errors compared to AES-GCM
//! - **Simplicity**: The algorithm is relatively simple to implement correctly
//!
//! ## Security Properties
//!
//! - **Confidentiality**: The encrypted message cannot be read without the secret key
//! - **Integrity**: Any modification to the ciphertext will be detected during decryption
//! - **Authenticity**: The receiver can verify that the message was created by someone with the secret key
//! - **Nonce misuse resistance**: While nonce reuse should always be avoided, XChaCha20-Poly1305 provides
//!   better resistance to nonce reuse compared to some other AEAD constructions
//!
//! ## Security Considerations and Best Practices
//!
//! - **Nonce handling**: While the 192-bit nonce makes random generation safe, you can also use a counter
//!   for maximum safety. Never reuse a nonce with the same key.
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
//! ## When to Use XChaCha20-Poly1305
//!
//! - When you need a modern, secure AEAD algorithm with excellent software performance
//! - When you want to safely use randomly generated nonces
//! - When you need an algorithm that works efficiently on all platforms without hardware acceleration
//! - When you need a well-analyzed and trusted algorithm with a large security margin
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = xchacha20poly1305::Key::generate();
//!
//! // Create a nonce
//! let nonce = xchacha20poly1305::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Additional authenticated data (not encrypted, but authenticated)
//! let additional_data = b"Important metadata";
//!
//! // Encrypt the message
//! let ciphertext = xchacha20poly1305::encrypt(
//!     message,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! // Decrypt the message
//! let decrypted = xchacha20poly1305::decrypt(
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
pub const KEYBYTES: usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
/// Number of bytes in a nonce (24)
///
/// The nonce must be unique for each encryption operation with the same key.
/// It can be public, but must never be reused with the same key.
pub const NPUBBYTES: usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;

/// A nonce (number used once) for XChaCha20-Poly1305-IETF operations
///
/// This struct represents a nonce for use with the XChaCha20-Poly1305-IETF encryption algorithm.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// XChaCha20-Poly1305-IETF uses a 192-bit nonce, which is large enough that random nonces can be
/// safely used without worrying about collisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NPUBBYTES]);

impl Nonce {
    /// Generate a random nonce for use with XChaCha20-Poly1305-IETF functions
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
    /// use sodium::crypto_aead::xchacha20poly1305;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = xchacha20poly1305::Nonce::generate();
    /// assert_eq!(nonce.as_bytes().len(), xchacha20poly1305::NPUBBYTES);
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; NPUBBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from bytes of the correct length
    ///
    /// ## Arguments
    ///
    /// * `bytes` - Bytes of length NPUBBYTES
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
pub const ABYTES: usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;

/// A secret key for XChaCha20-Poly1305 encryption and decryption
///
/// This struct represents a 256-bit (32-byte) secret key used for
/// XChaCha20-Poly1305 authenticated encryption and decryption.
/// The key should be generated using a secure random number generator
/// and kept secret.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = xchacha20poly1305::Key::generate();
///
/// // Create a key from existing bytes
/// let key_bytes = [0x42; xchacha20poly1305::KEYBYTES];
/// let key_from_bytes = xchacha20poly1305::Key::from_bytes(&key_bytes).unwrap();
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
        Ok(Key(key))
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

/// Encrypt a message using XChaCha20-Poly1305-IETF
///
/// This function encrypts a message using the XChaCha20-Poly1305-IETF algorithm.
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
/// * `Result<Vec<u8>>` - The encrypted message with authentication tag appended
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
/// * For random nonces, use `random::bytes(NPUBBYTES)`
/// * The additional data is authenticated but not encrypted
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = xchacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = xchacha20poly1305::encrypt(
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
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
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

/// Decrypt a message using XChaCha20-Poly1305-IETF
///
/// This function decrypts a message that was encrypted using the XChaCha20-Poly1305-IETF
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
/// use sodium::crypto_aead::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = xchacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = xchacha20poly1305::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message
/// let decrypted = xchacha20poly1305::decrypt(
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
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
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

/// Encrypt a message using XChaCha20-Poly1305-IETF with detached authentication tag
///
/// This function encrypts a message using the XChaCha20-Poly1305-IETF algorithm and returns
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
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = xchacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = xchacha20poly1305::encrypt_detached(
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
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
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

/// Decrypt a message using XChaCha20-Poly1305-IETF with detached authentication tag
///
/// This function decrypts a message that was encrypted using the XChaCha20-Poly1305-IETF
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
/// use sodium::crypto_aead::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = xchacha20poly1305::Key::generate();
///
/// // Generate a random nonce
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = xchacha20poly1305::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message with detached authentication tag
/// let decrypted = xchacha20poly1305::decrypt_detached(
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
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
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
        let message = b"Hello, XChaCha20-Poly1305!";
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
        let message = b"Hello, XChaCha20-Poly1305 with detached MAC!";
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
        let message = b"Hello, XChaCha20-Poly1305!";
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
        let bytes = [0x43; NPUBBYTES];
        let nonce2 = Nonce::from(bytes);
        assert_eq!(nonce2.as_bytes(), &bytes);

        // Test From<Nonce> for [u8; NPUBBYTES]
        let extracted: [u8; NPUBBYTES] = nonce2.into();
        assert_eq!(extracted, bytes);

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
        let bytes = [0x43; KEYBYTES];
        let key2 = Key::from(bytes);
        assert_eq!(key2.as_bytes(), &bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let extracted: [u8; KEYBYTES] = key2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let key3 = Key::generate();
        let slice_ref: &[u8] = key3.as_ref();
        assert_eq!(slice_ref.len(), KEYBYTES);
    }
}
