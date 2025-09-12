//! # Stream Ciphers
//!
//! This module provides access to various stream ciphers implemented in libsodium:
//! - ChaCha20: A stream cipher developed by Daniel J. Bernstein with good diffusion properties
//! - XChaCha20: An extended nonce variant of ChaCha20 (recommended for most applications)
//! - Salsa20: The predecessor to ChaCha20, also developed by Daniel J. Bernstein
//!
//! ## Important Notes
//!
//! - These functions are stream ciphers and do not provide authenticated encryption.
//! - They can be used to generate pseudo-random data from a key or as building blocks
//!   for implementing custom constructions.
//! - For authenticated encryption, use `crypto_secretbox` instead.
//! - XChaCha20 is recommended for most applications due to its extended nonce size.
//!
//! ## Usage Example
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_stream;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = crypto_stream::Key::generate().unwrap();
//!
//! // Create a nonce (in a real application, this should be unique for each message)
//! let nonce = crypto_stream::xchacha20::Nonce::from_bytes([0u8; crypto_stream::xchacha20::NONCEBYTES]);
//!
//! // Message to encrypt
//! let message = b"This is a secret message";
//!
//! // Encrypt the message using XChaCha20
//! let encrypted = crypto_stream::xchacha20::stream_xor(message, &nonce, &key).unwrap();
//!
//! // Decrypt the message (with stream ciphers, encryption and decryption are the same operation)
//! let decrypted = crypto_stream::xchacha20::stream_xor(&encrypted, &nonce, &key).unwrap();
//!
//! assert_eq!(&decrypted, message);
//! ```

use crate::{Result, SodiumError};
use std::convert::TryFrom;
use std::fmt;

// Re-export submodules
pub mod chacha20;
pub mod salsa20;
pub mod xchacha20;

/// Number of bytes in a standard stream encryption key (32 bytes)
pub const KEYBYTES: usize = libsodium_sys::crypto_stream_KEYBYTES as usize;
/// Number of bytes in a standard stream encryption nonce (24 bytes)
pub const NONCEBYTES: usize = libsodium_sys::crypto_stream_NONCEBYTES as usize;

/// A secret key for stream encryption
///
/// This key is used for symmetric encryption with various stream ciphers.
/// All stream cipher variants in this module use the same key size (32 bytes).
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generates a new random key for stream encryption
    ///
    /// This function generates a cryptographically secure random key that can be used
    /// with any of the stream cipher variants in this module (ChaCha20, XChaCha20, Salsa20).
    ///
    /// # Returns
    /// * `Result<Self>` - A randomly generated key
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_stream;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = crypto_stream::Key::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_stream_keygen(key.as_mut_ptr());
        }
        Ok(Key(key))
    }

    /// Creates a key from a byte slice
    ///
    /// This function creates a key from an existing byte slice, which must be exactly
    /// `KEYBYTES` (32) bytes long. This is useful when you have an existing key or
    /// when you need to derive a key from another source.
    ///
    /// # Arguments
    /// * `slice` - The bytes to create the key from
    ///
    /// # Returns
    /// * `Result<Self>` - The key or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `KEYBYTES` bytes long
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_stream;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a key from existing bytes
    /// let key_bytes = [0x42; crypto_stream::KEYBYTES]; // In a real application, use a proper key
    /// let key = crypto_stream::Key::from_slice(&key_bytes).unwrap();
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {KEYBYTES} bytes"
            )));
        }

        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(slice);
        Ok(Key(key))
    }

    /// Returns a reference to the key as a byte slice
    ///
    /// This method provides access to the raw bytes of the key, which can be useful
    /// when you need to pass the key to other functions or store it.
    ///
    /// # Returns
    /// * `&[u8]` - A reference to the key bytes
    ///
    /// # Security Considerations
    /// Be careful when handling the raw key bytes. Avoid logging or displaying them,
    /// and ensure they are securely erased from memory when no longer needed.
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_stream;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = crypto_stream::Key::generate().unwrap();
    ///
    /// // Get the raw bytes of the key
    /// let key_bytes = key.as_bytes();
    /// assert_eq!(key_bytes.len(), crypto_stream::KEYBYTES);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// Add implementation of Display for Key for easier debugging
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key([...])") // Don't show the actual bytes for security
    }
}

// Add implementation of TryFrom for Key for more idiomatic conversions
impl TryFrom<&[u8]> for Key {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Key::from_slice(bytes)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        // Generate a random key
        let key = Key::generate().unwrap();

        // Verify the key size
        assert_eq!(key.as_bytes().len(), KEYBYTES);

        // Test creating a key from bytes
        let key_bytes = key.as_bytes();
        let key2 = Key::from_slice(key_bytes).unwrap();
        assert_eq!(key2.as_bytes(), key_bytes);
    }

    #[test]
    fn test_key_traits() {
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
        let key3 = Key::generate().unwrap();
        let slice_ref: &[u8] = key3.as_ref();
        assert_eq!(slice_ref.len(), KEYBYTES);
    }

    #[test]
    fn test_chacha20() {
        // Generate a random key and nonce
        let key = Key::generate().unwrap();
        let nonce = chacha20::Nonce::from_bytes([0u8; chacha20::NONCEBYTES]);
        let message = b"test message";

        // Test stream generation
        let stream = chacha20::stream(32, &nonce, &key).unwrap();
        assert_eq!(stream.len(), 32);

        // Verify the stream is not all zeros
        assert!(stream.iter().any(|&b| b != 0));

        // Test encryption/decryption
        let encrypted = chacha20::stream_xor(message, &nonce, &key).unwrap();

        // Verify the encrypted data is different from the original
        assert_ne!(&encrypted, message);

        // Decrypt and verify it matches the original
        let decrypted = chacha20::stream_xor(&encrypted, &nonce, &key).unwrap();
        assert_eq!(&decrypted, message);
    }

    #[test]
    fn test_xchacha20() {
        // Generate a random key and nonce
        let key = Key::generate().unwrap();
        let nonce = xchacha20::Nonce::from_bytes([0u8; xchacha20::NONCEBYTES]);
        let message = b"test message";

        // Test stream generation
        let stream = xchacha20::stream(32, &nonce, &key).unwrap();
        assert_eq!(stream.len(), 32);

        // Verify the stream is not all zeros
        assert!(stream.iter().any(|&b| b != 0));

        // Test encryption/decryption
        let encrypted = xchacha20::stream_xor(message, &nonce, &key).unwrap();

        // Verify the encrypted data is different from the original
        assert_ne!(&encrypted, message);

        // Decrypt and verify it matches the original
        let decrypted = xchacha20::stream_xor(&encrypted, &nonce, &key).unwrap();
        assert_eq!(&decrypted, message);
    }

    #[test]
    fn test_salsa20() {
        // Generate a random key and nonce
        let key = Key::generate().unwrap();
        let nonce = salsa20::Nonce::from_bytes([0u8; salsa20::NONCEBYTES]);
        let message = b"test message";

        // Test stream generation
        let stream = salsa20::stream(32, &nonce, &key);
        assert_eq!(stream.len(), 32);

        // Verify the stream is not all zeros
        assert!(stream.iter().any(|&b| b != 0));

        // Test encryption/decryption
        let encrypted = salsa20::stream_xor(message, &nonce, &key);

        // Verify the encrypted data is different from the original
        assert_ne!(&encrypted, message);

        // Decrypt and verify it matches the original
        let decrypted = salsa20::stream_xor(&encrypted, &nonce, &key);
        assert_eq!(&decrypted, message);
    }

    #[test]
    fn test_invalid_nonce_length() {
        // Generate a random key (unused but kept for documentation purposes)
        let _key = Key::generate().unwrap();

        // Create invalid nonce slices
        let invalid_nonce_long = vec![0u8; chacha20::NONCEBYTES + 1];
        let invalid_nonce_short = vec![0u8; chacha20::NONCEBYTES - 1];

        // Test chacha20 nonce validation
        assert!(chacha20::Nonce::try_from_slice(&invalid_nonce_long).is_err());
        assert!(chacha20::Nonce::try_from_slice(&invalid_nonce_short).is_err());

        // Test xchacha20 nonce validation
        let invalid_xchacha_nonce_long = vec![0u8; xchacha20::NONCEBYTES + 1];
        let invalid_xchacha_nonce_short = vec![0u8; xchacha20::NONCEBYTES - 1];
        assert!(xchacha20::Nonce::try_from_slice(&invalid_xchacha_nonce_long).is_err());
        assert!(xchacha20::Nonce::try_from_slice(&invalid_xchacha_nonce_short).is_err());

        // Test salsa20 nonce validation
        let invalid_salsa_nonce_long = vec![0u8; salsa20::NONCEBYTES + 1];
        let invalid_salsa_nonce_short = vec![0u8; salsa20::NONCEBYTES - 1];
        assert!(salsa20::Nonce::try_from_slice(&invalid_salsa_nonce_long).is_err());
        assert!(salsa20::Nonce::try_from_slice(&invalid_salsa_nonce_short).is_err());
    }
}
