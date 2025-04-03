//! # Short-Input Hash Function (SipHash-2-4)
//!
//! This module provides a fast, short-input hash function based on SipHash-2-4.
//! It is designed for hash table lookups, manipulation detection, and other
//! non-cryptographic purposes where collision resistance is required.
//!
//! ## Features
//!
//! - **Fast hashing**: Optimized for short inputs and speed
//! - **64-bit output**: Compact hash values suitable for hash tables
//! - **Keyed hashing**: Uses a 128-bit key for collision resistance
//! - **Lightweight**: Minimal memory and CPU requirements
//!
//! ## Use Cases
//!
//! - **Hash tables**: Protect against hash-flooding denial-of-service attacks
//! - **Bloom filters**: Compact set membership testing
//! - **Data structures**: Efficient indexing and lookup
//! - **Checksums**: Quick integrity checks for small data
//!
//! ## Security Considerations
//!
//! - SipHash-2-4 is NOT a cryptographic hash function and should not be used for:
//!   - Password hashing (use `crypto_pwhash` instead)
//!   - Message authentication codes (use `crypto_auth` instead)
//!   - Digital signatures (use `crypto_sign` instead)
//!   - General-purpose hashing (use `crypto_generichash` instead)
//! - Always use a random key to prevent predictable collisions
//!
//! ## Example Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_shorthash;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = crypto_shorthash::Key::generate();
//!
//! // Compute a hash of a short input
//! let data = b"Hello, world!";
//! let hash = crypto_shorthash::shorthash(data, &key);
//!
//! // The same input with the same key always produces the same hash
//! let hash2 = crypto_shorthash::shorthash(data, &key);
//! assert_eq!(hash, hash2);
//!
//! // Different keys produce different hashes for the same input
//! let key2 = crypto_shorthash::Key::generate();
//! let hash3 = crypto_shorthash::shorthash(data, &key2);
//! assert_ne!(hash, hash3);
//! ```

use crate::{Result, SodiumError};
use libc;

/// Number of bytes in a key
pub const KEYBYTES: usize = libsodium_sys::crypto_shorthash_KEYBYTES as usize;
/// Number of bytes in a hash
pub const BYTES: usize = libsodium_sys::crypto_shorthash_BYTES as usize;

/// A key for SipHash-2-4
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generate a new key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {} bytes",
                KEYBYTES
            )));
        }

        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(bytes);
        Ok(Key(key))
    }

    /// Generate a new random key
    pub fn generate() -> Self {
        let bytes = crate::random::bytes(KEYBYTES);
        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(&bytes);
        Key(key)
    }

    /// Get the bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Compute a 64-bit hash using SipHash-2-4
///
/// This function computes a 64-bit hash of the input data using the SipHash-2-4 algorithm.
/// It is designed for hash table lookups, manipulation detection, and other non-cryptographic
/// purposes where collision resistance is required.
///
/// # Arguments
///
/// * `input` - The data to hash
/// * `key` - The key to use for hashing
///
/// # Returns
///
/// * `[u8; BYTES]` - The computed hash
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_shorthash;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = crypto_shorthash::Key::generate();
///
/// // Compute a hash of a short input
/// let data = b"Hello, world!";
/// let hash = crypto_shorthash::shorthash(data, &key);
/// ```
pub fn shorthash(input: &[u8], key: &Key) -> [u8; BYTES] {
    let mut out = [0u8; BYTES];

    unsafe {
        // This call cannot fail with valid inputs, and we validate inputs through the Key type
        libsodium_sys::crypto_shorthash(
            out.as_mut_ptr(),
            input.as_ptr(),
            input.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        );
    }

    out
}

/// SipHash-2-4 hash function with 128-bit output
pub mod siphash24 {
    use super::*;

    /// Number of bytes in a key
    pub const KEYBYTES: usize = libsodium_sys::crypto_shorthash_siphash24_KEYBYTES as usize;
    /// Number of bytes in a hash
    pub const BYTES: usize = libsodium_sys::crypto_shorthash_siphash24_BYTES as usize;

    /// A key for SipHash-2-4
    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Key([u8; KEYBYTES]);

    impl Key {
        /// Generate a new key from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != KEYBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "key must be exactly {} bytes",
                    KEYBYTES
                )));
            }

            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(bytes);
            Ok(Key(key))
        }

        /// Generate a new random key
        pub fn generate() -> Self {
            let bytes = crate::random::bytes(KEYBYTES);
            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(&bytes);
            Key(key)
        }

        /// Get the bytes of the key
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// Compute a 64-bit hash using SipHash-2-4
    ///
    /// This function computes a 64-bit hash of the input data using the SipHash-2-4 algorithm.
    /// It is designed for hash table lookups, manipulation detection, and other non-cryptographic
    /// purposes where collision resistance is required.
    ///
    /// # Arguments
    ///
    /// * `input` - The data to hash
    /// * `key` - The key to use for hashing
    ///
    /// # Returns
    ///
    /// * `[u8; BYTES]` - The computed hash
    pub fn shorthash(input: &[u8], key: &Key) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];

        unsafe {
            // This call cannot fail with valid inputs, and we validate inputs through the Key type
            libsodium_sys::crypto_shorthash_siphash24(
                out.as_mut_ptr(),
                input.as_ptr(),
                input.len() as libc::c_ulonglong,
                key.as_bytes().as_ptr(),
            );
        }

        out
    }
}

/// SipHash-1-3 hash function with 64-bit output
pub mod siphashx24 {
    use super::*;

    /// Number of bytes in a key
    pub const KEYBYTES: usize = libsodium_sys::crypto_shorthash_siphashx24_KEYBYTES as usize;
    /// Number of bytes in a hash
    pub const BYTES: usize = libsodium_sys::crypto_shorthash_siphashx24_BYTES as usize;

    /// A key for SipHash-1-3
    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Key([u8; KEYBYTES]);

    impl Key {
        /// Generate a new key from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != KEYBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "key must be exactly {} bytes",
                    KEYBYTES
                )));
            }

            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(bytes);
            Ok(Key(key))
        }

        /// Generate a new random key
        pub fn generate() -> Self {
            let bytes = crate::random::bytes(KEYBYTES);
            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(&bytes);
            Key(key)
        }

        /// Get the bytes of the key
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// Compute a 64-bit hash using SipHash-1-3
    ///
    /// This function computes a 64-bit hash of the input data using the SipHash-1-3 algorithm.
    /// It is designed for hash table lookups, manipulation detection, and other non-cryptographic
    /// purposes where collision resistance is required.
    ///
    /// # Arguments
    ///
    /// * `input` - The data to hash
    /// * `key` - The key to use for hashing
    ///
    /// # Returns
    ///
    /// * `[u8; BYTES]` - The computed hash
    pub fn shorthash(input: &[u8], key: &Key) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];

        unsafe {
            // This call cannot fail with valid inputs, and we validate inputs through the Key type
            libsodium_sys::crypto_shorthash_siphashx24(
                out.as_mut_ptr(),
                input.as_ptr(),
                input.len() as libc::c_ulonglong,
                key.as_bytes().as_ptr(),
            );
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // No need for ct-codecs in these tests

    #[test]
    fn test_shorthash() {
        let key = Key::generate();
        let data = b"test data";

        let hash = shorthash(data, &key);
        assert_eq!(hash.len(), BYTES);

        // Same data and key should produce the same hash
        let hash2 = shorthash(data, &key);
        assert_eq!(hash, hash2);

        // Different data should produce different hash
        let data2 = b"different data";
        let hash3 = shorthash(data2, &key);
        assert_ne!(hash, hash3);

        // Different key should produce different hash
        let key2 = Key::generate();
        let hash4 = shorthash(data, &key2);
        assert_ne!(hash, hash4);
    }

    #[test]
    fn test_siphash24() {
        let key = siphash24::Key::generate();
        let data = b"test data";

        let hash = siphash24::shorthash(data, &key);
        assert_eq!(hash.len(), siphash24::BYTES);

        // Same data and key should produce the same hash
        let hash2 = siphash24::shorthash(data, &key);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_siphashx24() {
        let key = siphashx24::Key::generate();
        let data = b"test data";

        let hash = siphashx24::shorthash(data, &key);
        assert_eq!(hash.len(), siphashx24::BYTES);

        // Same data and key should produce the same hash
        let hash2 = siphashx24::shorthash(data, &key);
        assert_eq!(hash, hash2);
    }
}
