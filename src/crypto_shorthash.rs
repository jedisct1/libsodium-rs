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
use std::convert::TryFrom;

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
                "key must be exactly {KEYBYTES} bytes"
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

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<[u8; KEYBYTES]> for Key {
    fn from(bytes: [u8; KEYBYTES]) -> Self {
        Key(bytes)
    }
}

impl From<Key> for [u8; KEYBYTES] {
    fn from(key: Key) -> Self {
        key.0
    }
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
                    "key must be exactly {KEYBYTES} bytes"
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

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl TryFrom<&[u8]> for Key {
        type Error = SodiumError;

        fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
            Self::from_bytes(bytes)
        }
    }

    impl From<[u8; KEYBYTES]> for Key {
        fn from(bytes: [u8; KEYBYTES]) -> Self {
            Key(bytes)
        }
    }

    impl From<Key> for [u8; KEYBYTES] {
        fn from(key: Key) -> Self {
            key.0
        }
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
                    "key must be exactly {KEYBYTES} bytes"
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

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl TryFrom<&[u8]> for Key {
        type Error = SodiumError;

        fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
            Self::from_bytes(bytes)
        }
    }

    impl From<[u8; KEYBYTES]> for Key {
        fn from(bytes: [u8; KEYBYTES]) -> Self {
            Key(bytes)
        }
    }

    impl From<Key> for [u8; KEYBYTES] {
        fn from(key: Key) -> Self {
            key.0
        }
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

    #[test]
    fn test_key_traits() {
        // Test for the main Key type
        let key_bytes = [0u8; KEYBYTES];

        // Test From<[u8; KEYBYTES]>
        let key = Key::from(key_bytes);

        // Test AsRef<[u8]>
        assert_eq!(key.as_ref(), &key_bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let bytes_back: [u8; KEYBYTES] = key.clone().into();
        assert_eq!(bytes_back, key_bytes);

        // Test TryFrom<&[u8]> - success case
        let key_from_slice = Key::try_from(&key_bytes[..]).unwrap();
        assert_eq!(key_from_slice, key);

        // Test TryFrom<&[u8]> - error cases
        let short_slice = vec![0u8; KEYBYTES - 1];
        assert!(Key::try_from(short_slice.as_slice()).is_err());

        let long_slice = vec![0u8; KEYBYTES + 1];
        assert!(Key::try_from(long_slice.as_slice()).is_err());
    }

    #[test]
    fn test_siphash24_key_traits() {
        // Test for siphash24::Key type
        let key_bytes = [0u8; siphash24::KEYBYTES];

        // Test From<[u8; KEYBYTES]>
        let key = siphash24::Key::from(key_bytes);

        // Test AsRef<[u8]>
        assert_eq!(key.as_ref(), &key_bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let bytes_back: [u8; siphash24::KEYBYTES] = key.clone().into();
        assert_eq!(bytes_back, key_bytes);

        // Test TryFrom<&[u8]> - success case
        let key_from_slice = siphash24::Key::try_from(&key_bytes[..]).unwrap();
        assert_eq!(key_from_slice, key);

        // Test TryFrom<&[u8]> - error cases
        let short_slice = vec![0u8; siphash24::KEYBYTES - 1];
        assert!(siphash24::Key::try_from(short_slice.as_slice()).is_err());

        let long_slice = vec![0u8; siphash24::KEYBYTES + 1];
        assert!(siphash24::Key::try_from(long_slice.as_slice()).is_err());
    }

    #[test]
    fn test_siphashx24_key_traits() {
        // Test for siphashx24::Key type
        let key_bytes = [0u8; siphashx24::KEYBYTES];

        // Test From<[u8; KEYBYTES]>
        let key = siphashx24::Key::from(key_bytes);

        // Test AsRef<[u8]>
        assert_eq!(key.as_ref(), &key_bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let bytes_back: [u8; siphashx24::KEYBYTES] = key.clone().into();
        assert_eq!(bytes_back, key_bytes);

        // Test TryFrom<&[u8]> - success case
        let key_from_slice = siphashx24::Key::try_from(&key_bytes[..]).unwrap();
        assert_eq!(key_from_slice, key);

        // Test TryFrom<&[u8]> - error cases
        let short_slice = vec![0u8; siphashx24::KEYBYTES - 1];
        assert!(siphashx24::Key::try_from(short_slice.as_slice()).is_err());

        let long_slice = vec![0u8; siphashx24::KEYBYTES + 1];
        assert!(siphashx24::Key::try_from(long_slice.as_slice()).is_err());
    }

    #[test]
    fn test_key_conversion_roundtrip() {
        // Test round-trip conversions for main Key
        let original_key = Key::generate();
        let bytes: [u8; KEYBYTES] = original_key.clone().into();
        let reconstructed_key = Key::from(bytes);
        assert_eq!(original_key, reconstructed_key);

        // Also test through TryFrom
        let key_via_try = Key::try_from(&bytes[..]).unwrap();
        assert_eq!(original_key, key_via_try);
    }

    #[test]
    fn test_siphash24_key_conversion_roundtrip() {
        // Test round-trip conversions for siphash24::Key
        let original_key = siphash24::Key::generate();
        let bytes: [u8; siphash24::KEYBYTES] = original_key.clone().into();
        let reconstructed_key = siphash24::Key::from(bytes);
        assert_eq!(original_key, reconstructed_key);

        // Also test through TryFrom
        let key_via_try = siphash24::Key::try_from(&bytes[..]).unwrap();
        assert_eq!(original_key, key_via_try);
    }

    #[test]
    fn test_siphashx24_key_conversion_roundtrip() {
        // Test round-trip conversions for siphashx24::Key
        let original_key = siphashx24::Key::generate();
        let bytes: [u8; siphashx24::KEYBYTES] = original_key.clone().into();
        let reconstructed_key = siphashx24::Key::from(bytes);
        assert_eq!(original_key, reconstructed_key);

        // Also test through TryFrom
        let key_via_try = siphashx24::Key::try_from(&bytes[..]).unwrap();
        assert_eq!(original_key, key_via_try);
    }

    #[test]
    fn test_as_ref_consistency() {
        // Ensure AsRef and as_bytes return the same data
        let key = Key::generate();
        assert_eq!(key.as_ref(), key.as_bytes());

        let key24 = siphash24::Key::generate();
        assert_eq!(key24.as_ref(), key24.as_bytes());

        let keyx24 = siphashx24::Key::generate();
        assert_eq!(keyx24.as_ref(), keyx24.as_bytes());
    }

    #[test]
    fn test_try_from_error_messages() {
        // Test that TryFrom produces appropriate error messages
        let short_slice = vec![0u8; 5];
        let result = Key::try_from(short_slice.as_slice());
        assert!(result.is_err());
        if let Err(SodiumError::InvalidInput(msg)) = result {
            assert!(msg.contains(&KEYBYTES.to_string()));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test for siphash24
        let result24 = siphash24::Key::try_from(short_slice.as_slice());
        assert!(result24.is_err());
        if let Err(SodiumError::InvalidInput(msg)) = result24 {
            assert!(msg.contains(&siphash24::KEYBYTES.to_string()));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test for siphashx24
        let resultx24 = siphashx24::Key::try_from(short_slice.as_slice());
        assert!(resultx24.is_err());
        if let Err(SodiumError::InvalidInput(msg)) = resultx24 {
            assert!(msg.contains(&siphashx24::KEYBYTES.to_string()));
        } else {
            panic!("Expected InvalidInput error");
        }
    }
}
