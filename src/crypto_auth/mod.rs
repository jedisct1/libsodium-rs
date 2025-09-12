//! # Secret-Key Authentication
//!
//! This module provides functions for message authentication using secret keys.
//! It allows you to compute an authentication tag for a message and a secret key,
//! and provides a way to verify that a given tag is valid for a given message and key.
//!
//! ## Purpose
//!
//! The authentication function is deterministic: the same (message, key) tuple will always
//! produce the same output. Even if the message is public, knowing the key is required to
//! compute a valid tag. Therefore, the key should remain confidential. The tag, however,
//! can be public.
//!
//! Typical use cases include:
//! - A prepares a message, adds an authentication tag, and sends it to B
//! - A doesn't store the message
//! - Later on, B sends the message and the authentication tag back to A
//! - A uses the authentication tag to verify that it created this message
//!
//! This operation does not encrypt the message. It only computes and verifies an
//! authentication tag.
//!
//! ## Algorithm
//!
//! The default implementation uses HMAC-SHA512-256.
//!
//! ## Usage Example
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_auth;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = crypto_auth::Key::generate().unwrap();
//!
//! // Message to authenticate
//! let message = b"Hello, world!";
//!
//! // Compute authentication tag
//! let tag = crypto_auth::auth(message, &key).unwrap();
//!
//! // Verify the tag
//! let verification = crypto_auth::verify(&tag, message, &key);
//! assert!(verification);
//!
//! // Verification fails with a different message
//! let wrong_message = b"Modified message";
//! let verification = crypto_auth::verify(&tag, wrong_message, &key);
//! assert!(!verification);
//! ```

use crate::{Result, SodiumError};
use libc;
use std::convert::TryFrom;

/// Number of bytes in an authentication tag (32 bytes)
pub const BYTES: usize = libsodium_sys::crypto_auth_BYTES as usize;
/// Number of bytes in an authentication key (32 bytes)
pub const KEYBYTES: usize = libsodium_sys::crypto_auth_KEYBYTES as usize;

/// A secret key for authentication
///
/// This key is used to compute and verify authentication tags. It should be kept secret,
/// as anyone with the key can create valid authentication tags.
#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generates a new random key for authentication
    ///
    /// This function generates a cryptographically secure random key that can be used
    /// for message authentication. The key is `KEYBYTES` (32) bytes long.
    ///
    /// # Returns
    /// * `Result<Self>` - A new randomly generated key
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_auth;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = crypto_auth::Key::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_auth_keygen(key.as_mut_ptr());
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
    /// * `slice` - Byte slice of exactly `KEYBYTES` (32) bytes length
    ///
    /// # Returns
    /// * `Result<Self>` - A new key or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `KEYBYTES` bytes long
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_auth;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a key from existing bytes
    /// let key_bytes = [0x42; crypto_auth::KEYBYTES]; // In a real application, use a proper key
    /// let key = crypto_auth::Key::from_slice(&key_bytes).unwrap();
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
    /// when you need to pass the key to other functions or store it securely.
    ///
    /// # Returns
    /// * `&[u8]` - Reference to the key bytes
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_auth;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = crypto_auth::Key::generate().unwrap();
    ///
    /// // Get the raw bytes of the key
    /// let key_bytes = key.as_bytes();
    /// assert_eq!(key_bytes.len(), crypto_auth::KEYBYTES);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_slice(slice)
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

/// An authentication tag
///
/// This represents an authentication tag computed for a message using a secret key.
/// The tag can be publicly shared and later verified to ensure the authenticity of
/// a message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tag([u8; BYTES]);

impl Tag {
    /// Creates a tag from a byte slice
    ///
    /// This function creates a tag from an existing byte slice, which must be exactly
    /// `BYTES` (32) bytes long. This is useful when you receive a tag from another party
    /// and need to verify it.
    ///
    /// # Arguments
    /// * `slice` - Byte slice of exactly `BYTES` (32) bytes length
    ///
    /// # Returns
    /// * `Result<Self>` - A new tag or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `BYTES` bytes long
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_auth;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a tag from existing bytes
    /// let tag_bytes = [0x42; crypto_auth::BYTES]; // In a real application, this would be a real tag
    /// let tag = crypto_auth::Tag::from_slice(&tag_bytes).unwrap();
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "tag must be exactly {BYTES} bytes"
            )));
        }
        let mut tag = [0u8; BYTES];
        tag.copy_from_slice(slice);
        Ok(Tag(tag))
    }

    /// Returns a reference to the tag as a byte slice
    ///
    /// This method provides access to the raw bytes of the tag, which can be useful
    /// when you need to transmit the tag or store it.
    ///
    /// # Returns
    /// * `&[u8]` - Reference to the tag bytes
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_auth;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = crypto_auth::Key::generate().unwrap();
    ///
    /// // Compute authentication tag for a message
    /// let message = b"Hello, world!";
    /// let tag = crypto_auth::auth(message, &key).unwrap();
    ///
    /// // Get the raw bytes of the tag
    /// let tag_bytes = tag.as_bytes();
    /// assert_eq!(tag_bytes.len(), crypto_auth::BYTES);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Tag {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

impl From<[u8; BYTES]> for Tag {
    fn from(bytes: [u8; BYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Tag> for [u8; BYTES] {
    fn from(tag: Tag) -> [u8; BYTES] {
        tag.0
    }
}

/// Computes an authentication tag for a message using a secret key
///
/// This function computes an authentication tag for a message and a secret key. The tag
/// is deterministic: the same (message, key) tuple will always produce the same output.
/// The tag can be later verified using the `verify` function.
///
/// The default implementation uses HMAC-SHA512-256.
///
/// # Arguments
/// * `message` - Message to authenticate
/// * `key` - Secret key for authentication
///
/// # Returns
/// * `Result<Tag>` - Authentication tag or an error
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_auth;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = crypto_auth::Key::generate().unwrap();
///
/// // Message to authenticate
/// let message = b"Hello, world!";
///
/// // Compute authentication tag
/// let tag = crypto_auth::auth(message, &key).unwrap();
/// ```
pub fn auth(message: &[u8], key: &Key) -> Result<Tag> {
    let mut tag = [0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_auth(
            tag.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("authentication failed".into()));
    }

    Ok(Tag(tag))
}

/// Verifies that a tag is valid for a message and key
///
/// This function verifies that a given authentication tag is valid for a given message
/// and key. It returns `true` if the verification passes, or `false` if the
/// verification fails (indicating that the message may have been tampered with or that
/// the wrong key was used).
///
/// # Arguments
/// * `tag` - Authentication tag to verify
/// * `message` - Message that was authenticated
/// * `key` - Secret key used for authentication
///
/// # Returns
/// * `bool` - `true` if verification passes, `false` otherwise
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_auth;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = crypto_auth::Key::generate().unwrap();
///
/// // Message to authenticate
/// let message = b"Hello, world!";
///
/// // Compute authentication tag
/// let tag = crypto_auth::auth(message, &key).unwrap();
///
/// // Verify the tag (should succeed)
/// assert!(crypto_auth::verify(&tag, message, &key));
///
/// // Verify with wrong message (should fail)
/// let wrong_message = b"Modified message";
/// assert!(!crypto_auth::verify(&tag, wrong_message, &key));
///
/// // Verify with wrong key (should fail)
/// let wrong_key = crypto_auth::Key::generate().unwrap();
/// assert!(!crypto_auth::verify(&tag, message, &wrong_key));
/// ```
pub fn verify(tag: &Tag, message: &[u8], key: &Key) -> bool {
    let result = unsafe {
        libsodium_sys::crypto_auth_verify(
            tag.as_bytes().as_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        )
    };

    result == 0
}

// Export submodules
/// HMAC-SHA-256 authentication functions
pub mod hmacsha256;
/// HMAC-SHA-512 authentication functions
pub mod hmacsha512;
/// HMAC-SHA-512-256 authentication functions (truncated SHA-512)
pub mod hmacsha512256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate().unwrap();
        assert_eq!(key.as_bytes().len(), KEYBYTES);
    }

    #[test]
    fn test_key_from_slice() {
        let bytes = vec![0u8; KEYBYTES];
        let key = Key::from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), bytes.as_slice());

        // Test invalid key size
        assert!(Key::from_slice(&[0u8; KEYBYTES + 1]).is_err());
    }

    #[test]
    fn test_tag_from_slice() {
        let bytes = vec![0u8; BYTES];
        let tag = Tag::from_slice(&bytes).unwrap();
        assert_eq!(tag.as_bytes(), bytes.as_slice());

        // Test invalid tag size
        assert!(Tag::from_slice(&[0u8; BYTES + 1]).is_err());
    }

    #[test]
    fn test_auth_and_verify() {
        let key = Key::generate().unwrap();
        let message = b"test message";

        // Create authentication tag
        let tag = auth(message, &key).unwrap();

        // Verify the tag
        assert!(verify(&tag, message, &key));

        // Verify with wrong message
        assert!(!verify(&tag, b"wrong message", &key));

        // Verify with wrong key
        let wrong_key = Key::generate().unwrap();
        assert!(!verify(&tag, message, &wrong_key));
    }

    #[test]
    fn test_key_as_ref() {
        let key = Key::generate().unwrap();
        let key_ref: &[u8] = key.as_ref();
        assert_eq!(key_ref.len(), KEYBYTES);
        assert_eq!(key_ref, key.as_bytes());
    }

    #[test]
    fn test_key_try_from_slice() {
        // Valid slice
        let bytes = vec![0x42; KEYBYTES];
        let key = Key::try_from(bytes.as_slice()).unwrap();
        assert_eq!(key.as_bytes(), bytes.as_slice());

        // Invalid slice - too short
        let short_bytes = vec![0x42; KEYBYTES - 1];
        assert!(Key::try_from(short_bytes.as_slice()).is_err());

        // Invalid slice - too long
        let long_bytes = vec![0x42; KEYBYTES + 1];
        assert!(Key::try_from(long_bytes.as_slice()).is_err());
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [0x42; KEYBYTES];
        let key = Key::from(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_into_bytes() {
        let original_bytes = [0x42; KEYBYTES];
        let key = Key::from(original_bytes);
        let bytes: [u8; KEYBYTES] = key.into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_tag_as_ref() {
        let key = Key::generate().unwrap();
        let message = b"test message";
        let tag = auth(message, &key).unwrap();
        let tag_ref: &[u8] = tag.as_ref();
        assert_eq!(tag_ref.len(), BYTES);
        assert_eq!(tag_ref, tag.as_bytes());
    }

    #[test]
    fn test_tag_try_from_slice() {
        // Valid slice
        let bytes = vec![0x42; BYTES];
        let tag = Tag::try_from(bytes.as_slice()).unwrap();
        assert_eq!(tag.as_bytes(), bytes.as_slice());

        // Invalid slice - too short
        let short_bytes = vec![0x42; BYTES - 1];
        assert!(Tag::try_from(short_bytes.as_slice()).is_err());

        // Invalid slice - too long
        let long_bytes = vec![0x42; BYTES + 1];
        assert!(Tag::try_from(long_bytes.as_slice()).is_err());
    }

    #[test]
    fn test_tag_from_bytes() {
        let bytes = [0x42; BYTES];
        let tag = Tag::from(bytes);
        assert_eq!(tag.as_bytes(), &bytes);
    }

    #[test]
    fn test_tag_into_bytes() {
        let original_bytes = [0x42; BYTES];
        let tag = Tag::from(original_bytes);
        let bytes: [u8; BYTES] = tag.into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_key_tag_roundtrip() {
        // Test Key roundtrip
        let key_bytes = [0x42; KEYBYTES];
        let key = Key::from(key_bytes);
        let key_bytes_out: [u8; KEYBYTES] = key.into();
        assert_eq!(key_bytes, key_bytes_out);
        let key_from_bytes = Key::from(key_bytes_out);
        assert_eq!(key_from_bytes.as_bytes(), &key_bytes);

        // Test Tag roundtrip with real tag
        let key = Key::generate().unwrap();
        let message = b"test message";
        let tag = auth(message, &key).unwrap();
        let tag_bytes: [u8; BYTES] = tag.clone().into();
        let tag_from_bytes = Tag::from(tag_bytes);
        assert_eq!(tag.as_bytes(), tag_from_bytes.as_bytes());

        // Verify the reconstructed tag still works
        assert!(verify(&tag_from_bytes, message, &key));
    }
}
