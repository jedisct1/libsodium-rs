//! # One-Time Authentication (Poly1305)
//!
//! This module provides functions for computing and verifying one-time authentication tags
//! using the Poly1305 algorithm. Poly1305 is a cryptographic message authentication code (MAC)
//! that can be used to verify the integrity and authenticity of a message.
//!
//! ## About Poly1305
//!
//! Poly1305 is a state-of-the-art message authentication code designed by Daniel J. Bernstein.
//! It computes a 16-byte (128-bit) authentication tag for a message and a 32-byte key.
//! The algorithm is based on evaluation of a polynomial modulo the prime 2^130 - 5.
//!
//! ## Security Properties
//!
//! - **High security**: Poly1305 offers 128-bit security against forgery attempts
//! - **Constant-time**: The implementation is designed to take the same amount of time regardless of input
//! - **Deterministic**: The same message and key always produce the same tag
//! - **Efficient**: Poly1305 is extremely fast on modern processors
//!
//! ## Security Considerations
//!
//! - **CRITICAL**: Each key must be used **only once**. Reusing a key for multiple messages
//!   completely compromises security. The name "one-time" is not a suggestion but a strict requirement.
//! - Poly1305 is designed to be used in conjunction with a cipher, typically in an AEAD construction.
//! - For most applications, you should use higher-level AEAD constructions like `crypto_secretbox`
//!   or `crypto_box` instead of using this module directly.
//! - Poly1305 by itself does not provide confidentiality (encryption) - it only provides authenticity.
//!
//! ## When to Use This Module
//!
//! You should only use this module directly if you:
//! - Understand the security implications of one-time authentication
//! - Have a specific need for standalone authentication tags
//! - Can guarantee that each key will be used only once
//! - Have a secure mechanism for key generation and management
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_onetimeauth;
//! use sodium::ensure_init;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     ensure_init()?;
//!
//!     // Generate a random key (should only be used once)
//!     let key = crypto_onetimeauth::Key::generate();
//!     let message = b"Hello, world!";
//!
//!     // Compute the authentication tag
//!     let tag = crypto_onetimeauth::onetimeauth(message, &key);
//!
//!     // Verify the tag
//!     assert!(crypto_onetimeauth::verify(&tag, message, &key));
//!
//!     // For incremental authentication
//!     let mut state = crypto_onetimeauth::State::new(&key);
//!     state.update(b"Hello, ");
//!     state.update(b"world!");
//!     let tag2 = state.finalize();
//!
//!     assert_eq!(tag.as_bytes(), tag2.as_bytes());
//!     Ok(())
//! }
//! ```
//!

use crate::{Result, SodiumError};
use std::convert::TryFrom;
use std::fmt;

/// Number of bytes in a key
pub const KEYBYTES: usize = libsodium_sys::crypto_onetimeauth_KEYBYTES as usize;
/// Number of bytes in a tag
pub const BYTES: usize = libsodium_sys::crypto_onetimeauth_BYTES as usize;

/// A key for Poly1305 one-time authentication
///
/// This key is used for computing and verifying Poly1305 authentication tags.
/// It must be exactly 32 bytes long.
///
/// ## Security Warning
///
/// This key should be used only once for a single message.
/// Reusing the same key for multiple messages completely compromises security.
/// This is why Poly1305 is called a "one-time" authenticator.
///
/// ## Key Generation
///
/// Keys should be generated using a cryptographically secure random number generator.
/// The `generate()` method provides a convenient way to create a secure random key.
///
/// ## Usage Pattern
///
/// 1. Generate a new key for each message to be authenticated
/// 2. Use the key to compute an authentication tag
/// 3. Never reuse the key for another message
/// 4. Store or transmit the key securely alongside the message and tag
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

/// A Poly1305 authentication tag
///
/// This tag is used to verify the authenticity of a message. It is always 16 bytes (128 bits) long.
///
/// ## Security Properties
///
/// - The tag provides 128-bit security against forgery attempts
/// - Tags are deterministic: the same message and key always produce the same tag
/// - Verification is constant-time to prevent timing attacks
///
/// ## Usage
///
/// - The tag should be transmitted or stored alongside the message
/// - The recipient can verify the tag to ensure the message hasn't been tampered with
/// - The tag does not need to be kept secret, but the key used to create it does
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tag([u8; BYTES]);

impl Key {
    /// Generate a new key from bytes
    ///
    /// # Arguments
    /// * `bytes` - The bytes to create the key from
    ///
    /// # Returns
    /// * `Result<Self>` - The key or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `KEYBYTES` bytes long
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {} bytes, got {}",
                KEYBYTES,
                bytes.len()
            )));
        }

        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(bytes);
        Ok(Key(key))
    }

    /// Generate a new random key
    ///
    /// # Returns
    /// * `Self` - A randomly generated key
    ///
    /// # Panics
    /// This function will panic if the random number generator fails, which should never happen
    pub fn generate() -> Self {
        let bytes = crate::random::bytes(KEYBYTES);
        // This unwrap is safe because we know the length is correct
        Key::from_bytes(&bytes).unwrap()
    }

    /// Get the bytes of the key
    ///
    /// # Returns
    /// * `&[u8]` - A reference to the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Tag {
    /// Create a tag from bytes
    ///
    /// # Arguments
    /// * `bytes` - The bytes to create the tag from
    ///
    /// # Returns
    /// * `Result<Self>` - The tag or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `BYTES` bytes long
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "tag must be exactly {} bytes, got {}",
                BYTES,
                bytes.len()
            )));
        }

        let mut tag = [0u8; BYTES];
        tag.copy_from_slice(bytes);
        Ok(Tag(tag))
    }

    /// Get the bytes of the tag
    ///
    /// # Returns
    /// * `&[u8]` - A reference to the tag bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Poly1305 state for incremental authentication
///
/// This structure allows computing a Poly1305 authentication tag incrementally,
/// which is useful when the entire message is not available at once or when
/// processing large messages in chunks to avoid excessive memory usage.
///
/// ## Memory Efficiency
///
/// Using the incremental API allows processing messages of any size without
/// needing to load the entire message into memory at once. This is particularly
/// useful for:
///
/// - Large files that don't fit in memory
/// - Streaming data from a network or other source
/// - Memory-constrained environments
///
/// ## Security Note
///
/// The security properties of Poly1305 are maintained when using the incremental API.
/// The same tag will be produced regardless of how the message is chunked, as long as
/// the chunks are processed in the correct order.
pub struct State {
    state: Box<libsodium_sys::crypto_onetimeauth_state>,
}

impl State {
    /// Creates a new Poly1305 authentication state
    ///
    /// # Arguments
    /// * `key` - The key to use for authentication
    ///
    /// # Returns
    /// * `Self` - The initialized state
    ///
    /// # Panics
    /// This function should never panic with valid inputs. The key validity is ensured by the Key type.
    pub fn new(key: &Key) -> Self {
        let mut state: Box<libsodium_sys::crypto_onetimeauth_state> =
            Box::new(unsafe { std::mem::zeroed() });
        let result = unsafe {
            libsodium_sys::crypto_onetimeauth_init(state.as_mut(), key.as_bytes().as_ptr())
        };

        // This should never fail with a valid key, which is guaranteed by the Key type
        debug_assert_eq!(result, 0, "Poly1305 state initialization failed");

        State { state }
    }

    /// Updates the authentication state with more input data
    ///
    /// # Arguments
    /// * `input` - The data to include in the authentication
    ///
    /// This function cannot fail with valid inputs, and we validate inputs through the State constructor.
    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            // This call cannot fail with valid inputs
            libsodium_sys::crypto_onetimeauth_update(
                self.state.as_mut(),
                input.as_ptr(),
                input.len() as libc::c_ulonglong,
            );
        }
    }

    /// Finalizes the authentication computation and returns the tag
    ///
    /// # Returns
    /// * `Tag` - The authentication tag
    ///
    /// This function cannot fail with valid inputs, and we validate inputs through the State constructor.
    pub fn finalize(&mut self) -> Tag {
        let mut tag = [0u8; BYTES];
        unsafe {
            // This call cannot fail with valid inputs
            libsodium_sys::crypto_onetimeauth_final(self.state.as_mut(), tag.as_mut_ptr());
        }

        Tag(tag)
    }
}

/// Computes a Poly1305 one-time authentication tag for the input data
///
/// This function computes a 16-byte (128-bit) authentication tag for the given input data
/// using the provided key. It provides a convenient one-shot interface for authenticating
/// data that is already available in memory.
///
/// ## Security Properties
///
/// - **Forgery resistance**: It is computationally infeasible to create a valid tag for a
///   message without knowing the key
/// - **Collision resistance**: It is computationally infeasible to find two different messages
///   that produce the same tag with the same key
///
/// ## Use Cases
///
/// - **Message authentication**: Verify that a message hasn't been tampered with
/// - **API request signing**: Authenticate requests to an API
/// - **Component of authenticated encryption**: Used in combination with encryption
///
/// ## Arguments
/// * `input` - The data to authenticate
/// * `key` - The key to use for authentication (should be used only once)
///
/// ## Returns
/// * `Tag` - The 16-byte authentication tag
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_onetimeauth;
/// use sodium::ensure_init;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     ensure_init()?;
///
///     // Generate a random key (should only be used once)
///     let key = crypto_onetimeauth::Key::generate();
///     let message = b"Message to authenticate";
///
///     // Compute the authentication tag
///     let tag = crypto_onetimeauth::onetimeauth(message, &key);
///
///     // Later, verify the tag
///     assert!(crypto_onetimeauth::verify(&tag, message, &key));
///     Ok(())
/// }
/// ```
///
/// ## Security Considerations
/// - **CRITICAL**: Each key must be used only once. Reusing a key for multiple messages
///   completely compromises security.
/// - For most applications, you should use higher-level AEAD constructions like `crypto_secretbox`
///   or `crypto_box` instead of using this function directly.
/// - This function does not provide confidentiality (encryption) - it only provides authenticity.
pub fn onetimeauth(input: &[u8], key: &Key) -> Tag {
    let mut tag = [0u8; BYTES];

    unsafe {
        // This call cannot fail with valid inputs, and we validate inputs through the Key type
        libsodium_sys::crypto_onetimeauth(
            tag.as_mut_ptr(),
            input.as_ptr(),
            input.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        );
    }

    Tag(tag)
}

/// Verifies a Poly1305 one-time authentication tag
///
/// This function verifies that a Poly1305 authentication tag is valid for the given
/// input data and key. It returns a boolean indicating whether the tag is valid.
///
/// ## Constant-Time Verification
///
/// This function performs verification in constant time to prevent timing attacks.
/// This means the time taken to verify a tag does not depend on the content of the
/// tag or the validity of the tag, making it resistant to timing side-channel attacks.
///
/// ## Security Considerations
///
/// - The key used for verification must be the same key used to create the tag
/// - Even if verification fails, the key should not be reused for another message
/// - Failed verification indicates the message may have been tampered with or corrupted
///
/// ## Arguments
/// * `tag` - The tag to verify
/// * `input` - The data that was authenticated
/// * `key` - The key that was used for authentication
///
/// ## Returns
/// * `bool` - `true` if the tag is valid, `false` otherwise
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_onetimeauth;
/// use sodium::ensure_init;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     ensure_init()?;
///
///     // Generate a random key (should only be used once)
///     let key = crypto_onetimeauth::Key::generate();
///     let message = b"Message to authenticate";
///     let tag = crypto_onetimeauth::onetimeauth(message, &key);
///
///     // Verify the tag with the original message
///     assert!(crypto_onetimeauth::verify(&tag, message, &key));
///
///     // Verification should fail with a different message
///     let tampered_message = b"Tampered message";
///     assert!(!crypto_onetimeauth::verify(&tag, tampered_message, &key));
///     Ok(())
/// }
/// ```
pub fn verify(tag: &Tag, input: &[u8], key: &Key) -> bool {
    let result = unsafe {
        libsodium_sys::crypto_onetimeauth_verify(
            tag.as_bytes().as_ptr(),
            input.as_ptr(),
            input.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        )
    };

    result == 0
}

// Add implementation of Display for Tag for easier debugging
impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({:?})", self.0)
    }
}

// Add implementation of TryFrom for Key for more idiomatic conversions
impl TryFrom<&[u8]> for Key {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Key::from_bytes(bytes)
    }
}

// Add implementation of TryFrom for Tag for more idiomatic conversions
impl TryFrom<&[u8]> for Tag {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Tag::from_bytes(bytes)
    }
}

// Add AsRef<[u8]> implementation for Key
impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Add AsRef<[u8]> implementation for Tag
impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Add From<[u8; KEYBYTES]> for Key
impl From<[u8; KEYBYTES]> for Key {
    fn from(bytes: [u8; KEYBYTES]) -> Self {
        Key(bytes)
    }
}

// Add From<[u8; BYTES]> for Tag
impl From<[u8; BYTES]> for Tag {
    fn from(bytes: [u8; BYTES]) -> Self {
        Tag(bytes)
    }
}

// Add From<Key> for [u8; KEYBYTES]
impl From<Key> for [u8; KEYBYTES] {
    fn from(key: Key) -> Self {
        key.0
    }
}

// Add From<Tag> for [u8; BYTES]
impl From<Tag> for [u8; BYTES] {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onetimeauth() {
        // Generate a random key
        let key = Key::generate();
        let message = b"Hello, World!";

        // Compute the authentication tag
        let tag = onetimeauth(message, &key);
        assert_eq!(tag.as_bytes().len(), BYTES);

        // Verify the tag with correct inputs
        assert!(verify(&tag, message, &key));

        // Verify with wrong message - should fail
        let wrong_message = b"Wrong message";
        assert!(!verify(&tag, wrong_message, &key));

        // Verify with wrong key - should fail
        let wrong_key = Key::generate();
        assert!(!verify(&tag, message, &wrong_key));
    }

    #[test]
    fn test_onetimeauth_incremental() {
        // Generate a random key
        let key = Key::generate();
        let message1 = b"Hello, ";
        let message2 = b"World!";

        // Compute tag in one go for comparison
        let full_message = b"Hello, World!";
        let expected_tag = onetimeauth(full_message, &key);

        // Compute tag incrementally
        let mut state = State::new(&key);
        state.update(message1);
        state.update(message2);
        let incremental_tag = state.finalize();

        // Both methods should produce the same tag
        assert_eq!(expected_tag.as_bytes(), incremental_tag.as_bytes());
    }

    #[test]
    fn test_key_trait_implementations() {
        // Test From<[u8; KEYBYTES]> for Key
        let key_bytes = [42u8; KEYBYTES];
        let key = Key::from(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let key_bytes_back: [u8; KEYBYTES] = key.clone().into();
        assert_eq!(key_bytes_back, key_bytes);

        // Test AsRef<[u8]> for Key
        let key_ref: &[u8] = key.as_ref();
        assert_eq!(key_ref, &key_bytes);
        assert_eq!(key_ref.len(), KEYBYTES);
    }

    #[test]
    fn test_tag_trait_implementations() {
        // Test From<[u8; BYTES]> for Tag
        let tag_bytes = [99u8; BYTES];
        let tag = Tag::from(tag_bytes);
        assert_eq!(tag.as_bytes(), &tag_bytes);

        // Test From<Tag> for [u8; BYTES]
        let tag_bytes_back: [u8; BYTES] = tag.clone().into();
        assert_eq!(tag_bytes_back, tag_bytes);

        // Test AsRef<[u8]> for Tag
        let tag_ref: &[u8] = tag.as_ref();
        assert_eq!(tag_ref, &tag_bytes);
        assert_eq!(tag_ref.len(), BYTES);
    }

    #[test]
    fn test_key_tag_conversions_with_real_crypto() {
        // Generate a real key and test conversions
        let key = Key::generate();
        let key_bytes: [u8; KEYBYTES] = key.clone().into();
        let key_restored = Key::from(key_bytes);
        assert_eq!(key.as_bytes(), key_restored.as_bytes());

        // Test with real crypto operations
        let message = b"Test message for trait conversions";
        let tag = onetimeauth(message, &key_restored);

        // Convert tag to bytes and back
        let tag_bytes: [u8; BYTES] = tag.clone().into();
        let tag_restored = Tag::from(tag_bytes);

        // Verify the restored tag works correctly
        assert!(verify(&tag_restored, message, &key_restored));
    }
}
