//! HMAC-SHA-512 Message Authentication Code
//!
//! This module provides functions for computing and verifying HMAC-SHA-512 message authentication
//! codes. HMAC-SHA-512 is a keyed hash function that can be used to verify both the integrity and
//! authenticity of a message.
//!
//! ## Features
//!
//! - **Strong security**: Based on the SHA-512 hash function, providing 256-bit security
//! - **Standardized**: Widely used and recognized in security protocols
//! - **Fixed output size**: Always produces a 64-byte (512-bit) authentication tag
//! - **Incremental interface**: Supports processing large messages in chunks
//!
//! ## Security Considerations
//!
//! - The key should be kept secret and should be randomly generated
//! - HMAC-SHA-512 provides stronger security than HMAC-SHA-256 at the cost of slightly lower performance
//! - For public key authentication, consider using crypto_sign instead
//!
//! ## Example Usage
//!
//! ```
//! # use libsodium_rs::crypto_auth::hmacsha512;
//! # use libsodium_rs::ensure_init;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # ensure_init()?;
//! // Generate a random key
//! let key = hmacsha512::Key::generate();
//!
//! // Message to authenticate
//! let message = b"Hello, world!";
//!
//! // Compute the authentication tag
//! let tag = hmacsha512::auth(message, &key)?;
//!
//! // Verify the authentication tag
//! hmacsha512::verify(&tag, message, &key)?;
//!
//! // The verification succeeds only if the tag is valid for this message and key
//! assert!(hmacsha512::verify(&tag, message, &key).is_ok());
//! # Ok(())
//! # }
//! ```

use crate::{Result, SodiumError};
use libc;

/// Number of bytes in a key
pub const KEYBYTES: usize = libsodium_sys::crypto_auth_hmacsha512_KEYBYTES as usize;
/// Number of bytes in a MAC (message authentication code)
pub const BYTES: usize = libsodium_sys::crypto_auth_hmacsha512_BYTES as usize;

/// A key for HMAC-SHA-512
#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop, Clone, Eq, PartialEq)]
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
        unsafe {
            libsodium_sys::crypto_auth_hmacsha512_keygen(key.as_mut_ptr());
        }
        Key(key)
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

/// HMAC-SHA-512 state for incremental authentication
pub struct State {
    state: Box<libsodium_sys::crypto_auth_hmacsha512_state>,
}

impl State {
    /// Creates a new HMAC-SHA-512 authentication state
    pub fn new(key: &Key) -> Result<Self> {
        let mut state: Box<libsodium_sys::crypto_auth_hmacsha512_state> =
            Box::new(unsafe { std::mem::zeroed() });
        let result = unsafe {
            libsodium_sys::crypto_auth_hmacsha512_init(
                state.as_mut(),
                key.as_bytes().as_ptr(),
                key.as_bytes().len() as libc::size_t,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to initialize state".into(),
            ));
        }

        Ok(State { state })
    }

    /// Updates the authentication state with more input data
    pub fn update(&mut self, input: &[u8]) -> Result<()> {
        let result = unsafe {
            libsodium_sys::crypto_auth_hmacsha512_update(
                self.state.as_mut(),
                input.as_ptr(),
                input.len() as libc::c_ulonglong,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError("failed to update state".into()));
        }

        Ok(())
    }

    /// Finalizes the authentication computation and returns the MAC
    pub fn finalize(&mut self) -> Result<[u8; BYTES]> {
        let mut mac = [0u8; BYTES];
        let result = unsafe {
            libsodium_sys::crypto_auth_hmacsha512_final(self.state.as_mut(), mac.as_mut_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to finalize authentication".into(),
            ));
        }

        Ok(mac)
    }
}

/// Computes a HMAC-SHA-512 authentication tag for the input data
pub fn auth(input: &[u8], key: &Key) -> Result<[u8; BYTES]> {
    let mut mac = [0u8; BYTES];

    let result = unsafe {
        libsodium_sys::crypto_auth_hmacsha512(
            mac.as_mut_ptr(),
            input.as_ptr(),
            input.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("authentication failed".into()));
    }

    Ok(mac)
}

/// Verifies a HMAC-SHA-512 authentication tag
pub fn verify(mac: &[u8; BYTES], input: &[u8], key: &Key) -> Result<()> {
    let result = unsafe {
        libsodium_sys::crypto_auth_hmacsha512_verify(
            mac.as_ptr(),
            input.as_ptr(),
            input.len() as libc::c_ulonglong,
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("verification failed".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder, Encoder, Hex};

    #[test]
    fn test_auth() {
        let key = Key::generate();
        let message = b"Hello, World!";

        let mac = auth(message, &key).unwrap();
        assert_eq!(mac.len(), BYTES);

        // Verify the MAC
        assert!(verify(&mac, message, &key).is_ok());

        // Verify with wrong message
        let wrong_message = b"Wrong message";
        assert!(verify(&mac, wrong_message, &key).is_err());

        // Verify with wrong key
        let wrong_key = Key::generate();
        assert!(verify(&mac, message, &wrong_key).is_err());
    }

    #[test]
    fn test_auth_incremental() {
        let key = Key::generate();
        let message1 = b"Hello, ";
        let message2 = b"World!";

        // Compute MAC in one go
        let full_message = b"Hello, World!";
        let expected_mac = auth(full_message, &key).unwrap();

        // Compute MAC incrementally
        let mut state = State::new(&key).unwrap();
        state.update(message1).unwrap();
        state.update(message2).unwrap();
        let incremental_mac = state.finalize().unwrap();

        assert_eq!(expected_mac, incremental_mac);
    }

    #[test]
    fn test_known_vector() {
        // Test vector from RFC 4231 (Test Case 1)
        let mut key_bytes = vec![0u8; 20]; // 20 bytes for the hex string "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        Hex::decode(
            &mut key_bytes,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            None,
        )
        .unwrap();
        let mut padded_key = [0u8; KEYBYTES];
        padded_key[..key_bytes.len()].copy_from_slice(&key_bytes);

        let key = Key::from_bytes(&padded_key).unwrap();
        let message = b"Hi There";

        let mac = auth(message, &key).unwrap();
        let expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";

        let mut encoded = vec![0u8; mac.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, mac).unwrap();
        assert_eq!(std::str::from_utf8(encoded).unwrap(), expected);
    }

    #[test]
    fn test_key_as_ref() {
        let key = Key::generate();
        let bytes: &[u8] = key.as_ref();
        assert_eq!(bytes.len(), KEYBYTES);
        assert_eq!(bytes, key.as_bytes());
    }

    #[test]
    fn test_key_try_from_slice() {
        // Valid key
        let bytes = vec![0u8; KEYBYTES];
        let key = Key::try_from(bytes.as_slice()).unwrap();
        assert_eq!(key.as_bytes(), &bytes[..]);

        // Invalid key - too short
        let short_bytes = vec![0u8; KEYBYTES - 1];
        assert!(Key::try_from(short_bytes.as_slice()).is_err());

        // Invalid key - too long
        let long_bytes = vec![0u8; KEYBYTES + 1];
        assert!(Key::try_from(long_bytes.as_slice()).is_err());
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [42u8; KEYBYTES];
        let key = Key::from(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_into_bytes() {
        let original_bytes = [42u8; KEYBYTES];
        let key = Key::from(original_bytes);
        let bytes: [u8; KEYBYTES] = key.into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_key_roundtrip() {
        let original_bytes = [0x55u8; KEYBYTES];

        // From array -> Key -> into array
        let key = Key::from(original_bytes);
        let result: [u8; KEYBYTES] = key.into();
        assert_eq!(result, original_bytes);

        // From slice -> Key -> as_ref
        let key2 = Key::try_from(&original_bytes[..]).unwrap();
        let slice: &[u8] = key2.as_ref();
        assert_eq!(slice, &original_bytes[..]);
    }
}
