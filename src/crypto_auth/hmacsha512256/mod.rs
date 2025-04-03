//! HMAC-SHA-512-256 Message Authentication Code
//!
//! This module provides functions for computing and verifying HMAC-SHA-512-256 message authentication
//! codes. HMAC-SHA-512-256 is a keyed hash function that computes the HMAC using SHA-512 and then
//! truncates the output to 256 bits, providing a good balance between security and output size.
//!
//! ## Features
//!
//! - **Strong security**: Based on the SHA-512 hash function, truncated to 256 bits
//! - **Standardized**: Widely used and recognized in security protocols
//! - **Fixed output size**: Always produces a 32-byte (256-bit) authentication tag
//! - **Incremental interface**: Supports processing large messages in chunks
//!
//! ## Security Considerations
//!
//! - The key should be kept secret and should be randomly generated
//! - HMAC-SHA-512-256 provides the security of SHA-512 with the output size of SHA-256
//! - This is more resistant to length extension attacks than HMAC-SHA-256
//! - For public key authentication, consider using crypto_sign instead
//!
//! ## Example Usage
//!
//! ```
//! # use libsodium_rs::crypto_auth::hmacsha512256;
//! # use libsodium_rs::ensure_init;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # ensure_init()?;
//! // Generate a random key
//! let key = hmacsha512256::Key::generate();
//!
//! // Message to authenticate
//! let message = b"Hello, world!";
//!
//! // Compute the authentication tag
//! let tag = hmacsha512256::auth(message, &key)?;
//!
//! // Verify the authentication tag
//! hmacsha512256::verify(&tag, message, &key)?;
//!
//! // The verification succeeds only if the tag is valid for this message and key
//! assert!(hmacsha512256::verify(&tag, message, &key).is_ok());
//! # Ok(())
//! # }
//! ```

use crate::{Result, SodiumError};
use libc;

/// Number of bytes in a key
pub const KEYBYTES: usize = libsodium_sys::crypto_auth_hmacsha512256_KEYBYTES as usize;
/// Number of bytes in a MAC (message authentication code)
pub const BYTES: usize = libsodium_sys::crypto_auth_hmacsha512256_BYTES as usize;

/// A key for HMAC-SHA-512-256
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
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_auth_hmacsha512256_keygen(key.as_mut_ptr());
        }
        Key(key)
    }

    /// Get the bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// HMAC-SHA-512-256 state for incremental authentication
pub struct State {
    state: Box<libsodium_sys::crypto_auth_hmacsha512256_state>,
}

impl State {
    /// Creates a new HMAC-SHA-512-256 authentication state
    pub fn new(key: &Key) -> Result<Self> {
        let mut state: Box<libsodium_sys::crypto_auth_hmacsha512256_state> =
            Box::new(unsafe { std::mem::zeroed() });
        let result = unsafe {
            libsodium_sys::crypto_auth_hmacsha512256_init(
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
            libsodium_sys::crypto_auth_hmacsha512256_update(
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
            libsodium_sys::crypto_auth_hmacsha512256_final(self.state.as_mut(), mac.as_mut_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to finalize authentication".into(),
            ));
        }

        Ok(mac)
    }
}

/// Computes a HMAC-SHA-512-256 authentication tag for the input data
pub fn auth(input: &[u8], key: &Key) -> Result<[u8; BYTES]> {
    let mut mac = [0u8; BYTES];

    let result = unsafe {
        libsodium_sys::crypto_auth_hmacsha512256(
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

/// Verifies a HMAC-SHA-512-256 authentication tag
pub fn verify(mac: &[u8; BYTES], input: &[u8], key: &Key) -> Result<()> {
    let result = unsafe {
        libsodium_sys::crypto_auth_hmacsha512256_verify(
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
        // This is the first 32 bytes of the HMAC-SHA-512 output
        let expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde";

        let mut encoded = vec![0u8; mac.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, mac).unwrap();
        assert_eq!(std::str::from_utf8(encoded).unwrap(), expected);
    }
}
