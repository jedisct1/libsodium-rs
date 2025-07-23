//! # Generic Hash Function (BLAKE2b)
//!
//! This module provides a cryptographic hash function based on BLAKE2b that can be used
//! for a wide range of applications. BLAKE2b is a high-performance cryptographic hash
//! function that can be used as a replacement for SHA-2 and SHA-3.
//!
//! ## Features
//!
//! - **Variable output length**: Can produce hashes of any size between `BYTES_MIN` (16) and `BYTES_MAX` (64) bytes
//! - **Keyed hashing**: Supports keyed hashing (MAC) with keys of variable length
//! - **High performance**: Optimized for modern CPUs, faster than SHA-2 and SHA-3
//! - **Incremental hashing**: Supports incremental hashing for processing large data streams
//!
//! ## Security Considerations
//!
//! - BLAKE2b is a cryptographically secure hash function suitable for most applications
//! - For password hashing, use the `crypto_pwhash` module instead
//! - For message authentication codes (MACs), you can use this module with a key
//!
//! ## Example Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_generichash;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Simple hashing
//! let data = b"Hello, world!";
//! let hash = crypto_generichash::generichash(
//!     data,
//!     None,                            // No key
//!     crypto_generichash::BYTES,       // Default output length (32 bytes)
//! );
//!
//! // Keyed hashing (MAC)
//! let key = sodium::random::bytes(crypto_generichash::KEYBYTES); // 32-byte key
//! let keyed_hash = crypto_generichash::generichash(
//!     data,
//!     Some(&key),                      // With key
//!     crypto_generichash::BYTES,       // Default output length
//! );
//!
//! // Incremental hashing
//! let mut state = crypto_generichash::State::new(None, crypto_generichash::BYTES)
//!     .expect("Failed to initialize hash state");
//! state.update(b"Hello, ");
//! state.update(b"world!");
//! let incremental_hash = state.finalize();
//! ```

use crate::{Result, SodiumError};

// Export the blake2b submodule
pub mod blake2b;
pub use blake2b::*;

/// Minimum number of bytes in a hash output (16)
///
/// This is the minimum length of a hash that can be produced by the generic hash function.
pub const BYTES_MIN: usize = libsodium_sys::crypto_generichash_BYTES_MIN as usize;

/// Maximum number of bytes in a hash output (64)
///
/// This is the maximum length of a hash that can be produced by the generic hash function.
pub const BYTES_MAX: usize = libsodium_sys::crypto_generichash_BYTES_MAX as usize;

/// Default number of bytes in a hash output (32)
///
/// This is the recommended length for most applications, providing a good balance
/// between security and size.
pub const BYTES: usize = libsodium_sys::crypto_generichash_BYTES as usize;

/// Minimum number of bytes in a key (16)
///
/// This is the minimum length of a key that can be used for keyed hashing.
pub const KEYBYTES_MIN: usize = libsodium_sys::crypto_generichash_KEYBYTES_MIN as usize;

/// Maximum number of bytes in a key (64)
///
/// This is the maximum length of a key that can be used for keyed hashing.
pub const KEYBYTES_MAX: usize = libsodium_sys::crypto_generichash_KEYBYTES_MAX as usize;

/// Default number of bytes in a key (32)
///
/// This is the recommended key length for most applications, providing a good balance
/// between security and size.
pub const KEYBYTES: usize = libsodium_sys::crypto_generichash_KEYBYTES as usize;

/// BLAKE2b state for incremental hashing
///
/// This struct represents the state of a BLAKE2b hash computation. It is used for
/// incremental hashing, where data is processed in chunks rather than all at once.
/// This is useful for hashing large files or streams of data.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_generichash;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Create a new hashing state
/// let mut state = crypto_generichash::State::new(
///     None,                            // No key
///     crypto_generichash::BYTES,       // Default output length (32 bytes)
/// ).expect("Failed to initialize hash state");
///
/// // Update the state with data in chunks
/// state.update(b"Hello, ");
/// state.update(b"world!");
///
/// // Finalize the hash computation
/// let hash = state.finalize();
/// ```
pub struct State {
    state: libsodium_sys::crypto_generichash_state,
    output_len: usize,
}

impl Drop for State {
    fn drop(&mut self) {
        // Securely clear the state when dropped
        unsafe {
            // Use sodium_memzero to clear the state
            libsodium_sys::sodium_memzero(
                &mut self.state as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libsodium_sys::crypto_generichash_state>(),
            );
        }
    }
}

impl State {
    /// Creates a new BLAKE2b hashing state
    ///
    /// This function initializes a new BLAKE2b hashing state for incremental hashing.
    /// It can be used with or without a key, and the output length can be customized.
    ///
    /// ## Algorithm Details
    ///
    /// The generic hash function is currently implemented using BLAKE2b, a fast
    /// cryptographic hash function built on the ChaCha stream cipher. BLAKE2b is
    /// designed to be faster than MD5, SHA-1, SHA-2, and SHA-3, yet is at least
    /// as secure as the latest standard SHA-3.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new hashing state without a key
    /// let mut state = crypto_generichash::State::new(
    ///     None,                            // No key
    ///     crypto_generichash::BYTES,       // Default output length (32 bytes)
    /// ).unwrap();
    ///
    /// // Create a new hashing state with a key (for MAC)
    /// let key = sodium::random::bytes(crypto_generichash::KEYBYTES); // 32-byte key
    /// let mut keyed_state = crypto_generichash::State::new(
    ///     Some(&key),                      // With key
    ///     crypto_generichash::BYTES,       // Default output length
    /// ).unwrap();
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `key` - Optional key for keyed hashing (MAC). If provided, must be between
    ///   `KEYBYTES_MIN` (16) and `KEYBYTES_MAX` (64) bytes.
    /// * `output_len` - Length of the output hash in bytes. Must be between
    ///   `BYTES_MIN` (16) and `BYTES_MAX` (64) bytes.
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new BLAKE2b state or an error
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The output length is not between `BYTES_MIN` and `BYTES_MAX`
    /// - The key length is not between `KEYBYTES_MIN` and `KEYBYTES_MAX`
    /// - The state initialization fails
    pub fn new(key: Option<&[u8]>, output_len: usize) -> Result<Self> {
        if !(BYTES_MIN..=BYTES_MAX).contains(&output_len) {
            return Err(SodiumError::InvalidInput(format!(
                "Output length must be between {BYTES_MIN} and {BYTES_MAX} bytes"
            )));
        }

        if let Some(key) = key {
            if key.len() < KEYBYTES_MIN || key.len() > KEYBYTES_MAX {
                return Err(SodiumError::InvalidInput(format!(
                    "Key length must be between {KEYBYTES_MIN} and {KEYBYTES_MAX} bytes"
                )));
            }
        }

        let mut state = Self {
            state: unsafe { std::mem::zeroed() },
            output_len,
        };

        let result = match key {
            Some(key) => unsafe {
                libsodium_sys::crypto_generichash_init(
                    &mut state.state,
                    key.as_ptr(),
                    key.len() as libc::size_t,
                    output_len as libc::size_t,
                )
            },
            None => unsafe {
                libsodium_sys::crypto_generichash_init(
                    &mut state.state,
                    std::ptr::null(),
                    0,
                    output_len as libc::size_t,
                )
            },
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "Failed to initialize BLAKE2b state".to_string(),
            ));
        }

        Ok(state)
    }

    /// Updates the hash state with more input data
    ///
    /// This function updates the hash state with additional input data.
    /// It can be called multiple times to process data in chunks.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new hashing state
    /// let mut state = crypto_generichash::State::new(
    ///     None,                            // No key
    ///     crypto_generichash::BYTES,       // Default output length (32 bytes)
    /// ).unwrap();
    ///
    /// // Update the state with data in chunks
    /// state.update(b"Hello, ");
    /// state.update(b"world!");
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `input` - Data to add to the hash computation
    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            libsodium_sys::crypto_generichash_update(
                &mut self.state,
                input.as_ptr(),
                input.len() as libc::c_ulonglong,
            );
        }
    }

    /// Finalizes the hash computation and returns the hash value
    ///
    /// This function finalizes the hash computation and returns the resulting hash value.
    /// After calling this function, the state should not be used anymore.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new hashing state
    /// let mut state = crypto_generichash::State::new(
    ///     None,                            // No key
    ///     crypto_generichash::BYTES,       // Default output length (32 bytes)
    /// ).expect("Failed to initialize hash state");
    ///
    /// // Update the state with data
    /// state.update(b"Hello, world!");
    ///
    /// // Finalize the hash computation
    /// let hash = state.finalize();
    /// ```
    ///
    /// ## Returns
    ///
    /// * `Vec<u8>` - The computed hash
    pub fn finalize(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.output_len];

        unsafe {
            libsodium_sys::crypto_generichash_final(
                &mut self.state,
                out.as_mut_ptr(),
                out.len() as libc::size_t,
            );
        }

        out
    }
}

/// Computes a BLAKE2b hash of the input data with an optional key
///
/// This function computes a BLAKE2b hash of the input data, optionally using a key
/// for keyed hashing (MAC). It provides a convenient one-shot interface for hashing
/// data that is already available in memory.
///
/// ## Algorithm Details
///
/// The generic hash function is currently implemented using BLAKE2b, a fast
/// cryptographic hash function built on the ChaCha stream cipher. BLAKE2b is
/// designed to be faster than MD5, SHA-1, SHA-2, and SHA-3, yet is at least
/// as secure as the latest standard SHA-3.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_generichash;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Simple hashing
/// let data = b"Hello, world!";
/// let hash = crypto_generichash::generichash(
///     data,
///     None,                            // No key
///     crypto_generichash::BYTES,       // Default output length (32 bytes)
/// );
///
/// // Keyed hashing (MAC)
/// let key = sodium::random::bytes(crypto_generichash::KEYBYTES); // 32-byte key
/// let keyed_hash = crypto_generichash::generichash(
///     data,
///     Some(&key),                      // With key
///     crypto_generichash::BYTES,       // Default output length
/// );
///
/// // Custom output length
/// let short_hash = crypto_generichash::generichash(
///     data,
///     None,                            // No key
///     crypto_generichash::BYTES_MIN,   // Minimum output length (16 bytes)
/// ).expect("Failed to generate hash");
/// assert_eq!(short_hash.len(), crypto_generichash::BYTES_MIN);
/// ```
///
/// ## Arguments
///
/// * `input` - Data to hash
/// * `key` - Optional key for keyed hashing (MAC). If provided, must be between
///   `KEYBYTES_MIN` (16) and `KEYBYTES_MAX` (64) bytes.
/// * `output_len` - Length of the output hash in bytes. Must be between
///   `BYTES_MIN` (16) and `BYTES_MAX` (64) bytes.
///
/// ## Returns
///
/// * `Result<Vec<u8>>` - The computed hash, or an error if parameters are invalid.
///
/// ## Behavior with Invalid Parameters
///
/// If invalid parameters are provided (output length or key length out of range),
/// the function will return an appropriate error.
pub fn generichash(input: &[u8], key: Option<&[u8]>, output_len: usize) -> Result<Vec<u8>> {
    // Validate output length
    if !(BYTES_MIN..=BYTES_MAX).contains(&output_len) {
        return Err(SodiumError::InvalidInput(format!(
            "Output length must be between {BYTES_MIN} and {BYTES_MAX}"
        )));
    }

    // Validate key length if provided
    if let Some(key) = key {
        if key.len() < KEYBYTES_MIN || key.len() > KEYBYTES_MAX {
            return Err(SodiumError::InvalidKey(format!(
                "Key length must be between {KEYBYTES_MIN} and {KEYBYTES_MAX}"
            )));
        }
    }

    // Create state and handle potential errors
    let mut state = State::new(key, output_len)?;
    state.update(input);
    Ok(state.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Encoder, Hex};

    #[test]
    fn test_generichash() {
        let data = b"test data";
        let hash = generichash(data, None, BYTES).unwrap();
        assert_eq!(
            {
                let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
                let encoded = Hex::encode(&mut encoded, &hash).unwrap();
                std::str::from_utf8(encoded).unwrap().to_string()
            },
            "eab94977a17791d0c089fe9e393261b3ab667cf0e8456632a842d905c468cf65"
        );
    }

    #[test]
    fn test_generichash_with_key() {
        let data = b"test data";
        let key = vec![0u8; KEYBYTES]; // Use a properly sized key
        let hash = generichash(data, Some(&key), BYTES).unwrap();
        assert_eq!(
            {
                let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
                let encoded = Hex::encode(&mut encoded, &hash).unwrap();
                std::str::from_utf8(encoded).unwrap().to_string()
            },
            "9e34d14a3d2082187f56b14df4e9aaf36b0562e0f842b5b323555192b0c08c22"
        );
    }

    #[test]
    fn test_generichash_incremental() {
        let mut state = State::new(None, BYTES).expect("Failed to create BLAKE2b state");
        state.update(b"test ");
        state.update(b"data");
        let hash = state.finalize();
        let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, &hash).unwrap();
        assert_eq!(
            std::str::from_utf8(encoded).unwrap(),
            "eab94977a17791d0c089fe9e393261b3ab667cf0e8456632a842d905c468cf65"
        );
    }

    #[test]
    fn test_invalid_output_length() {
        // Should return an error for invalid output length
        assert!(generichash(b"test", None, BYTES_MAX + 1).is_err());
        assert!(generichash(b"test", None, BYTES_MIN - 1).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let long_key = vec![0u8; KEYBYTES_MAX + 1];
        // Should return an error for invalid key length
        assert!(generichash(b"test", Some(&long_key), BYTES).is_err());
    }
}
