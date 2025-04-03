//! # SHA-512 Cryptographic Hash Function
//!
//! This module provides access to the SHA-512 hash function with support for incremental hashing.
//!
//! ## Important Notes
//!
//! - This function is provided primarily for interoperability with other applications.
//! - For general purpose hashing, consider using `crypto_generichash` (BLAKE2b) instead.
//! - SHA-512 is vulnerable to length extension attacks.
//! - This module provides both one-shot and incremental hashing interfaces.
//!
//! ## Usage Example
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_hash::sha512;
//! use sodium::ensure_init;
//! use ct_codecs::{Encoder, Hex};
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // One-shot hashing
//! let data = b"The quick brown fox jumps over the lazy dog";
//! let hash = sha512::hash(data);
//!
//! // Convert to hex for display
//! let mut encoded = vec![0u8; hash.len() * 2];
//! let encoded = Hex::encode(&mut encoded, &hash).unwrap();
//! let hash_hex = std::str::from_utf8(encoded).unwrap();
//!
//! println!("SHA-512: {}", hash_hex);
//!
//! // Incremental hashing
//! let mut state = sha512::State::new();
//! state.update(b"The quick brown ");
//! state.update(b"fox jumps over the lazy dog");
//! let hash2 = state.finalize();
//! assert_eq!(hash, hash2);
//! ```

// No need for Result import since hash functions can't fail

/// Number of bytes in a SHA-512 hash output (64 bytes, 512 bits)
pub const BYTES: usize = libsodium_sys::crypto_hash_sha512_BYTES as usize;

/// SHA-512 state for incremental hashing
///
/// This struct represents the state of a SHA-512 hash computation. It is used for
/// incremental hashing, where data is processed in chunks rather than all at once.
/// This is useful for hashing large files or streams of data.
pub struct State {
    state: libsodium_sys::crypto_hash_sha512_state,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// Creates a new SHA-512 hashing state
    ///
    /// This function initializes a new SHA-512 hashing state for incremental hashing.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_hash::sha512;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new hashing state
    /// let mut state = sha512::State::new();
    ///
    /// // Update the state with data
    /// state.update(b"Hello, world!");
    ///
    /// // Finalize the hash computation
    /// let hash = state.finalize();
    /// ```
    ///
    /// # Returns
    ///
    /// * `Self` - A new SHA-512 hashing state
    pub fn new() -> Self {
        let mut state = Self {
            state: unsafe { std::mem::zeroed() },
        };

        // This operation cannot fail in libsodium
        unsafe {
            libsodium_sys::crypto_hash_sha512_init(&mut state.state);
        }

        state
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
    /// use sodium::crypto_hash::sha512;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new hashing state
    /// let mut state = sha512::State::new();
    ///
    /// // Update the state with data in chunks
    /// state.update(b"Hello, ");
    /// state.update(b"world!");
    ///
    /// // Finalize the hash computation
    /// let hash = state.finalize();
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `input` - Data to add to the hash computation
    ///
    /// # Returns
    ///
    /// * `()` - This operation always succeeds
    pub fn update(&mut self, input: &[u8]) {
        // This operation cannot fail in libsodium
        unsafe {
            libsodium_sys::crypto_hash_sha512_update(
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
    /// use sodium::crypto_hash::sha512;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new hashing state
    /// let mut state = sha512::State::new();
    ///
    /// // Update the state with data
    /// state.update(b"Hello, world!");
    ///
    /// // Finalize the hash computation
    /// let hash = state.finalize();
    /// ```
    ///
    /// # Returns
    ///
    /// * `[u8; BYTES]` - The computed hash
    pub fn finalize(&mut self) -> [u8; BYTES] {
        let mut hash = [0u8; BYTES];

        // This operation cannot fail in libsodium
        unsafe {
            libsodium_sys::crypto_hash_sha512_final(&mut self.state, hash.as_mut_ptr());
        }

        hash
    }
}

/// Computes a SHA-512 hash of the input data
///
/// This function computes a SHA-512 hash of the input data in a single pass.
/// It is a convenience wrapper around the incremental hashing API.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_hash::sha512;
/// use sodium::ensure_init;
/// use ct_codecs::{Encoder, Hex};
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Data to hash
/// let data = b"Hello, world!";
///
/// // Compute hash
/// let hash = sha512::hash(data);
///
/// // Convert to hex for display
/// let mut encoded = vec![0u8; hash.len() * 2];
/// let encoded = Hex::encode(&mut encoded, &hash).unwrap();
/// let hash_hex = std::str::from_utf8(encoded).unwrap();
///
/// println!("SHA-512: {}", hash_hex);
/// ```
///
/// ## Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// * `[u8; BYTES]` - The SHA-512 hash of the input data (64 bytes)
pub fn hash(data: &[u8]) -> [u8; BYTES] {
    let mut state = State::new();
    state.update(data);
    state.finalize()
}

/// Returns the size of the `crypto_hash_sha512_state` struct in bytes
///
/// This function is primarily used for FFI bindings to other languages.
pub fn statebytes() -> usize {
    unsafe { libsodium_sys::crypto_hash_sha512_statebytes() }
}

/// Returns the size of the SHA-512 hash output in bytes
///
/// This function returns the size of the SHA-512 hash output in bytes,
/// which is always 64 bytes (512 bits).
pub fn bytes() -> usize {
    unsafe { libsodium_sys::crypto_hash_sha512_bytes() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Encoder, Hex};

    #[test]
    fn test_hash() {
        let data = b"test data";
        let hash = hash(data);

        // Convert hash to hex string for comparison
        let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, hash).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d"
        );
    }

    #[test]
    fn test_incremental_hash() {
        let mut state = State::new();
        state.update(b"test ");
        state.update(b"data");
        let result = state.finalize();

        // Convert hash to hex string for comparison
        let mut encoded = vec![0u8; result.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, result).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d"
        );

        // Compare with one-shot hash
        let one_shot_hash = crate::crypto_hash::hash_sha512(b"test data");
        assert_eq!(result, one_shot_hash);
    }

    #[test]
    fn test_statebytes() {
        assert_eq!(
            statebytes(),
            std::mem::size_of::<libsodium_sys::crypto_hash_sha512_state>()
        );
    }

    #[test]
    fn test_bytes() {
        assert_eq!(bytes(), BYTES);
    }
}
