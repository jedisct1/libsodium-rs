//! # SHA3-256 Cryptographic Hash Function
//!
//! This module provides access to the SHA3-256 hash function with support for incremental hashing.
//!
//! ## Important Notes
//!
//! - This function is provided primarily for interoperability with other applications.
//! - For general purpose hashing, consider using `crypto_generichash` (BLAKE2b) instead.
//! - SHA3-256 does not have the length extension weakness of Merkle-Damgard hashes.
//! - This module provides both one-shot and incremental hashing interfaces.
//!
//! ## Usage Example
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_hash::sha3256;
//! use sodium::ensure_init;
//! use ct_codecs::{Encoder, Hex};
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // One-shot hashing
//! let data = b"The quick brown fox jumps over the lazy dog";
//! let hash = sha3256::hash(data);
//!
//! // Convert to hex for display
//! let mut encoded = vec![0u8; hash.len() * 2];
//! let encoded = Hex::encode(&mut encoded, &hash).unwrap();
//! let hash_hex = std::str::from_utf8(encoded).unwrap();
//!
//! println!("SHA3-256: {}", hash_hex);
//!
//! // Incremental hashing
//! let mut state = sha3256::State::new();
//! state.update(b"The quick brown ");
//! state.update(b"fox jumps over the lazy dog");
//! let hash2 = state.finalize();
//! assert_eq!(hash, hash2);
//! ```

/// Number of bytes in a SHA3-256 hash output (32 bytes, 256 bits)
pub const BYTES: usize = libsodium_sys::crypto_hash_sha3256_BYTES as usize;

/// SHA3-256 state for incremental hashing.
pub struct State {
    state: libsodium_sys::crypto_hash_sha3256_state,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// Creates a new SHA3-256 hashing state.
    pub fn new() -> Self {
        let mut state = std::mem::MaybeUninit::uninit();
        let state_ptr = state.as_mut_ptr();

        unsafe {
            libsodium_sys::crypto_hash_sha3256_init(state_ptr);
            Self {
                state: state.assume_init(),
            }
        }
    }

    /// Updates the hash state with additional input data.
    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            libsodium_sys::crypto_hash_sha3256_update(
                &mut self.state,
                input.as_ptr(),
                input.len() as u64,
            );
        }
    }

    /// Finalizes the hash computation and returns the hash value.
    pub fn finalize(&mut self) -> [u8; BYTES] {
        let mut hash = [0u8; BYTES];

        unsafe {
            libsodium_sys::crypto_hash_sha3256_final(&mut self.state, hash.as_mut_ptr());
        }

        hash
    }
}

/// Computes a SHA3-256 hash of the input data.
pub fn hash(data: &[u8]) -> [u8; BYTES] {
    let mut state = State::new();
    state.update(data);
    state.finalize()
}

/// Returns the size of the `crypto_hash_sha3256_state` struct in bytes.
pub fn statebytes() -> usize {
    unsafe { libsodium_sys::crypto_hash_sha3256_statebytes() }
}

/// Returns the size of the SHA3-256 hash output in bytes.
pub fn bytes() -> usize {
    unsafe { libsodium_sys::crypto_hash_sha3256_bytes() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Encoder, Hex};

    #[test]
    fn test_hash() {
        let data = b"test data";
        let hash = hash(data);

        let mut encoded = vec![0u8; hash.len() * 2];
        let encoded = Hex::encode(&mut encoded, hash).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "fc88e0ac33ff105e376f4ece95fb06925d5ab20080dbe3aede7dd47e45dfd931"
        );
    }

    #[test]
    fn test_incremental_hash() {
        let mut state = State::new();
        state.update(b"test ");
        state.update(b"data");
        let result = state.finalize();

        let mut encoded = vec![0u8; result.len() * 2];
        let encoded = Hex::encode(&mut encoded, result).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "fc88e0ac33ff105e376f4ece95fb06925d5ab20080dbe3aede7dd47e45dfd931"
        );
        assert_eq!(result, crate::crypto_hash::hash_sha3256(b"test data"));
    }

    #[test]
    fn test_statebytes() {
        assert_eq!(
            statebytes(),
            std::mem::size_of::<libsodium_sys::crypto_hash_sha3256_state>()
        );
    }

    #[test]
    fn test_bytes() {
        assert_eq!(bytes(), BYTES);
    }
}
