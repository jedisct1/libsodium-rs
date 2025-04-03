//! # BLAKE2b Cryptographic Hash Function
//!
//! This module provides access to the BLAKE2b hash function with support for incremental hashing.
//!
//! ## Features
//!
//! - **Variable output length**: Can produce hashes of any size between `BYTES_MIN` (16) and `BYTES_MAX` (64) bytes
//! - **Keyed hashing**: Supports keyed hashing (MAC) with keys of variable length
//! - **High performance**: Optimized for modern CPUs, faster than SHA-2 and SHA-3
//! - **Incremental hashing**: Supports incremental hashing for processing large data streams
//!
//! ## Usage Example
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_generichash::blake2b;
//! use sodium::ensure_init;
//! use ct_codecs::{Encoder, Hex};
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // One-shot hashing
//! let data = b"The quick brown fox jumps over the lazy dog";
//! let hash = blake2b::hash(
//!     data,
//!     blake2b::BYTES,                 // Default output length (32 bytes)
//! );
//!
//! // Convert to hex for display
//! let mut encoded = vec![0u8; hash.len() * 2];
//! let encoded = Hex::encode(&mut encoded, &hash).unwrap();
//! let hash_hex = std::str::from_utf8(encoded).unwrap();
//!
//! println!("BLAKE2b: {}", hash_hex);
//!
//! // Incremental hashing
//! let mut state = blake2b::State::new(
//!     None,                           // No key
//!     blake2b::BYTES,                 // Default output length (32 bytes)
//! ).expect("Failed to initialize BLAKE2b state");
//! state.update(b"The quick brown ");
//! state.update(b"fox jumps over the lazy dog");
//! let hash2 = state.finalize();
//! assert_eq!(hash, hash2);
//! ```

// Re-export the core module contents
mod core;
pub use core::*;

// Export the State implementation
mod state;
pub use state::State;

// Export the one-shot hashing functions
mod hash;
pub use hash::{hash, hash_with_key, hash_with_salt_and_personal};

// Export utility functions
mod utils;
pub use utils::{keybytes, personalbytes, saltbytes, statebytes};

// Include tests
#[cfg(test)]
mod tests;
