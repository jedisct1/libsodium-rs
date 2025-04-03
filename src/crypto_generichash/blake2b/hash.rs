//! # BLAKE2b One-Shot Hashing Functions
//!
//! This module provides functions for computing BLAKE2b hashes in a single call.
//! These functions are convenient when the entire message is available at once and
//! you don't need the incremental API provided by the `state` module.
//!
//! ## One-Shot vs. Incremental Hashing
//!
//! - **One-Shot Hashing**: Process the entire message in a single function call
//!   - Advantages: Simpler API, less code, potentially more efficient for small messages
//!   - Disadvantages: Requires the entire message to be in memory
//!
//! - **Incremental Hashing**: Process the message in chunks using the `State` API
//!   - Advantages: Memory-efficient for large messages, can process streaming data
//!   - Disadvantages: Slightly more complex API, requires managing state
//!
//! ## BLAKE2b Security Properties
//!
//! - **Collision resistance**: Computationally infeasible to find two different inputs with the same hash
//! - **Preimage resistance**: Given a hash value, computationally infeasible to find an input that produces it
//! - **Second preimage resistance**: Given an input, computationally infeasible to find another input with the same hash
//! - **Pseudorandomness**: Output bits are indistinguishable from random when the input is unknown
//! - **Length-extension resistance**: Unlike SHA-1/SHA-2, knowing H(m) doesn't allow computing H(m||m')
//!
//! BLAKE2b produces hash values
//! of any size between 1 and 64 bytes.
//!
//! BLAKE2b features:
//! - High speed on 64-bit platforms
//! - Security comparable to SHA-3
//! - Simpler design than SHA-2
//! - Optimized for modern CPUs
//! - Optional key for MAC computation
//! - Optional salt and personalization parameters
//! - Parallel and tree hashing modes
//!
//! For incremental hashing (processing data in chunks), use the `State` struct instead.

use super::state::State;

/// Computes a BLAKE2b hash of the input data
///
/// This function computes a BLAKE2b hash of the input data with the specified output length.
/// It provides a simple one-shot interface for hashing data that is already available in memory.
///
/// ## Security Properties
///
/// - **Cryptographic strength**: BLAKE2b provides up to 256 bits of security (with 64-byte output)
/// - **Collision resistance**: Finding two different inputs with the same hash is computationally infeasible
/// - **Preimage resistance**: Given a hash value, finding an input that produces it is computationally infeasible
/// - **Deterministic**: The same input always produces the same output
///
/// ## Performance
///
/// BLAKE2b is optimized for 64-bit platforms and is typically faster than SHA-1, SHA-2, and SHA-3
/// while providing stronger security guarantees.
///
/// ## Arguments
///
/// * `input` - The data to hash
/// * `output_len` - Length of the output hash in bytes. Must be between `BYTES_MIN` (1)
///   and `BYTES_MAX` (64) bytes.
///
/// ## Returns
///
/// * `Result<Vec<u8>>` - The computed hash or an error
///
/// ## Errors
///
/// Returns an error if the output length is not between `BYTES_MIN` (1) and `BYTES_MAX` (64) bytes
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_generichash::blake2b;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Compute a 32-byte hash
/// let data = b"Hello, world!";
/// let hash = blake2b::hash(data, 32);
///
/// assert_eq!(hash.len(), 32);
/// ```
pub fn hash(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut state = State::new(None, output_len).expect("Invalid parameters for BLAKE2b hash");
    state.update(input);
    state.finalize()
}

/// Computes a BLAKE2b hash of the input data with a key
///
/// This function computes a BLAKE2b hash of the input data using a key
/// for keyed hashing (MAC). It provides a convenient one-shot interface for hashing
/// data that is already available in memory.
///
/// ## Security Properties
///
/// - **Collision resistance**: Computationally infeasible to find two distinct inputs that
///   hash to the same output
/// - **Preimage resistance**: Given a hash value, it is computationally infeasible to find an
///   input that hashes to that value
/// - **Second preimage resistance**: Given an input, it is computationally infeasible to find
///   another input that hashes to the same value
/// - **Keyed mode**: When used with a key, BLAKE2b provides authentication (MAC functionality)
///
/// ## Use Cases
///
/// - **Data integrity verification**: Ensure data hasn't been altered
/// - **Password hashing**: Store password hashes securely (though specialized password
///   hashing functions like Argon2 are preferred)
/// - **Message authentication**: When used with a key
/// - **Checksums**: Verify file integrity
/// - **Pseudorandom number generation**: As part of a PRNG construction
///
/// ## Arguments
///
/// * `input` - Data to hash
/// * `key` - The key for keyed hashing (MAC). This turns the hash function
///   into a MAC (Message Authentication Code)
/// * `output_len` - Length of the output hash in bytes (between 1 and 64 bytes)
///
/// ## Returns
///
/// * `Result<Vec<u8>>` - The computed hash or an error
///
/// ## Errors
///
/// Returns an error if:
/// - The output length is not between `BYTES_MIN` (1) and `BYTES_MAX` (64) bytes
/// - The key length is not between `KEYBYTES_MIN` (0) and `KEYBYTES_MAX` (64) bytes
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_generichash::blake2b;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Simple hashing without a key
/// let data = b"Hello, world!";
/// let key2 = b"secret key";
/// let mac2 = blake2b::hash_with_key(data, key2, 32);
/// assert_eq!(mac2.len(), 32);
///
/// // Keyed hashing (MAC)
/// let key = b"secret key";
/// let mac = blake2b::hash_with_key(data, key, 32);
/// assert_eq!(mac.len(), 32);
/// ```
pub fn hash_with_key(input: &[u8], key: &[u8], output_len: usize) -> Vec<u8> {
    let mut state = State::new(Some(key), output_len).expect("Invalid parameters for BLAKE2b hash");
    state.update(input);
    state.finalize()
}

/// Computes a BLAKE2b hash with salt and personalization
///
/// This function computes a BLAKE2b hash with optional key, salt, and personalization
/// parameters. These parameters allow customizing the hash function for different applications
/// and creating domain separation between different uses of the same hash function.
///
/// ## Customization Parameters
///
/// - **Salt**: An optional 16-byte value that can be used to derive different hash functions
///   from the same algorithm. Unlike the key, the salt is not secret and can be publicly known.
///   It's useful for creating different hash functions for different applications or contexts.
///
/// - **Personalization**: An optional 16-byte string that identifies a particular application
///   or use case. This provides domain separation between different uses of the same hash function.
///   For example, you might use different personalization strings for "file checksums" vs "password hashing".
///
/// ## Security Benefits
///
/// Using salt and personalization provides several security benefits:
///
/// - **Domain separation**: Prevents hash values from one application being used in another
/// - **Uniqueness**: Creates distinct hash functions for different purposes
/// - **Isolation**: Ensures that a vulnerability in one usage context doesn't affect others
/// - **Versioning**: Allows for algorithm updates while maintaining backward compatibility
///
/// ## Arguments
///
/// * `input` - The data to hash
/// * `key` - Optional key for keyed hashing (MAC). If provided, must be at most
///   `KEYBYTES_MAX` (64) bytes long.
/// * `output_len` - Length of the output hash in bytes. Must be between `BYTES_MIN` (1)
///   and `BYTES_MAX` (64) bytes.
/// * `salt` - Optional salt for customizing the hash. If provided, must be exactly
///   `SALTBYTES` (16) bytes long.
/// * `personal` - Optional personalization string for customizing the hash. If provided,
///   must be exactly `PERSONALBYTES` (16) bytes long.
///
/// ## Returns
///
/// * `Result<Vec<u8>>` - The computed hash or an error
///
/// ## Errors
///
/// Returns an error if:
/// - The output length is not between `BYTES_MIN` (1) and `BYTES_MAX` (64) bytes
/// - The key length is greater than `KEYBYTES_MAX` (64) bytes
/// - The salt is provided and its length is not `SALTBYTES` (16) bytes
/// - The personalization is provided and its length is not `PERSONALBYTES` (16) bytes
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_generichash::blake2b;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Data to hash
/// let data = b"Hello, world!";
///
/// // Optional parameters
/// let key = b"secret key";
/// let salt = b"0123456789abcdef";       // Must be exactly 16 bytes
/// let personal = b"my-app-v1.0.0000";  // Must be exactly 16 bytes
///
/// // Compute hash with all parameters
/// let hash = blake2b::hash_with_salt_and_personal(
///     data,
///     Some(key),
///     32,  // 32-byte output
///     Some(salt),
///     Some(personal)
/// ).expect("Failed to compute hash");
///
/// assert_eq!(hash.len(), 32);
///
/// // Different personalization produces different hash for same input
/// let personal2 = b"my-app-v2.0.0000";  // Must be exactly 16 bytes
/// let hash2 = blake2b::hash_with_salt_and_personal(
///     data,
///     Some(key),
///     32,
///     Some(salt),
///     Some(personal2)
/// ).expect("Failed to compute hash");
///
/// // The hashes should be different despite same input and key
/// assert_ne!(hash, hash2);
/// ```
pub fn hash_with_salt_and_personal(
    input: &[u8],
    key: Option<&[u8]>,
    output_len: usize,
    salt: Option<&[u8]>,
    personal: Option<&[u8]>,
) -> Result<Vec<u8>, crate::SodiumError> {
    let mut state = State::new_with_salt_and_personal(key, output_len, salt, personal)?;
    state.update(input);
    Ok(state.finalize())
}
