//! # BLAKE2b State for Incremental Hashing
//!
//! This module provides a state structure for computing BLAKE2b hashes incrementally.
//! This is useful when the entire message is not available at once, or when memory
//! usage needs to be minimized.
//!
//! ## Incremental Hashing
//!
//! Incremental hashing allows processing data in chunks rather than requiring the entire
//! message to be in memory at once. This is particularly useful for:
//!
//! - Processing large files that don't fit in memory
//! - Hashing streaming data (e.g., from a network socket)
//! - Minimizing memory usage in constrained environments
//! - Updating a hash as new data becomes available
//! - Implementing streaming protocols where data arrives in pieces
//!
//! ## How Incremental Hashing Works
//!
//! The incremental hashing process consists of three main steps:
//!
//! 1. **Initialization**: Create a new state with parameters like key, output length, salt, and personalization
//! 2. **Update**: Process data chunks sequentially, updating the internal state
//! 3. **Finalization**: Complete the hash computation and retrieve the final hash value
//!
//! The internal state maintains all necessary information between updates, including:
//! - The partially processed message
//! - Length counters
//! - Compression function state
//! - Initialization parameters (key, salt, personalization)
//!
//! ## BLAKE2b Features
//!
//! BLAKE2b is a cryptographic hash function that offers several advantages:
//!
//! - **Speed**: Faster than MD5, SHA-1, SHA-2, and SHA-3 on modern 64-bit platforms
//! - **Security**: Designed to be resistant to length extension attacks
//! - **Flexibility**: Supports variable output lengths from 1 to 64 bytes
//! - **Keyed hashing**: Can be used as a MAC (Message Authentication Code)
//! - **Customization**: Supports salt and personalization parameters
//! - **Parallel computation**: Can be efficiently parallelized (though not implemented in this API)
//!
//! ## Security Considerations
//!
//! - The incremental API provides the same security guarantees as the one-shot API
//! - The hash result is independent of how the data is chunked
//! - Once finalized, a state should not be reused for security reasons
//! - For keyed hashing (MAC), the key should be kept secret and have sufficient entropy

use super::core::*;
use crate::{Result, SodiumError};

/// BLAKE2b state for incremental hashing
///
/// This structure allows computing a BLAKE2b hash incrementally by updating the state
/// with chunks of data. This is useful when the entire message is not available at once,
/// or when memory usage needs to be minimized.
///
/// ## Memory Efficiency
///
/// The incremental API allows processing messages of any size without needing to
/// load the entire message into memory at once. This is particularly valuable for:
///
/// - Large files that exceed available memory
/// - Streaming data from a network or other source
/// - Memory-constrained environments like embedded systems
/// - Processing data that arrives in chunks over time
///
/// ## Security Properties
///
/// - The security properties of BLAKE2b are maintained when using the incremental API
/// - The same hash will be produced regardless of how the message is chunked
/// - The state contains internal padding and length tracking to ensure security
/// - Resistance to length extension attacks is preserved
/// - Collision resistance and preimage resistance are maintained
///
/// ## Typical Usage Pattern
///
/// 1. Create a new state with `State::new()` or `State::new_with_salt_and_personal()`
/// 2. Update the state with data chunks using `update()`
/// 3. Finalize and get the hash with `finalize()`
///
/// ## Performance Considerations
///
/// - There is a small overhead for maintaining the incremental state
/// - For very small messages, the one-shot API may be more efficient
/// - For large messages or streaming data, the incremental API is more efficient
/// - The chunk size does not significantly affect performance as long as it's reasonable
///
/// ## BLAKE2b state for incremental hashing
///
/// This struct represents the state of a BLAKE2b hash computation. It allows for
/// incremental hashing, where data can be processed in chunks rather than all at once.
/// This is useful for hashing large files or streaming data without loading everything
/// into memory.
///
/// ## Use Cases
///
/// - **Large files**: Hash files that are too large to fit in memory
/// - **Streaming data**: Hash data as it becomes available (e.g., network streams)
/// - **Append-only data**: Update a hash as new data is appended
/// - **Memory-constrained environments**: Process data without loading it all at once
pub struct State {
    state: libsodium_sys::crypto_generichash_blake2b_state,
    output_len: usize,
}

impl State {
    /// Creates a new BLAKE2b hashing state
    ///
    /// This function initializes a new BLAKE2b hashing state with the specified key and
    /// output length. The key is optional and can be used to create a MAC (Message
    /// Authentication Code) rather than a plain hash.
    ///
    /// ## Initialization Process
    ///
    /// When a new BLAKE2b state is created, the following happens:
    ///
    /// 1. The internal state is initialized with the BLAKE2b initialization vector (IV)
    /// 2. The state is modified based on the output length and key parameters
    /// 3. If a key is provided, it's processed as the first block with appropriate padding
    /// 4. The state is now ready to process message data via the `update()` method
    ///
    /// ## Security Properties
    ///
    /// - **Without a key**: The state produces a cryptographic hash function with the following properties:
    ///   - Collision resistance: Computationally infeasible to find two different inputs with the same hash
    ///   - Preimage resistance: Given a hash value, computationally infeasible to find an input that produces it
    ///   - Second preimage resistance: Given an input, computationally infeasible to find another input with the same hash
    ///   - Pseudorandomness: Output bits are indistinguishable from random when the input is unknown
    ///
    /// - **With a key**: The state produces a MAC (Message Authentication Code) with the following properties:
    ///   - All the properties of the hash function above
    ///   - Authentication: Only someone with the key can produce a valid MAC for a given message
    ///   - Forgery resistance: Computationally infeasible to forge a valid MAC without knowing the key
    ///
    /// - **Output length affects security level**:
    ///   - 32 bytes (256 bits): Suitable for most applications, provides ~128 bits of security
    ///   - 64 bytes (512 bits): Maximum security, provides ~256 bits of security
    ///   - Smaller outputs provide proportionally less security
    ///
    /// ## Arguments
    ///
    /// * `key` - Optional key for keyed hashing (MAC). If provided, must be at most
    ///   `KEYBYTES_MAX` (64) bytes long.
    /// * `output_len` - Length of the output hash in bytes. Must be between `BYTES_MIN` (1)
    ///   and `BYTES_MAX` (64) bytes.
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new BLAKE2b state or an error
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The output length is not between `BYTES_MIN` (1) and `BYTES_MAX` (64) bytes
    /// - The key length is greater than `KEYBYTES_MAX` (64) bytes
    /// - The state initialization fails
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash::blake2b::State;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new state with no key and 32-byte output
    /// let mut state = State::new(None, 32).expect("Failed to create state");
    ///
    /// // Update with data
    /// state.update(b"Hello, ");
    /// state.update(b"world!");
    ///
    /// // Finalize and get the hash
    /// let hash = state.finalize();
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn new(key: Option<&[u8]>, output_len: usize) -> Result<Self> {
        if !(BYTES_MIN..=BYTES_MAX).contains(&output_len) {
            return Err(SodiumError::InvalidInput(format!(
                "Output length must be between {BYTES_MIN} and {BYTES_MAX} bytes"
            )));
        }

        if let Some(key) = key {
            // KEYBYTES_MIN is 0, so we only need to check the upper bound
            if key.len() > KEYBYTES_MAX {
                return Err(SodiumError::InvalidInput(format!(
                    "Key length must be at most {KEYBYTES_MAX} bytes"
                )));
            }
        }

        let mut state = Self {
            state: unsafe { std::mem::zeroed() },
            output_len,
        };

        let result = match key {
            Some(key) => unsafe {
                libsodium_sys::crypto_generichash_blake2b_init(
                    &mut state.state,
                    key.as_ptr(),
                    key.len() as libc::size_t,
                    output_len as libc::size_t,
                )
            },
            None => unsafe {
                libsodium_sys::crypto_generichash_blake2b_init(
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

    /// Creates a new BLAKE2b hashing state with salt and personalization
    ///
    /// This function initializes a new BLAKE2b hashing state with optional salt and
    /// personalization parameters, in addition to the key and output length. These
    /// parameters allow creating domain-separated hash functions for different applications.
    ///
    /// ## Customization Parameters
    ///
    /// - **Salt**: An optional 16-byte value that can be used to derive different hash functions
    ///   from the same algorithm. Unlike the key, the salt is not secret and can be publicly known.
    ///   It's useful for creating different hash functions for different applications or contexts.
    ///   
    ///   Example uses for salt:
    ///   - Creating different hash variants for different protocols
    ///   - Adding randomness to hash functions without requiring secrecy
    ///   - Parameterizing hash functions for different environments (e.g., test vs. production)
    ///
    /// - **Personalization**: An optional 16-byte string that identifies a particular application
    ///   or use case. This provides domain separation between different uses of the same hash function.
    ///   For example, you might use different personalization strings for "file checksums" vs "password hashing".
    ///   
    ///   Example personalization strings:
    ///   - `"FILE_CHECKSUM_1"`
    ///   - `"PASSWORD_HASH2"`
    ///   - `"APP_ID_V1.2.3_"`
    ///   - `"EMAIL_VERIF_22"`
    ///
    /// ## Difference Between Salt and Personalization
    ///
    /// While both parameters customize the hash function, they serve different purposes:
    ///
    /// - **Salt** is typically more dynamic and can change between deployments or instances
    /// - **Personalization** is typically static and identifies a specific application or use case
    /// - Use salt when you want to create different hash instances of the same application
    /// - Use personalization when you want to separate different applications or contexts
    ///
    /// ## Security Benefits
    ///
    /// Using salt and personalization provides several security benefits:
    ///
    /// - **Domain separation**: Prevents hash values from one application being used in another
    /// - **Uniqueness**: Creates distinct hash functions for different purposes
    /// - **Isolation**: Ensures that a vulnerability in one usage context doesn't affect others
    /// - **Versioning**: Allows for algorithm updates while maintaining backward compatibility
    /// - **Multi-tenant isolation**: Ensures that data from different tenants produces different hashes
    /// - **Replay protection**: Prevents hash values from being reused in different contexts
    ///
    /// ## Arguments
    ///
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
    /// * `Result<Self>` - A new BLAKE2b state or an error
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The output length is not between `BYTES_MIN` (1) and `BYTES_MAX` (64) bytes
    /// - The key length is greater than `KEYBYTES_MAX` (64) bytes
    /// - The salt is provided and its length is not `SALTBYTES` (16) bytes
    /// - The personalization is provided and its length is not `PERSONALBYTES` (16) bytes
    /// - The state initialization fails
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash::blake2b::State;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new state with customization parameters
    /// let key = b"secret key";
    /// let salt = b"0123456789abcdef";       // Must be exactly 16 bytes
    /// let personal = b"my-app-v1.0.0000";  // Must be exactly 16 bytes
    ///
    /// let mut state = State::new_with_salt_and_personal(
    ///     Some(key),
    ///     32,  // 32-byte output
    ///     Some(salt),
    ///     Some(personal)
    /// ).expect("Failed to create state");
    ///
    /// // Use the state for incremental hashing
    /// state.update(b"Hello, world!");
    /// let hash = state.finalize();
    /// ```
    pub fn new_with_salt_and_personal(
        key: Option<&[u8]>,
        output_len: usize,
        salt: Option<&[u8]>,
        personal: Option<&[u8]>,
    ) -> Result<Self> {
        if !(BYTES_MIN..=BYTES_MAX).contains(&output_len) {
            return Err(SodiumError::InvalidInput(format!(
                "Output length must be between {BYTES_MIN} and {BYTES_MAX} bytes"
            )));
        }

        if let Some(key) = key {
            // KEYBYTES_MIN is 0, so we only need to check the upper bound
            if key.len() > KEYBYTES_MAX {
                return Err(SodiumError::InvalidInput(format!(
                    "Key length must be at most {KEYBYTES_MAX} bytes"
                )));
            }
        }

        // Only validate salt if it's provided (null salt is allowed)
        if let Some(salt) = salt {
            if salt.len() != SALTBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "Salt length must be exactly {SALTBYTES} bytes"
                )));
            }
        }

        // Only validate personalization if it's provided (null personalization is allowed)
        if let Some(personal) = personal {
            if personal.len() != PERSONALBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "Personalization length must be exactly {PERSONALBYTES} bytes"
                )));
            }
        }

        let mut state = Self {
            state: unsafe { std::mem::zeroed() },
            output_len,
        };

        let result = unsafe {
            libsodium_sys::crypto_generichash_blake2b_init_salt_personal(
                &mut state.state,
                key.map_or(std::ptr::null(), |k| k.as_ptr()),
                key.map_or(0, |k| k.len() as libc::size_t),
                output_len as libc::size_t,
                salt.map_or(std::ptr::null(), |s| s.as_ptr()),
                personal.map_or(std::ptr::null(), |p| p.as_ptr()),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "Failed to initialize BLAKE2b state with salt and personalization".to_string(),
            ));
        }

        Ok(state)
    }

    /// Updates the hashing state with additional data
    ///
    /// This function updates the BLAKE2b hashing state with additional input data.
    /// It can be called multiple times to process data incrementally, allowing you
    /// to hash data chunk by chunk without loading it all into memory at once.
    ///
    /// ## How Update Works
    ///
    /// When you call `update()`, the following happens internally:
    ///
    /// 1. The input data is processed in blocks of 128 bytes (BLAKE2b's block size)
    /// 2. For each complete block:
    ///    - The block is mixed into the internal state using the BLAKE2b compression function
    ///    - The message length counter is updated
    /// 3. Any remaining partial block is stored in an internal buffer for the next update
    ///    or finalization
    ///
    /// This design allows for efficient processing of data of any size, as the state
    /// maintains all necessary information between calls.
    ///
    /// ## Performance Considerations
    ///
    /// - For optimal performance, use larger chunks when possible (e.g., 4-8 KB)
    /// - There's no need to align chunks to any particular boundary
    /// - The internal state maintains all necessary information between updates
    /// - The chunk size doesn't affect the resulting hash value, only performance
    /// - Very small chunks (e.g., 1 byte at a time) will work correctly but may be inefficient
    ///
    /// ## Security Properties
    ///
    /// - The update operation maintains all security properties of BLAKE2b
    /// - The resulting hash is independent of how the data is chunked
    /// - The state properly tracks message length to prevent length extension attacks
    ///
    /// ## Arguments
    ///
    /// * `input` - The data chunk to add to the hash
    ///
    /// ## Returns
    ///
    /// This function does not return a value. It modifies the state in place.
    ///
    /// ## Error Handling
    ///
    /// This function performs internal error checking but does not return errors to the caller.
    /// If an internal error occurs (which should never happen with valid inputs and a properly
    /// initialized state), a debug assertion will fail in debug builds.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash::blake2b::State;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new state
    /// let mut state = State::new(None, 32).expect("Failed to create state");
    ///
    /// // Process data in chunks
    /// let data = [0u8; 1024]; // Example data
    /// let chunk_size = 256;
    ///
    /// for chunk in data.chunks(chunk_size) {
    ///     state.update(chunk);
    /// }
    ///
    /// // Finalize to get the hash
    /// let hash = state.finalize();
    /// ```
    pub fn update(&mut self, input: &[u8]) {
        let result = unsafe {
            libsodium_sys::crypto_generichash_blake2b_update(
                &mut self.state,
                input.as_ptr(),
                input.len() as libc::c_ulonglong,
            )
        };

        // This should never fail with valid inputs
        debug_assert_eq!(result, 0, "Failed to update BLAKE2b state");
    }

    /// Finalizes the hash computation and returns the hash
    ///
    /// This function finalizes the BLAKE2b hash computation and returns the resulting hash.
    /// It performs the final padding and processing required to complete the hash.
    /// After calling this function, the state should not be used again as it is consumed.
    ///
    /// ## Finalization Process
    ///
    /// The finalization process involves several steps:
    ///
    /// 1. **Length Incorporation**: The total length of the processed message is incorporated
    ///    into the hash computation, ensuring that different message lengths produce different hashes
    /// 2. **Final Padding**: Appropriate padding is applied to the message according to the BLAKE2b
    ///    specification to ensure security properties are maintained
    /// 3. **Final Compression**: The last block is processed through the compression function
    /// 4. **Output Extraction**: The hash value is extracted from the internal state
    ///
    /// ## Security Considerations
    ///
    /// The finalization step is critical for security. It ensures that:
    /// - The full message length is incorporated into the hash, preventing length extension attacks
    /// - Proper padding is applied according to the BLAKE2b specification
    /// - The hash is correctly extracted from the internal state
    /// - The security properties of BLAKE2b (collision resistance, preimage resistance) are maintained
    ///
    /// ## Important Usage Notes
    ///
    /// - Once finalized, the state should not be reused for security reasons
    /// - Attempting to update or finalize a state after it has been finalized may lead to
    ///   undefined behavior or security vulnerabilities
    /// - The output hash has the full security properties of BLAKE2b
    /// - The output length was determined when the state was created and cannot be changed
    /// - The finalize operation consumes the state internally, though Rust's ownership system
    ///   still allows access to the struct
    ///
    /// ## Returns
    ///
    /// * `Vec<u8>` - The computed hash of the length specified during initialization
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_generichash::blake2b::State;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new state and process data
    /// let mut state = State::new(None, 32).unwrap();
    /// state.update(b"Data to hash");
    ///
    /// // Finalize and get the hash
    /// let hash = state.finalize();
    /// assert_eq!(hash.len(), 32);
    ///
    /// // After finalization, the state should not be used again
    /// // The following would be incorrect usage:
    /// // state.update(b"More data"); // Don't do this!
    /// // let invalid_hash = state.finalize(); // Don't do this!
    /// ```
    pub fn finalize(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.output_len];

        let result = unsafe {
            libsodium_sys::crypto_generichash_blake2b_final(
                &mut self.state,
                out.as_mut_ptr(),
                out.len() as libc::size_t,
            )
        };

        // This should never fail with valid inputs
        debug_assert_eq!(result, 0, "Failed to finalize BLAKE2b hash");

        out
    }
}
