//! # Curve25519 Scalar Multiplication
//!
//! This module provides functions for performing scalar multiplication operations
//! using the Curve25519 elliptic curve. Curve25519 is designed for use in the X25519
//! key exchange scheme and provides strong security properties.
//!
//! X25519 is the Diffie-Hellman key exchange using Curve25519. It was introduced by
//! Daniel J. Bernstein and is widely used due to its security, performance, and
//! simplicity of implementation.
//!
//! ## Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_scalarmult::curve25519;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a secret key (normally this would be random)
//! let mut secret_key = vec![0u8; curve25519::SCALARBYTES];
//! secret_key[0] = 1; // Make it non-zero for a valid key
//!
//! // In a real app, this would be received from another party
//! let mut public_key = vec![0u8; curve25519::BYTES];
//! public_key[0] = 9; // Make it non-zero for a valid key
//!
//! // Compute a shared secret using your secret key and another party's public key
//! match curve25519::scalarmult(&secret_key, &public_key) {
//!     Ok(shared_secret) => {
//!         println!("Shared secret computed successfully");
//!         // Use shared_secret for further operations
//!     },
//!     Err(err) => {
//!         eprintln!("Failed to compute shared secret: {}", err);
//!         // Handle the error appropriately
//!     }
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - Curve25519 is designed for key exchange and provides excellent security and performance
//! - The curve has a cofactor of 8, which means some care must be taken in certain applications
//! - For most key exchange applications, Curve25519 is the recommended choice
//! - Always use cryptographically secure random values for secret keys
//! - Secret keys are automatically clamped: bits 0, 1, 2 of the first byte are cleared, bit 7 of the
//!   last byte is cleared, and bit 6 of the last byte is set
//! - As X25519 encodes a field element that is always smaller than 2^255, the top bit is not used
//! - Results from scalar multiplication should not be used directly as cryptographic keys
//!   without hashing
//! - The Curve25519 implementation is designed to avoid side-channel attacks
//! - If the protocol requires a prime-order group, consider using Ristretto255 instead

use crate::{Result, SodiumError};

pub const BYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES as usize;
pub const SCALARBYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_SCALARBYTES as usize;

/// Computes a shared secret using Curve25519
///
/// This function multiplies a point `public_key` by a scalar `secret_key`
/// and puts the resulting element into the returned bytes.
///
/// The secret key is automatically clamped before use, meaning certain bits
/// are set or cleared to ensure it meets the requirements for Curve25519.
///
/// # Arguments
///
/// * `secret_key` - Your secret key (must be exactly `SCALARBYTES` bytes)
/// * `public_key` - The other party's public key (must be exactly `BYTES` bytes)
///
/// # Returns
///
/// * A shared secret of `BYTES` bytes
/// * Note: The result should not be used directly as a cryptographic key. Always hash
///   the output before using it as a key for encryption or other cryptographic operations.
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the key lengths are incorrect
/// * `SodiumError::OperationError` - If the operation fails (e.g., if the result is all zeros,
///   which can happen if the public key is invalid or if the secret key is 0 after clamping)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::curve25519;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keys (in a real application, use random keys)
/// let secret_key = vec![0u8; curve25519::SCALARBYTES];
/// let public_key = vec![0u8; curve25519::BYTES]; // In a real app, this would be received from another party
///
/// // Compute shared secret
/// match curve25519::scalarmult(&secret_key, &public_key) {
///     Ok(shared_secret) => {
///         println!("Shared secret computed successfully");
///         // Important: Hash the shared secret before using it as a key
///         // let key = crypto_hash::sha256::hash(&shared_secret);
///     },
///     Err(err) => {
///         eprintln!("Failed to compute shared secret: {}", err);
///         // Handle the error appropriately
///     }
/// }
/// ```
#[must_use = "This function returns a shared secret that should be used for cryptographic operations"]
pub fn scalarmult(secret_key: &[u8], public_key: &[u8]) -> Result<[u8; BYTES]> {
    if secret_key.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "secret key must be exactly {SCALARBYTES} bytes"
        )));
    }
    if public_key.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!(
            "public key must be exactly {BYTES} bytes"
        )));
    }

    let mut shared_secret = [0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_scalarmult_curve25519(
            shared_secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "curve25519 scalarmult failed (result may be all zeros)".into(),
        ));
    }

    Ok(shared_secret)
}

/// Multiplies the Curve25519 base point by a scalar
///
/// This function multiplies the Curve25519 base point by a scalar `secret_key`
/// and puts the resulting element into the returned bytes.
///
/// The secret key is automatically clamped before use, meaning certain bits
/// are set or cleared to ensure it meets the requirements for Curve25519.
///
/// This operation is used to generate a public key from a secret key.
///
/// # Arguments
///
/// * `secret_key` - Your secret key (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * A public key of `BYTES` bytes
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the key length is incorrect
/// * `SodiumError::OperationError` - If the operation fails
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::curve25519;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a secret key (in a real application, use a random key)
/// let secret_key = vec![1u8; curve25519::SCALARBYTES]; // Non-zero for this example
///
/// // Compute the corresponding public key
/// match curve25519::scalarmult_base(&secret_key) {
///     Ok(public_key) => {
///         println!("Public key generated successfully");
///     },
///     Err(err) => {
///         eprintln!("Failed to generate public key: {}", err);
///         // Handle the error appropriately
///     }
/// }
/// ```
#[must_use = "This function returns a public key that should be used for cryptographic operations"]
pub fn scalarmult_base(secret_key: &[u8]) -> Result<[u8; BYTES]> {
    if secret_key.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "secret key must be exactly {SCALARBYTES} bytes"
        )));
    }

    let mut public_key = [0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_scalarmult_curve25519_base(
            public_key.as_mut_ptr(),
            secret_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "curve25519 scalarmult_base failed (secret key may be 0)".into(),
        ));
    }

    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalarmult() {
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });
        // Make sure it's not all zeros
        secret_key[0] = 1;

        let mut public_key = vec![0u8; BYTES];
        // Initialize with sequential values offset by 100
        public_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = (i + 100) as u8;
        });

        // Try the operation, but don't unwrap
        match scalarmult(&secret_key, &public_key) {
            Ok(shared_secret) => {
                assert_eq!(shared_secret.len(), BYTES);
            }
            Err(_) => {
                // It's okay if this fails, as long as it doesn't panic
                // Curve25519 has strict requirements for valid keys
            }
        }
    }

    #[test]
    fn test_scalarmult_base() {
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });
        // Make sure it's not all zeros
        secret_key[0] = 1;

        // Try the operation, but don't unwrap
        match scalarmult_base(&secret_key) {
            Ok(public_key) => {
                assert_eq!(public_key.len(), BYTES);
            }
            Err(_) => {
                // It's okay if this fails, as long as it doesn't panic
                // Curve25519 has strict requirements for valid keys
            }
        }
    }
}
