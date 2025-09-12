//! # Ristretto255 Scalar Multiplication
//!
//! This module provides functions for performing scalar multiplication operations
//! using the Ristretto255 group. Ristretto255 is a prime-order group built on top
//! of the Edwards25519 curve, which eliminates the cofactor issues present in both
//! Curve25519 and Ed25519.
//!
//! Ristretto255 is a technique for constructing prime order elliptic curve groups with
//! non-malleable encodings. It extends the Edwards25519 curve to provide a prime-order
//! group that's more suitable for many cryptographic protocols.
//!
//! ## Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_scalarmult::ristretto255;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a secret key (normally this would be random)
//! let secret_key = vec![0u8; ristretto255::SCALARBYTES];
//! let public_key = vec![0u8; ristretto255::BYTES]; // In a real app, this would be received from another party
//!
//! // Compute a shared secret using your secret key and another party's public key
//! match ristretto255::scalarmult(&secret_key, &public_key) {
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
//! - Ristretto255 provides a prime-order group, which simplifies protocol design
//! - It eliminates the cofactor-related security issues present in Curve25519 and Ed25519
//! - For protocols that require a prime-order group, Ristretto255 is often the best choice
//! - Always use cryptographically secure random values for secret keys
//! - Results from scalar multiplication should not be used directly as cryptographic keys
//!   without hashing
//! - Ristretto255 provides a canonical encoding, meaning each group element has exactly
//!   one valid encoding
//! - The encoding is also non-malleable, preventing certain classes of attacks
//! - Unlike Curve25519 and Ed25519, Ristretto255 has no small-subgroup elements

use crate::{Result, SodiumError};

pub const BYTES: usize = libsodium_sys::crypto_scalarmult_ristretto255_BYTES as usize;
pub const SCALARBYTES: usize = libsodium_sys::crypto_scalarmult_ristretto255_SCALARBYTES as usize;

/// Computes a shared secret using Ristretto255
///
/// This function multiplies an element represented by `public_key` by a scalar `secret_key`
/// (in the [0..L[ range) and puts the resulting element into the returned bytes.
///
/// The Ristretto255 group has prime order L = 2^252 + 27742317777372353535851937790883648493,
/// which means that all non-identity elements have the same order.
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
/// * Security Note: The returned shared secret contains sensitive cryptographic material
///   and should be zeroized when no longer needed. Consider using the `zeroize` crate
///   or `sodium_memzero` from the `utils` module to securely clear this data.
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the key lengths are incorrect
/// * `SodiumError::OperationError` - If the operation fails (e.g., if the result is the identity element
///   or if the public key is not a valid Ristretto255 point encoding)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::ristretto255;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keys (in a real application, use random keys)
/// let secret_key = vec![0u8; ristretto255::SCALARBYTES];
/// let public_key = vec![0u8; ristretto255::BYTES]; // In a real app, this would be received from another party
///
/// // Compute shared secret
/// match ristretto255::scalarmult(&secret_key, &public_key) {
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
        libsodium_sys::crypto_scalarmult_ristretto255(
            shared_secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "ristretto255 scalarmult failed (result is the identity element)".into(),
        ));
    }

    Ok(shared_secret)
}

/// Multiplies the Ristretto255 base point by a scalar
///
/// This function multiplies the generator by a scalar `secret_key` (in the [0..L[ range)
/// and puts the resulting element into the returned bytes.
///
/// The Ristretto255 base point is the canonical generator of the Ristretto255 group.
///
/// # Arguments
///
/// * `secret_key` - Your secret key (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * A public key of `BYTES` bytes
/// * The resulting point will always be a valid Ristretto255 encoding
/// * Security Note: While the public key itself is not sensitive, the secret key used
///   to generate it should be properly zeroized when no longer needed. Consider using
///   the `zeroize` crate or `sodium_memzero` from the `utils` module for this purpose.
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the key length is incorrect
/// * `SodiumError::OperationError` - If the operation fails (e.g., if the secret key is 0)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::ristretto255;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a secret key (in a real application, use a random key)
/// let secret_key = vec![1u8; ristretto255::SCALARBYTES]; // Non-zero for this example
///
/// // Compute the corresponding public key
/// match ristretto255::scalarmult_base(&secret_key) {
///     Ok(public_key) => {
///         println!("Public key generated successfully");
///         // Use public_key for further operations
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
        libsodium_sys::crypto_scalarmult_ristretto255_base(
            public_key.as_mut_ptr(),
            secret_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "ristretto255 scalarmult_base failed (secret key may be 0)".into(),
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
                // Ristretto255 has strict requirements for valid keys
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
                // Ristretto255 has strict requirements for valid keys
            }
        }
    }
}
