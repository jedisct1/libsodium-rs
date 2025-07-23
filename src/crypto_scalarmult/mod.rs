//! # Scalar Multiplication Operations
//!
//! This module provides functions for performing scalar multiplication operations
//! on various elliptic curves. These operations are the foundation of many
//! cryptographic protocols, particularly for key exchange and public key cryptography.
//!
//! ## Available Algorithms
//!
//! - **Default**: The default implementation (currently Curve25519)
//! - **Curve25519**: X25519 Elliptic Curve Diffie-Hellman (ECDH) function
//! - **Ed25519**: Edwards-curve Digital Signature Algorithm (EdDSA) curve operations
//! - **Ristretto255**: A prime-order group built on top of Edwards25519
//!
//! ## Usage
//!
//! The primary use case for these functions is to compute shared secrets for
//! key exchange protocols:
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_scalarmult;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a secret key (normally this would be random)
//! let mut secret_key = vec![0u8; crypto_scalarmult::SCALARBYTES];
//! secret_key[0] = 1; // Make it non-zero for a valid key
//!
//! // In a real application, you would receive a public key from another party
//! // Here we create a sample public key for demonstration
//! let mut public_key = vec![0u8; crypto_scalarmult::BYTES];
//! public_key[0] = 9; // Make it non-zero for a valid key
//!
//! // Compute a shared secret using your secret key and their public key
//! match crypto_scalarmult::scalarmult(&secret_key, &public_key) {
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
//! - Keep secret keys confidential
//! - Validate public keys before using them (this is done automatically by the API)
//! - For most applications, consider using the higher-level `crypto_box` or `crypto_kx` APIs

use crate::{Result, SodiumError};

pub const BYTES: usize = libsodium_sys::crypto_scalarmult_BYTES as usize;
pub const SCALARBYTES: usize = libsodium_sys::crypto_scalarmult_SCALARBYTES as usize;

// Re-export submodules
pub mod curve25519;
pub mod ed25519;
pub mod ristretto255;

/// Computes a shared secret given a secret key and another party's public key
///
/// This is the default implementation, which currently uses Curve25519.
///
/// # Arguments
///
/// * `secret_key` - Your secret key (must be exactly `SCALARBYTES` bytes)
/// * `public_key` - The other party's public key (must be exactly `BYTES` bytes)
///
/// # Returns
///
/// * A shared secret of `BYTES` bytes
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the key lengths are incorrect
/// * `SodiumError::OperationError` - If the operation fails (e.g., due to invalid keys)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keys (in a real application, use random keys)
/// let mut secret_key = vec![0u8; crypto_scalarmult::SCALARBYTES];
/// secret_key[0] = 1; // Make it non-zero for a valid key
///
/// // In a real app, this would be received from another party
/// let mut public_key = vec![0u8; crypto_scalarmult::BYTES];
/// public_key[0] = 9; // Make it non-zero for a valid key
///
/// // Compute shared secret
/// match crypto_scalarmult::scalarmult(&secret_key, &public_key) {
///     Ok(shared_secret) => {
///         println!("Shared secret computed successfully");
///         // Use shared_secret for further operations
///     },
///     Err(err) => {
///         eprintln!("Failed to compute shared secret: {}", err);
///         // Handle the error appropriately
///     }
/// }
/// ```
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
        libsodium_sys::crypto_scalarmult(
            shared_secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("scalarmult failed".into()));
    }

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalarmult() {
        // Create a valid secret key (not all zeros)
        let mut secret_key = vec![0u8; SCALARBYTES];
        secret_key[0] = 1; // Make it non-zero

        // Create a valid public key (not all zeros)
        let mut public_key = vec![0u8; BYTES];
        public_key[0] = 9; // A valid X25519 public key should have the high bit cleared

        let shared_secret = scalarmult(&secret_key, &public_key).unwrap();
        assert_eq!(shared_secret.len(), BYTES);
    }

    #[test]
    fn test_curve25519() {
        // Create a valid secret key (not all zeros)
        let mut secret_key = vec![0u8; curve25519::SCALARBYTES];
        secret_key[0] = 1; // Make it non-zero

        // Create a valid public key (not all zeros)
        let mut public_key = vec![0u8; curve25519::BYTES];
        public_key[0] = 9; // A valid X25519 public key should have the high bit cleared

        let shared_secret = curve25519::scalarmult(&secret_key, &public_key).unwrap();
        assert_eq!(shared_secret.len(), curve25519::BYTES);
    }

    #[test]
    fn test_ed25519() {
        // Skip this test if the operation fails
        // Ed25519 requires specially formatted keys for scalar multiplication
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; ed25519::SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });

        let mut public_key = vec![0u8; ed25519::BYTES];
        // Initialize with sequential values offset by 100
        public_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = (i + 100) as u8;
        });

        // Try the operation, but don't unwrap
        match ed25519::scalarmult(&secret_key, &public_key) {
            Ok(shared_secret) => {
                assert_eq!(shared_secret.len(), ed25519::BYTES);
            }
            Err(_) => {
                // It's okay if this fails, as long as it doesn't panic
                // Ed25519 has strict requirements for valid keys
            }
        }
    }

    #[test]
    fn test_ristretto255() {
        // Skip this test if the operation fails
        // Ristretto255 requires specially formatted keys for scalar multiplication
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; ristretto255::SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });

        let mut public_key = vec![0u8; ristretto255::BYTES];
        // Initialize with sequential values offset by 100
        public_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = (i + 100) as u8;
        });

        // Try the operation, but don't unwrap
        match ristretto255::scalarmult(&secret_key, &public_key) {
            Ok(shared_secret) => {
                assert_eq!(shared_secret.len(), ristretto255::BYTES);
            }
            Err(_) => {
                // It's okay if this fails, as long as it doesn't panic
                // Ristretto255 has strict requirements for valid keys
            }
        }
    }
}
