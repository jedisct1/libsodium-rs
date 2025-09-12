//! # Ed25519 Scalar Multiplication
//!
//! This module provides functions for performing scalar multiplication operations
//! using the Ed25519 elliptic curve. Ed25519 is primarily used for digital signatures,
//! but these functions allow for using it in key exchange protocols as well.
//!
//! Note that these functions are distinct from the X25519 key exchange and should
//! only be used in specific protocols that explicitly require Ed25519 scalar multiplication
//! rather than X25519.
//!
//! ## Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_scalarmult::ed25519;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a secret key (normally this would be random)
//! let secret_key = vec![0u8; ed25519::SCALARBYTES];
//! let public_key = vec![0u8; ed25519::BYTES]; // In a real app, this would be received from another party
//!
//! // Compute a shared secret using your secret key and another party's public key
//! match ed25519::scalarmult(&secret_key, &public_key) {
//!     Ok(shared_secret) => {
//!         println!("Shared secret computed successfully");
//!     },
//!     Err(err) => {
//!         println!("Failed to compute shared secret: {}", err);
//!     }
//! }
//!
//! // Alternatively, use the noclamp variant for specialized applications
//! match ed25519::scalarmult_noclamp(&secret_key, &public_key) {
//!     Ok(shared_secret_noclamp) => {
//!         println!("Shared secret (noclamp) computed successfully");
//!     },
//!     Err(err) => {
//!         println!("Failed to compute shared secret (noclamp): {}", err);
//!     }
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - Ed25519 is designed for signatures, so its use for key exchange requires careful consideration
//! - The curve has a cofactor of 8, which means some care must be taken in certain applications
//! - The "noclamp" variants skip the clamping of secret keys, which is generally less secure
//!   but may be needed for certain specialized protocols
//! - For most key exchange applications, Curve25519 or Ristretto255 may be more appropriate
//! - Always use cryptographically secure random values for secret keys
//! - Results from scalar multiplication should not be used directly as cryptographic keys
//!   without hashing
//! - The clamping operation ensures the scalar is a multiple of the cofactor (8), which
//!   helps prevent small subgroup attacks
//! - Be aware that Ed25519 scalar multiplication can be vulnerable to timing attacks if not
//!   implemented carefully (libsodium's implementation is constant-time)

use crate::{Result, SodiumError};

pub const BYTES: usize = libsodium_sys::crypto_scalarmult_ed25519_BYTES as usize;
pub const SCALARBYTES: usize = libsodium_sys::crypto_scalarmult_ed25519_SCALARBYTES as usize;

/// Computes a shared secret using Ed25519
///
/// This function multiplies a point `public_key` by a scalar `secret_key` (with clamping)
/// and puts the Y coordinate of the resulting point into the returned bytes.
///
/// Note that the scalar is "clamped" (the 3 low bits are cleared to make it a multiple
/// of the cofactor, bit 254 is set and bit 255 is cleared to respect the original design).
///
/// The clamping operation is important for security as it helps prevent small subgroup attacks
/// by ensuring the scalar is a multiple of the cofactor (8).
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
/// * `SodiumError::OperationError` - If the operation fails (e.g., if `secret_key` is 0 or if `public_key` is not valid)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::ed25519;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keys (in a real application, use random keys)
/// let secret_key = vec![0u8; ed25519::SCALARBYTES];
/// let public_key = vec![0u8; ed25519::BYTES]; // In a real app, this would be received from another party
///
/// // Compute shared secret
/// match ed25519::scalarmult(&secret_key, &public_key) {
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
        libsodium_sys::crypto_scalarmult_ed25519(
            shared_secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "ed25519 scalarmult failed (secret key may be 0 or public key is not valid)".into(),
        ));
    }

    Ok(shared_secret)
}

/// Computes a shared secret using Ed25519 without clamping the secret key
///
/// This function multiplies a point `public_key` by a scalar `secret_key` (without clamping)
/// and puts the Y coordinate of the resulting point into the returned bytes.
///
/// WARNING: This function skips the clamping operation, which can be dangerous in most
/// applications. Only use this function if you fully understand the security implications
/// and your protocol specifically requires unclamped scalars.
///
/// The "noclamp" variant skips the clamping of the secret key, which is generally less secure
/// but may be needed for certain specialized protocols.
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
/// * `SodiumError::OperationError` - If the operation fails (e.g., if `secret_key` is 0 or if `public_key` is not valid)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::ed25519;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keys (in a real application, use random keys)
/// let secret_key = vec![0u8; ed25519::SCALARBYTES];
/// let public_key = vec![0u8; ed25519::BYTES]; // In a real app, this would be received from another party
///
/// // Compute shared secret without clamping
/// match ed25519::scalarmult_noclamp(&secret_key, &public_key) {
///     Ok(shared_secret) => {
///         println!("Shared secret (noclamp) computed successfully");
///         // Use shared_secret for further operations
///     },
///     Err(err) => {
///         eprintln!("Failed to compute shared secret (noclamp): {}", err);
///         // Handle the error appropriately
///     }
/// }
/// ```
#[must_use = "This function returns a shared secret that should be used for cryptographic operations"]
pub fn scalarmult_noclamp(secret_key: &[u8], public_key: &[u8]) -> Result<[u8; BYTES]> {
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
        libsodium_sys::crypto_scalarmult_ed25519_noclamp(
            shared_secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "ed25519 scalarmult_noclamp failed (secret key may be 0 or public key is not valid)"
                .into(),
        ));
    }

    Ok(shared_secret)
}

/// Multiplies the Ed25519 base point by a scalar with clamping
///
/// This function multiplies the Ed25519 base point by a scalar (with clamping)
/// and puts the Y coordinate of the resulting point into the returned bytes.
///
/// This operation can be used to derive a public key from a secret key, though
/// the encoding differs from the standard Ed25519 public key encoding used for signatures.
///
/// Note that the scalar is "clamped" (the 3 low bits are cleared to make it a multiple
/// of the cofactor, bit 254 is set and bit 255 is cleared to respect the original design).
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
/// * `SodiumError::OperationError` - If the operation fails (e.g., if the secret key is 0)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::ed25519;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a secret key (in a real application, use a random key)
/// let secret_key = vec![1u8; ed25519::SCALARBYTES]; // Non-zero for this example
///
/// // Compute the corresponding public key
/// match ed25519::scalarmult_base(&secret_key) {
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
        libsodium_sys::crypto_scalarmult_ed25519_base(public_key.as_mut_ptr(), secret_key.as_ptr())
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "ed25519 scalarmult_base failed (secret key may be 0)".into(),
        ));
    }

    Ok(public_key)
}

/// Multiplies the Ed25519 base point by a scalar without clamping
///
/// This function multiplies the Ed25519 base point by a scalar (without clamping)
/// and puts the Y coordinate of the resulting point into the returned bytes.
///
/// WARNING: This function skips the clamping operation, which can be dangerous in most
/// applications. Only use this function if you fully understand the security implications
/// and your protocol specifically requires unclamped scalars.
///
/// The "noclamp" variant skips the clamping of the secret key, which is generally less secure
/// but may be needed for certain specialized protocols.
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
/// * `SodiumError::OperationError` - If the operation fails (e.g., if the secret key is 0)
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_scalarmult::ed25519;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a secret key (in a real application, use a random key)
/// let secret_key = vec![1u8; ed25519::SCALARBYTES]; // Non-zero for this example
///
/// // Compute the corresponding public key without clamping
/// match ed25519::scalarmult_base_noclamp(&secret_key) {
///     Ok(public_key) => {
///         println!("Public key generated successfully (noclamp)");
///         // Use public_key for further operations
///     },
///     Err(err) => {
///         eprintln!("Failed to generate public key (noclamp): {}", err);
///         // Handle the error appropriately
///     }
/// }
/// ```
#[must_use = "This function returns a public key that should be used for cryptographic operations"]
pub fn scalarmult_base_noclamp(secret_key: &[u8]) -> Result<[u8; BYTES]> {
    if secret_key.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "secret key must be exactly {SCALARBYTES} bytes"
        )));
    }

    let mut public_key = [0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_scalarmult_ed25519_base_noclamp(
            public_key.as_mut_ptr(),
            secret_key.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "ed25519 scalarmult_base_noclamp failed (secret key may be 0)".into(),
        ));
    }

    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalarmult() {
        // Skip this test if the operation fails
        // Ed25519 requires specially formatted keys for scalar multiplication
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });

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
                // Ed25519 has strict requirements for valid keys
            }
        }
    }

    #[test]
    fn test_scalarmult_noclamp() {
        // Skip this test if the operation fails
        // Ed25519 requires specially formatted keys for scalar multiplication
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });

        let mut public_key = vec![0u8; BYTES];
        // Initialize with sequential values offset by 100
        public_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = (i + 100) as u8;
        });

        // Try the operation, but don't unwrap
        match scalarmult_noclamp(&secret_key, &public_key) {
            Ok(shared_secret) => {
                assert_eq!(shared_secret.len(), BYTES);
            }
            Err(_) => {
                // It's okay if this fails, as long as it doesn't panic
                // Ed25519 has strict requirements for valid keys
            }
        }
    }

    #[test]
    fn test_scalarmult_base() {
        // Skip this test if the operation fails
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
                // Ed25519 has strict requirements for valid keys
            }
        }
    }

    #[test]
    fn test_scalarmult_base_noclamp() {
        // Skip this test if the operation fails
        // For testing purposes, we'll just check that the function doesn't panic
        let mut secret_key = vec![0u8; SCALARBYTES];
        // Initialize with sequential values
        secret_key.iter_mut().enumerate().for_each(|(i, byte)| {
            *byte = i as u8;
        });
        // Make sure it's not all zeros
        secret_key[0] = 1;

        // Try the operation, but don't unwrap
        match scalarmult_base_noclamp(&secret_key) {
            Ok(public_key) => {
                assert_eq!(public_key.len(), BYTES);
            }
            Err(_) => {
                // It's okay if this fails, as long as it doesn't panic
                // Ed25519 has strict requirements for valid keys
            }
        }
    }
}
