//! # Cryptographic Hashing Functions
//!
//! This module provides access to the SHA-256 and SHA-512 hash functions.
//!
//! ## Important Notes
//!
//! - These functions are provided primarily for interoperability with other applications.
//! - For general purpose hashing, consider using `crypto_generichash` (BLAKE2b) instead.
//! - These functions are not suitable for password hashing or key derivation.
//!   Use the `crypto_pwhash` module for those purposes.
//! - These functions are not keyed and are deterministic.
//! - The untruncated versions are vulnerable to length extension attacks.
//!
//! ## Usage Example
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_hash;
//! use sodium::ensure_init;
//! use ct_codecs::{Encoder, Hex};
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Data to hash
//! let data = b"The quick brown fox jumps over the lazy dog";
//!
//! // Compute SHA-256 hash
//! let hash = crypto_hash::hash_sha256(data);
//!
//! // Convert to hex for display
//! let mut encoded = vec![0u8; hash.len() * 2];
//! let encoded = Hex::encode(&mut encoded, &hash).unwrap();
//! let hash_hex = std::str::from_utf8(encoded).unwrap();
//!
//! println!("SHA-256: {}", hash_hex);
//! ```

pub mod sha256;
pub mod sha3256;
pub mod sha3512;
pub mod sha512;

// No need for Result import since hash functions can't fail

/// Number of bytes in a SHA-256 hash output (32 bytes, 256 bits)
pub const SHA256_BYTES: usize = sha256::BYTES;

/// Number of bytes in a SHA3-256 hash output (32 bytes, 256 bits)
pub const SHA3256_BYTES: usize = sha3256::BYTES;

/// Number of bytes in a SHA3-512 hash output (64 bytes, 512 bits)
pub const SHA3512_BYTES: usize = sha3512::BYTES;

/// Number of bytes in a SHA-512 hash output (64 bytes, 512 bits)
pub const SHA512_BYTES: usize = sha512::BYTES;

/// Computes a SHA-512 hash of the input data
///
/// This is a convenience wrapper around `hash_sha512`. The SHA-512 algorithm produces
/// a 64-byte (512-bit) hash value.
///
/// > **Note**: This function is primarily provided for compatibility with other systems.
/// > For new applications, consider using `crypto_generichash` (BLAKE2b) instead.
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * `[u8; SHA512_BYTES]` - The SHA-512 hash of the input data (64 bytes)
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_hash;
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
/// let hash = crypto_hash::hash(data);
///
/// // Convert to hex for display
/// let mut encoded = vec![0u8; hash.len() * 2];
/// let encoded = Hex::encode(&mut encoded, &hash).unwrap();
/// let hash_hex = std::str::from_utf8(encoded).unwrap();
///
/// println!("SHA-512: {}", hash_hex);
/// ```
pub fn hash(data: &[u8]) -> [u8; SHA512_BYTES] {
    let mut out = [0u8; SHA512_BYTES];
    unsafe {
        libsodium_sys::crypto_hash(out.as_mut_ptr(), data.as_ptr(), data.len() as u64);
    }
    out
}

/// Computes a SHA3-256 hash of the input data.
pub fn hash_sha3256(data: &[u8]) -> [u8; SHA3256_BYTES] {
    sha3256::hash(data)
}

/// Computes a SHA3-512 hash of the input data.
pub fn hash_sha3512(data: &[u8]) -> [u8; SHA3512_BYTES] {
    sha3512::hash(data)
}

/// Computes a SHA-256 hash of the input data
///
/// The SHA-256 algorithm produces a 32-byte (256-bit) hash value. This function
/// computes the hash in a single pass, which is suitable for small to medium-sized data.
///
/// > **Note**: This function is primarily provided for compatibility with other systems.
/// > For new applications, consider using `crypto_generichash` (BLAKE2b) instead.
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * `[u8; SHA256_BYTES]` - The SHA-256 hash of the input data (32 bytes)
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_hash;
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
/// let hash = crypto_hash::hash_sha256(data);
///
/// // Convert to hex for display
/// let mut encoded = vec![0u8; hash.len() * 2];
/// let encoded = Hex::encode(&mut encoded, &hash).unwrap();
/// let hash_hex = std::str::from_utf8(encoded).unwrap();
///
/// println!("SHA-256: {}", hash_hex);
/// ```
pub fn hash_sha256(data: &[u8]) -> [u8; SHA256_BYTES] {
    sha256::hash(data)
}

/// Computes a SHA-512 hash of the input data
///
/// The SHA-512 algorithm produces a 64-byte (512-bit) hash value. This function
/// computes the hash in a single pass, which is suitable for small to medium-sized data.
///
/// > **Note**: This function is primarily provided for compatibility with other systems.
/// > For new applications, consider using `crypto_generichash` (BLAKE2b) instead.
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * `[u8; SHA512_BYTES]` - The SHA-512 hash of the input data (64 bytes)
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_hash;
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
/// let hash = crypto_hash::hash_sha512(data);
///
/// // Convert to hex for display
/// let mut encoded = vec![0u8; hash.len() * 2];
/// let encoded = Hex::encode(&mut encoded, &hash).unwrap();
/// let hash_hex = std::str::from_utf8(encoded).unwrap();
///
/// println!("SHA-512: {}", hash_hex);
/// ```
pub fn hash_sha512(data: &[u8]) -> [u8; SHA512_BYTES] {
    sha512::hash(data)
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
    fn test_hash_sha256() {
        let data = b"test data";
        let hash = hash_sha256(data);

        // Convert hash to hex string for comparison
        let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, hash).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_hash_sha3256() {
        let data = b"test data";
        let hash = hash_sha3256(data);

        let mut encoded = vec![0u8; hash.len() * 2];
        let encoded = Hex::encode(&mut encoded, hash).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "fc88e0ac33ff105e376f4ece95fb06925d5ab20080dbe3aede7dd47e45dfd931"
        );
    }

    #[test]
    fn test_hash_sha3512() {
        let data = b"test data";
        let hash = hash_sha3512(data);

        let mut encoded = vec![0u8; hash.len() * 2];
        let encoded = Hex::encode(&mut encoded, hash).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "bb9e2a02237e6f8adcaef9fc14b898b7c80cedc114110472cdf925233621b705963c76e7b113bed3c278ff11671a6d1cdcba545e009ff4c0c02539899241993b"
        );
    }

    #[test]
    fn test_hash_sha512() {
        let data = b"test data";
        let hash = hash_sha512(data);

        // Convert hash to hex string for comparison
        let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
        let encoded = Hex::encode(&mut encoded, hash).unwrap();
        let hash_hex = std::str::from_utf8(encoded).unwrap();

        assert_eq!(
            hash_hex,
            "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d"
        );
    }
}
