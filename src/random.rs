//! # Secure Random Number Generation
//!
//! This module provides functions for generating cryptographically secure random numbers
//! and bytes. It uses libsodium's random number generator, which is designed to be
//! suitable for cryptographic operations.
//!
//! ## Security Considerations
//!
//! - The random number generator is automatically seeded with sufficient entropy during
//!   library initialization.
//! - The implementation is designed to be resistant to side-channel attacks.
//! - The generator is suitable for generating cryptographic keys, nonces, and other
//!   security-sensitive values.
//!
//! ## Available Functions
//!
//! - [`bytes`]: Generate a vector of random bytes
//! - [`fill_bytes`]: Fill an existing buffer with random bytes
//! - [`u32()`]: Generate a random 32-bit unsigned integer
//! - [`uniform`]: Generate a random 32-bit unsigned integer within a range
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::random;
//! use sodium::ensure_init;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     ensure_init()?;
//!
//!     // Generate 32 random bytes (suitable for a key)
//!     let random_bytes = random::bytes(32);
//!     assert_eq!(random_bytes.len(), 32);
//!
//!     // Fill an existing buffer with random bytes
//!     let mut buffer = [0u8; 16];
//!     random::fill_bytes(&mut buffer);
//!
//!     // Generate a random 32-bit unsigned integer
//!     let random_u32 = random::u32();
//!
//!     // Generate a random integer between 0 and 99 (inclusive)
//!     let dice_roll = random::uniform(100);
//!     assert!(dice_roll < 100);
//!
//!     Ok(())
//! }
//! ```
//!

use libsodium_sys;

/// Generate random bytes
pub fn bytes(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    unsafe {
        libsodium_sys::randombytes_buf(buf.as_mut_ptr() as *mut _, size);
    }
    buf
}

/// Fill a buffer with random bytes
///
/// This function fills the provided buffer with random bytes.
/// It cannot fail and does not return a Result.
pub fn fill_bytes(buf: &mut [u8]) {
    unsafe {
        libsodium_sys::randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len());
    }
}

/// Generate a random 32-bit unsigned integer
pub fn u32() -> u32 {
    unsafe { libsodium_sys::randombytes_random() }
}

/// Generate a random 32-bit unsigned integer between 0 and upper_bound (exclusive)
pub fn uniform(upper_bound: u32) -> u32 {
    unsafe { libsodium_sys::randombytes_uniform(upper_bound) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes1 = bytes(32);
        let bytes2 = bytes(32);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Extremely unlikely to be equal
    }

    #[test]
    fn test_random_u32() {
        let _ = u32(); // Just ensure it doesn't panic
    }

    #[test]
    fn test_uniform() {
        let bound = 100;
        for _ in 0..1000 {
            let n = uniform(bound);
            assert!(n < bound);
        }
    }
}
