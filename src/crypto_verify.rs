//! # Constant-Time Verification Functions
//!
//! This module provides functions for comparing fixed-length byte sequences in constant time.
//! These functions are designed to prevent timing attacks when verifying sensitive data such as
//! authentication tags, signatures, or other cryptographic values.
//!
//! ## Security Considerations
//!
//! - Standard comparison operators (like `==`) may not execute in constant time, potentially
//!   leaking information through timing variations.
//! - These functions guarantee that the comparison takes the same amount of time regardless
//!   of where the first difference occurs in the sequences.
//! - Always use these functions when comparing secret or security-critical values.
//!
//! ## Available Functions
//!
//! - [`verify_16`]: Compare two 16-byte sequences in constant time
//! - [`verify_32`]: Compare two 32-byte sequences in constant time
//! - [`verify_64`]: Compare two 64-byte sequences in constant time
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_verify;
//! use sodium::ensure_init;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     ensure_init()?;
//!
//!     let tag1 = [0u8; 32];
//!     let tag2 = [0u8; 32];
//!     let tag3 = [1u8; 32];
//!
//!     // Compare in constant time
//!     assert!(crypto_verify::verify_32(&tag1, &tag2)); // Equal
//!     assert!(!crypto_verify::verify_32(&tag1, &tag3)); // Not equal
//!
//!     Ok(())
//! }
//! ```
//!

// No need to import Result as functions return bool directly

/// Compares two 16-byte sequences in constant time
///
/// Returns `false` if the inputs are not 16 bytes in length or if they don't match.
/// This function executes in constant time for equal-length inputs.
///
/// Note: Length checking happens before constant-time comparison for safety,
/// as comparing different-length buffers would be undefined behavior.
pub fn verify_16(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 16 || y.len() != 16 {
        return false;
    }
    unsafe { libsodium_sys::crypto_verify_16(x.as_ptr(), y.as_ptr()) == 0 }
}

/// Compares two 32-byte sequences in constant time
///
/// Returns `false` if the inputs are not 32 bytes in length or if they don't match.
/// This function executes in constant time for equal-length inputs.
///
/// Note: Length checking happens before constant-time comparison for safety,
/// as comparing different-length buffers would be undefined behavior.
pub fn verify_32(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    unsafe { libsodium_sys::crypto_verify_32(x.as_ptr(), y.as_ptr()) == 0 }
}

/// Compares two 64-byte sequences in constant time
///
/// Returns `false` if the inputs are not 64 bytes in length or if they don't match.
/// This function executes in constant time for equal-length inputs.
///
/// Note: Length checking happens before constant-time comparison for safety,
/// as comparing different-length buffers would be undefined behavior.
pub fn verify_64(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 64 || y.len() != 64 {
        return false;
    }
    unsafe { libsodium_sys::crypto_verify_64(x.as_ptr(), y.as_ptr()) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_16() {
        let x = [0u8; 16];
        let y = [0u8; 16];
        let z = [1u8; 16];

        assert!(verify_16(&x, &x));
        assert!(verify_16(&x, &y));
        assert!(!verify_16(&x, &z));

        // Test invalid lengths
        assert!(!verify_16(&x, &[0u8; 15]));
        assert!(!verify_16(&[0u8; 15], &x));
    }

    #[test]
    fn test_verify_32() {
        let x = [0u8; 32];
        let y = [0u8; 32];
        let z = [1u8; 32];

        assert!(verify_32(&x, &x));
        assert!(verify_32(&x, &y));
        assert!(!verify_32(&x, &z));

        // Test invalid lengths
        assert!(!verify_32(&x, &[0u8; 31]));
        assert!(!verify_32(&[0u8; 31], &x));
    }

    #[test]
    fn test_verify_64() {
        let x = [0u8; 64];
        let y = [0u8; 64];
        let z = [1u8; 64];

        assert!(verify_64(&x, &x));
        assert!(verify_64(&x, &y));
        assert!(!verify_64(&x, &z));

        // Test invalid lengths
        assert!(!verify_64(&x, &[0u8; 63]));
        assert!(!verify_64(&[0u8; 63], &x));
    }
}
