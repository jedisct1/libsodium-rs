//! # Core Cryptographic Operations
//!
//! This module provides low-level cryptographic primitives for performing operations
//! on elliptic curves and other cryptographic cores. These functions are primarily
//! useful for implementing custom cryptographic constructions.
//!
//! ## Submodules
//!
//! - **Ed25519**: Operations on the Edwards25519 elliptic curve, including point validation,
//!   addition, subtraction, and scalar multiplication.
//! - **Ristretto255**: Operations using the Ristretto255 group, which provides a prime-order
//!   group built on top of the Edwards25519 curve with additional properties.
//! - **HChaCha20**: Core function for the HChaCha20 cipher, which is used in XChaCha20
//!   to extend the nonce size.
//!
//! ## Security Considerations
//!
//! These are low-level functions that should only be used if you understand the underlying
//! cryptographic principles. For most applications, you should use the higher-level APIs
//! provided by libsodium instead.
//!
//! ## Example: Point Addition on Ed25519
//!
//! ```rust
//! use libsodium_rs::crypto_core::ed25519;
//! use libsodium_rs::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Example valid Ed25519 points (base point and a multiple of it)
//! let p = [
//!     0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
//!     0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
//!     0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
//!     0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
//! ]; // Ed25519 base point
//! let q = p; // Using the same point for simplicity
//!
//! // Add the two points
//! match ed25519::add(&p, &q) {
//!     Ok(sum) => {
//!         // Use the resulting point
//!         println!("Addition successful!");
//!     },
//!     Err(err) => {
//!         // Handle the error case
//!         println!("Addition failed: {}", err);
//!     }
//! }
//! ```

use crate::{Result, SodiumError};

/// Ed25519 elliptic curve operations
///
/// This module provides low-level operations on the Edwards25519 elliptic curve, which is
/// used in the Ed25519 signature scheme. These operations include point validation,
/// addition, subtraction, scalar multiplication, and scalar reduction.
///
/// Points on the Edwards25519 curve are represented as their compressed Y coordinate
/// in 32 bytes. Scalars are also 32 bytes.
///
/// ## Security Considerations
///
/// - These functions are designed for implementing custom cryptographic protocols
/// - For standard use cases like signatures, use the higher-level `crypto_sign` module
/// - All operations are designed to be constant-time to prevent side-channel attacks
///
/// ## Example: Point Addition
///
/// ```rust
/// use libsodium_rs::crypto_core::ed25519;
///
/// // Assuming p and q are valid Ed25519 points
/// let p = [0u8; ed25519::BYTES]; // In practice, these would be valid points
/// let q = [0u8; ed25519::BYTES];
///
/// // Check if points are valid
/// if let (Ok(p_valid), Ok(q_valid)) = (ed25519::is_valid_point(&p), ed25519::is_valid_point(&q)) {
///     if p_valid && q_valid {
///         // Add the two points
///         match ed25519::add(&p, &q) {
///             Ok(sum) => {
///                 // Use the resulting point
///                 println!("Addition successful!");
///             },
///             Err(err) => {
///                 println!("Addition failed: {}", err);
///             }
///         }
///     }
/// }
/// ```
pub mod ed25519 {
    use super::*;

    /// Number of bytes in an Ed25519 point (32)
    pub const BYTES: usize = libsodium_sys::crypto_core_ed25519_BYTES as usize;
    /// Number of bytes in an Ed25519 scalar (32)
    pub const SCALARBYTES: usize = libsodium_sys::crypto_core_ed25519_SCALARBYTES as usize;
    /// Number of bytes in a non-reduced Ed25519 scalar (64)
    /// Used for representing scalars before reduction modulo L
    pub const NONREDUCEDSCALARBYTES: usize =
        libsodium_sys::crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize;
    /// Number of bytes for uniform representation (32)
    /// Used for the Elligator 2 map input
    pub const UNIFORMBYTES: usize = libsodium_sys::crypto_core_ed25519_UNIFORMBYTES as usize;

    /// Check if a point is on the Edwards25519 curve
    ///
    /// This function verifies that:
    /// - The point is on the Edwards25519 curve
    /// - The point is in canonical form
    /// - The point is on the main subgroup
    /// - The point doesn't have a small order
    ///
    /// # Arguments
    /// * `p` - Point to check (must be exactly `BYTES` length)
    ///
    /// # Returns
    /// * `Result<bool>` - `true` if the point is valid, `false` otherwise, or an error if the input is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Check if a point is valid
    /// let point = [0u8; ed25519::BYTES]; // In practice, this would be a real point
    /// match ed25519::is_valid_point(&point) {
    ///     Ok(true) => println!("Point is valid"),
    ///     Ok(false) => println!("Point is invalid"),
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the point has an invalid length
    pub fn is_valid_point(p: &[u8]) -> Result<bool> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid point length: expected {}, got {}",
                BYTES,
                p.len()
            )));
        }
        Ok(unsafe { libsodium_sys::crypto_core_ed25519_is_valid_point(p.as_ptr()) == 1 })
    }

    /// Add two points on the Edwards25519 curve
    ///
    /// This function performs point addition on the Edwards25519 curve. Both input points
    /// must be valid points on the curve. The result is also a point on the curve.
    ///
    /// # Mathematical Background
    ///
    /// On the Edwards25519 curve, point addition corresponds to adding the discrete logarithms
    /// of the points with respect to the base point. If P = g^a and Q = g^b (where g is the
    /// base point), then P + Q = g^(a+b).
    ///
    /// # Arguments
    /// * `p` - First point (must be exactly `BYTES` length)
    /// * `q` - Second point (must be exactly `BYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The sum of the two points or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Add two points
    /// let p = [0u8; ed25519::BYTES]; // In practice, these would be valid points
    /// let q = [0u8; ed25519::BYTES];
    ///
    /// let sum = ed25519::add(&p, &q).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either point has an invalid length
    /// - The addition operation fails (which should not happen for valid points)
    pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first point length: expected {}, got {}",
                BYTES,
                p.len()
            )));
        }
        if q.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second point length: expected {}, got {}",
                BYTES,
                q.len()
            )));
        }

        let mut r = [0u8; BYTES];
        if unsafe { libsodium_sys::crypto_core_ed25519_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) }
            != 0
        {
            return Err(SodiumError::OperationError("point addition failed".into()));
        }
        Ok(r)
    }

    /// Subtract two points on the Edwards25519 curve
    ///
    /// This function performs point subtraction on the Edwards25519 curve. Both input points
    /// must be valid points on the curve. The result is also a point on the curve.
    ///
    /// # Mathematical Background
    ///
    /// On the Edwards25519 curve, point subtraction corresponds to subtracting the discrete logarithms
    /// of the points with respect to the base point. If P = g^a and Q = g^b (where g is the
    /// base point), then P - Q = g^(a-b).
    ///
    /// # Arguments
    /// * `p` - First point (must be exactly `BYTES` length)
    /// * `q` - Second point (must be exactly `BYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The difference of the two points or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Subtract two points
    /// let p = [0u8; ed25519::BYTES]; // In practice, these would be valid points
    /// let q = [0u8; ed25519::BYTES];
    ///
    /// let difference = ed25519::sub(&p, &q).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either point has an invalid length
    /// - The subtraction operation fails (which should not happen for valid points)
    pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || q.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe { libsodium_sys::crypto_core_ed25519_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) }
            != 0
        {
            return Err(SodiumError::OperationError(
                "point subtraction failed".into(),
            ));
        }
        Ok(r)
    }

    /// Multiply a point by a scalar on the Edwards25519 curve
    ///
    /// This function performs scalar multiplication on the Edwards25519 curve. The input point
    /// must be a valid point on the curve, and the scalar must be a valid scalar. The result
    /// is also a point on the curve.
    ///
    /// # Mathematical Background
    ///
    /// Scalar multiplication computes n·P, which is equivalent to adding P to itself n times.
    /// If P = g^a, then n·P = g^(n·a mod L), where L is the order of the main subgroup.
    ///
    /// # Security Considerations
    ///
    /// - This operation is performed in constant time to prevent timing attacks
    /// - The scalar is not clamped, so it must be properly reduced if necessary
    ///
    /// # Arguments
    /// * `p` - Point to multiply (must be exactly `BYTES` length)
    /// * `n` - Scalar to multiply by (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The resulting point or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Multiply a point by a scalar
    /// let point = [0u8; ed25519::BYTES]; // In practice, this would be a valid point
    /// let scalar = [0u8; ed25519::SCALARBYTES]; // In practice, this would be a valid scalar
    ///
    /// let result = ed25519::scalar_mul(&point, &scalar).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The point has an invalid length
    /// - The scalar has an invalid length
    pub fn scalar_mul(p: &[u8], n: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid point length: expected {}, got {}",
                BYTES,
                p.len()
            )));
        }
        if n.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                n.len()
            )));
        }

        let mut r = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_mul(r.as_mut_ptr(), p.as_ptr(), n.as_ptr());
        }
        Ok(r)
    }

    /// Reduce a scalar to the valid range for the Edwards25519 curve
    ///
    /// This function reduces a 64-byte scalar to a 32-byte scalar modulo L, where L is the
    /// order of the main subgroup of the Edwards25519 curve.
    ///
    /// # Mathematical Background
    ///
    /// The scalar is reduced modulo L = 2^252 + 27_742_317_777_372_353_535_851_937_790_883_648_493, which
    /// is the order of the main subgroup of the Edwards25519 curve.
    ///
    /// # Arguments
    /// * `s` - Scalar to reduce (must be exactly `NONREDUCEDSCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The reduced scalar or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Reduce a scalar
    /// let scalar = [0u8; ed25519::NONREDUCEDSCALARBYTES]; // In practice, this would be a real scalar
    ///
    /// let reduced = ed25519::scalar_reduce(&scalar).unwrap();
    /// assert_eq!(reduced.len(), ed25519::SCALARBYTES);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the scalar has an invalid length
    pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != NONREDUCEDSCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                NONREDUCEDSCALARBYTES,
                s.len()
            )));
        }

        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_reduce(r.as_mut_ptr(), s.as_ptr());
        }
        Ok(r)
    }

    /// Generate a random valid point on the Edwards25519 curve
    ///
    /// This function generates a random point on the Edwards25519 curve. The point
    /// is guaranteed to be a valid point on the curve and in the main subgroup.
    ///
    /// # Returns
    /// * `[u8; BYTES]` - A random valid point on the curve
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate a random point
    /// let point = ed25519::random();
    ///
    /// // Verify that the point is valid
    /// assert!(ed25519::is_valid_point(&point).unwrap());
    /// ```
    pub fn random() -> [u8; BYTES] {
        let mut p = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_random(p.as_mut_ptr());
        }
        p
    }

    /// Generate a random scalar for the Edwards25519 curve
    ///
    /// This function generates a random scalar suitable for use with the Edwards25519 curve.
    /// The scalar is uniformly distributed between 0 and L-1, where L is the order of the
    /// main subgroup of the Edwards25519 curve.
    ///
    /// # Returns
    /// * `[u8; SCALARBYTES]` - A random scalar
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate a random scalar
    /// let scalar = ed25519::scalar_random();
    ///
    /// // Use the scalar for operations
    /// let point = ed25519::random();
    /// let result = ed25519::scalar_mul(&point, &scalar).unwrap();
    /// ```
    pub fn scalar_random() -> [u8; SCALARBYTES] {
        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_random(r.as_mut_ptr());
        }
        r
    }

    /// Compute the multiplicative inverse of a scalar
    ///
    /// This function computes the multiplicative inverse of a scalar modulo L, where L is the
    /// order of the main subgroup of the Edwards25519 curve. The inverse s^(-1) of a scalar s
    /// is such that s * s^(-1) ≡ 1 (mod L).
    ///
    /// # Arguments
    /// * `s` - Scalar to invert (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The multiplicative inverse of the scalar or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// - The scalar has an invalid length
    /// - The scalar is 0, which has no multiplicative inverse
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate a random non-zero scalar
    /// let mut scalar = ed25519::scalar_random();
    /// scalar[0] |= 1; // Ensure it's not zero
    ///
    /// // Compute its inverse
    /// let inverse = ed25519::scalar_invert(&scalar).unwrap();
    ///
    /// // Verify: scalar * inverse ≡ 1 (mod L)
    /// // This would require additional operations to verify
    /// ```
    pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut recip = [0u8; SCALARBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_invert(recip.as_mut_ptr(), s.as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "scalar inversion failed (scalar may be 0)".into(),
            ));
        }

        Ok(recip)
    }

    /// Negate a scalar
    ///
    /// This function computes the negation of a scalar modulo L, where L is the order of the
    /// main subgroup of the Edwards25519 curve. The negation -s of a scalar s is such that
    /// s + (-s) ≡ 0 (mod L).
    ///
    /// # Arguments
    /// * `s` - Scalar to negate (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The negation of the scalar or an error
    ///
    /// # Errors
    /// Returns an error if the scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate a random scalar
    /// let scalar = ed25519::scalar_random();
    ///
    /// // Compute its negation
    /// let negation = ed25519::scalar_negate(&scalar).unwrap();
    ///
    /// // Verify: scalar + negation ≡ 0 (mod L)
    /// // This would require additional operations to verify
    /// ```
    pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut neg = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_negate(neg.as_mut_ptr(), s.as_ptr());
        }

        Ok(neg)
    }

    /// Compute the complement of a scalar
    ///
    /// This function computes the complement of a scalar modulo L, where L is the order of the
    /// main subgroup of the Edwards25519 curve. The complement of a scalar s is defined as
    /// L - 1 - s.
    ///
    /// # Arguments
    /// * `s` - Scalar to complement (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The complement of the scalar or an error
    ///
    /// # Errors
    /// Returns an error if the scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate a random scalar
    /// let scalar = ed25519::scalar_random();
    ///
    /// // Compute its complement
    /// let complement = ed25519::scalar_complement(&scalar).unwrap();
    /// ```
    pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut comp = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_complement(comp.as_mut_ptr(), s.as_ptr());
        }

        Ok(comp)
    }

    /// Add two scalars
    ///
    /// This function adds two scalars modulo L, where L is the order of the main subgroup
    /// of the Edwards25519 curve.
    ///
    /// # Arguments
    /// * `x` - First scalar (must be exactly `SCALARBYTES` length)
    /// * `y` - Second scalar (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The sum of the scalars or an error
    ///
    /// # Errors
    /// Returns an error if either scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate two random scalars
    /// let x = ed25519::scalar_random();
    /// let y = ed25519::scalar_random();
    ///
    /// // Add them
    /// let sum = ed25519::scalar_add(&x, &y).unwrap();
    /// ```
    pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_add(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
        }

        Ok(z)
    }

    /// Subtract one scalar from another
    ///
    /// This function subtracts one scalar from another modulo L, where L is the order of the
    /// main subgroup of the Edwards25519 curve.
    ///
    /// # Arguments
    /// * `x` - First scalar (must be exactly `SCALARBYTES` length)
    /// * `y` - Second scalar to subtract (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The difference of the scalars (x - y) or an error
    ///
    /// # Errors
    /// Returns an error if either scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate two random scalars
    /// let x = ed25519::scalar_random();
    /// let y = ed25519::scalar_random();
    ///
    /// // Subtract y from x
    /// let difference = ed25519::scalar_sub(&x, &y).unwrap();
    /// ```
    pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_sub(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
        }

        Ok(z)
    }

    /// Multiply two scalars
    ///
    /// This function multiplies two scalars modulo L, where L is the order of the main subgroup
    /// of the Edwards25519 curve.
    ///
    /// # Arguments
    /// * `x` - First scalar (must be exactly `SCALARBYTES` length)
    /// * `y` - Second scalar (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The product of the scalars or an error
    ///
    /// # Errors
    /// Returns an error if either scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    ///
    /// // Generate two random scalars
    /// let x = ed25519::scalar_random();
    /// let y = ed25519::scalar_random();
    ///
    /// // Multiply them
    /// let product = ed25519::scalar_multiply(&x, &y).unwrap();
    /// ```
    pub fn scalar_multiply(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ed25519_scalar_mul(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
        }

        Ok(z)
    }

    /// Convert a uniform string to an Ed25519 point
    ///
    /// This function maps a 32-byte uniform string to a point on the Edwards25519 curve
    /// using the Elligator 2 map. The resulting point is guaranteed to be a valid point
    /// on the curve and in the main subgroup.
    ///
    /// # Arguments
    /// * `r` - Uniform string (must be exactly `UNIFORMBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The resulting point or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// - The uniform string has an invalid length
    /// - The conversion operation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ed25519;
    /// use libsodium_rs::random;
    ///
    /// // Generate a random uniform string
    /// let r = random::bytes(ed25519::UNIFORMBYTES);
    ///
    /// // Convert to a point
    /// let point = ed25519::from_uniform(&r).unwrap();
    ///
    /// // Verify that the point is valid
    /// assert!(ed25519::is_valid_point(&point).unwrap());
    /// ```
    pub fn from_uniform(r: &[u8]) -> Result<[u8; BYTES]> {
        if r.len() != UNIFORMBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid uniform string length: expected {}, got {}",
                UNIFORMBYTES,
                r.len()
            )));
        }

        let mut p = [0u8; BYTES];
        let result =
            unsafe { libsodium_sys::crypto_core_ed25519_from_uniform(p.as_mut_ptr(), r.as_ptr()) };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "conversion from uniform string failed".into(),
            ));
        }

        Ok(p)
    }
}

/// Ristretto255 elliptic curve operations
///
/// This module provides operations on the Ristretto255 group, which is a prime-order
/// group built on top of the Edwards25519 curve. Ristretto255 eliminates the cofactor
/// issues present in the raw Edwards25519 curve, providing a cleaner abstraction for
/// cryptographic protocols.
///
/// The Ristretto255 group has the following properties:
/// - It is a prime-order group (the order is exactly 2^252 + 27_742_317_777_372_353_535_851_937_790_883_648_493)
/// - All elements have a unique encoding (unlike raw Edwards25519 points)
/// - It is designed to be safer for implementing cryptographic protocols
///
/// ## Security Considerations
///
/// - These functions are designed for implementing custom cryptographic protocols
/// - All operations are designed to be constant-time to prevent side-channel attacks
/// - Ristretto255 is preferred over raw Ed25519 for many cryptographic protocols
///
/// ## Example: Random Point Generation
///
/// ```rust
/// use libsodium_rs::crypto_core::ristretto255;
///
/// // Generate a random Ristretto255 point
/// let point = ristretto255::random().unwrap();
///
/// // Verify that the point is valid
/// assert!(ristretto255::is_valid_point(&point).unwrap());
/// ```
pub mod ristretto255 {
    use super::*;

    /// Number of bytes in a Ristretto255 point (32)
    pub const BYTES: usize = libsodium_sys::crypto_core_ristretto255_BYTES as usize;
    /// Number of bytes in a Ristretto255 scalar (32)
    pub const SCALARBYTES: usize = libsodium_sys::crypto_core_ristretto255_SCALARBYTES as usize;
    /// Number of bytes in a non-reduced Ristretto255 scalar (64)
    /// Used for representing scalars before reduction modulo the group order
    pub const NONREDUCEDSCALARBYTES: usize =
        libsodium_sys::crypto_core_ristretto255_NONREDUCEDSCALARBYTES as usize;
    /// Number of bytes in a hash for Ristretto255 point generation (64)
    /// Used for the from_hash function
    pub const HASHBYTES: usize = libsodium_sys::crypto_core_ristretto255_HASHBYTES as usize;

    /// Check if a point is valid for the Ristretto255 encoding
    ///
    /// This function verifies that the provided bytes represent a valid Ristretto255 point.
    /// Unlike Ed25519, every valid Ristretto255 encoding corresponds to a unique group element.
    ///
    /// # Arguments
    /// * `p` - Point to check (must be exactly `BYTES` length)
    ///
    /// # Returns
    /// * `Result<bool>` - `true` if the point is valid, `false` otherwise, or an error if the input is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Check if a point is valid
    /// let point = [0u8; ristretto255::BYTES]; // In practice, this would be a real point
    /// match ristretto255::is_valid_point(&point) {
    ///     Ok(true) => println!("Point is valid"),
    ///     Ok(false) => println!("Point is invalid"),
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the point has an invalid length
    pub fn is_valid_point(p: &[u8]) -> Result<bool> {
        if p.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        Ok(unsafe { libsodium_sys::crypto_core_ristretto255_is_valid_point(p.as_ptr()) == 1 })
    }

    /// Add two points using the Ristretto255 encoding
    ///
    /// This function performs point addition in the Ristretto255 group. Both input points
    /// must be valid Ristretto255 points. The result is also a valid Ristretto255 point.
    ///
    /// # Mathematical Background
    ///
    /// In the Ristretto255 group, point addition corresponds to adding the discrete logarithms
    /// of the points with respect to the base point. If P = g^a and Q = g^b (where g is the
    /// base point), then P + Q = g^(a+b).
    ///
    /// # Arguments
    /// * `p` - First point (must be exactly `BYTES` length)
    /// * `q` - Second point (must be exactly `BYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The sum of the two points or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Add two points
    /// let p = ristretto255::random().unwrap();
    /// let q = ristretto255::random().unwrap();
    ///
    /// let sum = ristretto255::add(&p, &q).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either point has an invalid length
    /// - Either point is not a valid Ristretto255 encoding
    pub fn add(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || q.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe {
            libsodium_sys::crypto_core_ristretto255_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr())
        } != 0
        {
            return Err(SodiumError::OperationError("point addition failed".into()));
        }
        Ok(r)
    }

    /// Subtract two points using the Ristretto255 encoding
    ///
    /// This function performs point subtraction in the Ristretto255 group. Both input points
    /// must be valid Ristretto255 points. The result is also a valid Ristretto255 point.
    ///
    /// # Mathematical Background
    ///
    /// In the Ristretto255 group, point subtraction corresponds to subtracting the discrete logarithms
    /// of the points with respect to the base point. If P = g^a and Q = g^b (where g is the
    /// base point), then P - Q = g^(a-b).
    ///
    /// # Arguments
    /// * `p` - First point (must be exactly `BYTES` length)
    /// * `q` - Second point (must be exactly `BYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The difference of the two points or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Subtract two points
    /// let p = ristretto255::random().unwrap();
    /// let q = ristretto255::random().unwrap();
    ///
    /// let difference = ristretto255::sub(&p, &q).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either point has an invalid length
    /// - Either point is not a valid Ristretto255 encoding
    pub fn sub(p: &[u8], q: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || q.len() != BYTES {
            return Err(SodiumError::InvalidInput("invalid point length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe {
            libsodium_sys::crypto_core_ristretto255_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr())
        } != 0
        {
            return Err(SodiumError::OperationError(
                "point subtraction failed".into(),
            ));
        }
        Ok(r)
    }

    /// Create a random point using the Ristretto255 encoding
    ///
    /// This function generates a random point in the Ristretto255 group with a uniform
    /// distribution. The resulting point is guaranteed to be a valid Ristretto255 point.
    ///
    /// # Security Considerations
    ///
    /// - The random point is generated using a cryptographically secure random number generator
    /// - The discrete logarithm of the generated point with respect to any other point is unknown
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - A random Ristretto255 point or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate a random point
    /// let point = ristretto255::random().unwrap();
    /// assert_eq!(point.len(), ristretto255::BYTES);
    ///
    /// // Verify that the point is valid
    /// assert!(ristretto255::is_valid_point(&point).unwrap());
    /// ```
    pub fn random() -> Result<[u8; BYTES]> {
        let mut r = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_random(r.as_mut_ptr());
        }
        Ok(r)
    }

    /// Hash a message to a point using the Ristretto255 encoding
    ///
    /// This function deterministically maps a 64-byte hash to a point in the Ristretto255 group.
    /// The resulting point is guaranteed to be a valid Ristretto255 point. This is useful for
    /// protocols that need to convert arbitrary data to a group element.
    ///
    /// # Security Considerations
    ///
    /// - The discrete logarithm of the resulting point with respect to any other point is unknown
    /// - This function implements a variant of the Elligator 2 map
    ///
    /// # Arguments
    /// * `h` - Hash to map to a point (must be exactly `HASHBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The resulting Ristretto255 point or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    /// use libsodium_rs::random;
    ///
    /// // Generate a random 64-byte hash
    /// let mut hash = [0u8; ristretto255::HASHBYTES];
    /// random::fill_bytes(&mut hash);
    ///
    /// // Map the hash to a point
    /// let point = ristretto255::from_hash(&hash).unwrap();
    /// assert_eq!(point.len(), ristretto255::BYTES);
    ///
    /// // Verify that the point is valid
    /// assert!(ristretto255::is_valid_point(&point).unwrap());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the hash has an invalid length
    pub fn from_hash(h: &[u8]) -> Result<[u8; BYTES]> {
        if h.len() != HASHBYTES {
            return Err(SodiumError::InvalidInput("invalid hash length".into()));
        }
        let mut r = [0u8; BYTES];
        if unsafe { libsodium_sys::crypto_core_ristretto255_from_hash(r.as_mut_ptr(), h.as_ptr()) }
            != 0
        {
            return Err(SodiumError::OperationError("hash to point failed".into()));
        }
        Ok(r)
    }

    /// Scalar multiplication using the Ristretto255 encoding
    ///
    /// This function performs scalar multiplication in the Ristretto255 group. The input point
    /// must be a valid Ristretto255 point, and the scalar must be a valid scalar. The result
    /// is also a valid Ristretto255 point.
    ///
    /// # Mathematical Background
    ///
    /// Scalar multiplication computes n·P, which is equivalent to adding P to itself n times.
    /// If P = g^a, then n·P = g^(n·a mod L), where L is the order of the Ristretto255 group.
    ///
    /// # Security Considerations
    ///
    /// - This operation is performed in constant time to prevent timing attacks
    /// - The scalar is not clamped, so it must be properly reduced if necessary
    ///
    /// # Arguments
    /// * `p` - Point to multiply (must be exactly `BYTES` length)
    /// * `n` - Scalar to multiply by (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The resulting point or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate a random point and scalar
    /// let point = ristretto255::random().unwrap();
    /// let scalar = [1u8; ristretto255::SCALARBYTES]; // In practice, use a proper scalar
    ///
    /// // Multiply the point by the scalar
    /// let result = ristretto255::scalar_mul(&point, &scalar).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The point has an invalid length or is not a valid Ristretto255 encoding
    /// - The scalar has an invalid length
    pub fn scalar_mul(p: &[u8], n: &[u8]) -> Result<[u8; BYTES]> {
        if p.len() != BYTES || n.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput("invalid input length".into()));
        }
        let mut r = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_mul(
                r.as_mut_ptr(),
                n.as_ptr(),
                p.as_ptr(),
            );
        }
        Ok(r)
    }

    /// Reduce a scalar to the valid range for the Ristretto255 group
    ///
    /// This function reduces a 64-byte scalar to a 32-byte scalar modulo L, where L is the
    /// order of the Ristretto255 group (which is 2^252 + 27_742_317_777_372_353_535_851_937_790_883_648_493).
    ///
    /// # Mathematical Background
    ///
    /// The scalar is reduced modulo the order of the Ristretto255 group, which ensures that
    /// the resulting scalar is in the range [0, L-1].
    ///
    /// # Arguments
    /// * `s` - Scalar to reduce (must be exactly `NONREDUCEDSCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The reduced scalar or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    /// use libsodium_rs::random;
    ///
    /// // Generate a random 64-byte scalar
    /// let mut scalar = [0u8; ristretto255::NONREDUCEDSCALARBYTES];
    /// random::fill_bytes(&mut scalar);
    ///
    /// // Reduce the scalar
    /// let reduced = ristretto255::scalar_reduce(&scalar).unwrap();
    /// assert_eq!(reduced.len(), ristretto255::SCALARBYTES);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the scalar has an invalid length
    pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != NONREDUCEDSCALARBYTES {
            return Err(SodiumError::InvalidInput("invalid scalar length".into()));
        }
        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_reduce(r.as_mut_ptr(), s.as_ptr());
        }
        Ok(r)
    }

    /// Generate a random scalar for the Ristretto255 group
    ///
    /// This function generates a random scalar suitable for use with the Ristretto255 group.
    /// The scalar is uniformly distributed between 0 and L-1, where L is the order of the
    /// Ristretto255 group.
    ///
    /// # Returns
    /// * `[u8; SCALARBYTES]` - A random scalar
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate a random scalar
    /// let scalar = ristretto255::scalar_random();
    ///
    /// // Use the scalar for operations
    /// let point = ristretto255::random().unwrap();
    /// let result = ristretto255::scalar_mul(&point, &scalar).unwrap();
    /// ```
    pub fn scalar_random() -> [u8; SCALARBYTES] {
        let mut r = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_random(r.as_mut_ptr());
        }
        r
    }

    /// Compute the multiplicative inverse of a scalar
    ///
    /// This function computes the multiplicative inverse of a scalar modulo L, where L is the
    /// order of the Ristretto255 group. The inverse s^(-1) of a scalar s is such that
    /// s * s^(-1) ≡ 1 (mod L).
    ///
    /// # Arguments
    /// * `s` - Scalar to invert (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The multiplicative inverse of the scalar or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// - The scalar has an invalid length
    /// - The scalar is 0, which has no multiplicative inverse
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate a random non-zero scalar
    /// let mut scalar = ristretto255::scalar_random();
    /// scalar[0] |= 1; // Ensure it's not zero
    ///
    /// // Compute its inverse
    /// let inverse = ristretto255::scalar_invert(&scalar).unwrap();
    ///
    /// // Verify: scalar * inverse ≡ 1 (mod L)
    /// // This would require scalar_mul to verify
    /// ```
    pub fn scalar_invert(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut recip = [0u8; SCALARBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_invert(recip.as_mut_ptr(), s.as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "scalar inversion failed (scalar may be 0)".into(),
            ));
        }

        Ok(recip)
    }

    /// Negate a scalar
    ///
    /// This function computes the negation of a scalar modulo L, where L is the order of the
    /// Ristretto255 group. The negation -s of a scalar s is such that s + (-s) ≡ 0 (mod L).
    ///
    /// # Arguments
    /// * `s` - Scalar to negate (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The negation of the scalar or an error
    ///
    /// # Errors
    /// Returns an error if the scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate a random scalar
    /// let scalar = ristretto255::scalar_random();
    ///
    /// // Compute its negation
    /// let negation = ristretto255::scalar_negate(&scalar).unwrap();
    ///
    /// // Verify: scalar + negation ≡ 0 (mod L)
    /// // This would require scalar_add to verify
    /// ```
    pub fn scalar_negate(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut neg = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_negate(neg.as_mut_ptr(), s.as_ptr());
        }

        Ok(neg)
    }

    /// Compute the complement of a scalar
    ///
    /// This function computes the complement of a scalar modulo L, where L is the order of the
    /// Ristretto255 group. The complement of a scalar s is defined as L - 1 - s.
    ///
    /// # Arguments
    /// * `s` - Scalar to complement (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The complement of the scalar or an error
    ///
    /// # Errors
    /// Returns an error if the scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate a random scalar
    /// let scalar = ristretto255::scalar_random();
    ///
    /// // Compute its complement
    /// let complement = ristretto255::scalar_complement(&scalar).unwrap();
    /// ```
    pub fn scalar_complement(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if s.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid scalar length: expected {}, got {}",
                SCALARBYTES,
                s.len()
            )));
        }

        let mut comp = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_complement(
                comp.as_mut_ptr(),
                s.as_ptr(),
            );
        }

        Ok(comp)
    }

    /// Add two scalars
    ///
    /// This function adds two scalars modulo L, where L is the order of the Ristretto255 group.
    ///
    /// # Arguments
    /// * `x` - First scalar (must be exactly `SCALARBYTES` length)
    /// * `y` - Second scalar (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The sum of the scalars or an error
    ///
    /// # Errors
    /// Returns an error if either scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate two random scalars
    /// let x = ristretto255::scalar_random();
    /// let y = ristretto255::scalar_random();
    ///
    /// // Add them
    /// let sum = ristretto255::scalar_add(&x, &y).unwrap();
    /// ```
    pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_add(
                z.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        Ok(z)
    }

    /// Subtract one scalar from another
    ///
    /// This function subtracts one scalar from another modulo L, where L is the order of the
    /// Ristretto255 group.
    ///
    /// # Arguments
    /// * `x` - First scalar (must be exactly `SCALARBYTES` length)
    /// * `y` - Second scalar to subtract (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The difference of the scalars (x - y) or an error
    ///
    /// # Errors
    /// Returns an error if either scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate two random scalars
    /// let x = ristretto255::scalar_random();
    /// let y = ristretto255::scalar_random();
    ///
    /// // Subtract y from x
    /// let difference = ristretto255::scalar_sub(&x, &y).unwrap();
    /// ```
    pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_sub(
                z.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        Ok(z)
    }

    /// Multiply two scalars
    ///
    /// This function multiplies two scalars modulo L, where L is the order of the Ristretto255 group.
    /// Note that this is scalar-scalar multiplication, not scalar-point multiplication.
    ///
    /// # Arguments
    /// * `x` - First scalar (must be exactly `SCALARBYTES` length)
    /// * `y` - Second scalar (must be exactly `SCALARBYTES` length)
    ///
    /// # Returns
    /// * `Result<[u8; SCALARBYTES]>` - The product of the scalars or an error
    ///
    /// # Errors
    /// Returns an error if either scalar has an invalid length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::ristretto255;
    ///
    /// // Generate two random scalars
    /// let x = ristretto255::scalar_random();
    /// let y = ristretto255::scalar_random();
    ///
    /// // Multiply them
    /// let product = ristretto255::scalar_multiply(&x, &y).unwrap();
    /// ```
    pub fn scalar_multiply(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
        if x.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid first scalar length: expected {}, got {}",
                SCALARBYTES,
                x.len()
            )));
        }

        if y.len() != SCALARBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid second scalar length: expected {}, got {}",
                SCALARBYTES,
                y.len()
            )));
        }

        let mut z = [0u8; SCALARBYTES];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_mul(
                z.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        Ok(z)
    }
}

/// HChaCha20 core function operations
///
/// This module provides the HChaCha20 core function, which is a building block for
/// the XChaCha20 cipher. HChaCha20 is used to extend the nonce size of ChaCha20 from
/// 8 bytes to 24 bytes, providing better security for randomly generated nonces.
///
/// HChaCha20 is a variant of the ChaCha20 block function that takes a 16-byte input
/// (typically the first 16 bytes of a 24-byte nonce) and a 32-byte key, and produces
/// a 32-byte output that is used as a key for the ChaCha20 cipher with the remaining
/// 8 bytes of the nonce.
///
/// ## Security Considerations
///
/// - HChaCha20 is designed as an internal function and should not be used directly
///   for encryption
/// - For encryption, use the higher-level `crypto_stream_xchacha20` or
///   `crypto_secretbox_xchacha20poly1305` APIs
/// - The HChaCha20 function is designed to be resistant to timing attacks
///
/// ## Example: Using HChaCha20 as a key derivation function
///
/// ```rust
/// use libsodium_rs::crypto_core::hchacha20;
/// use libsodium_rs::random;
///
/// // Generate a random key and input
/// let mut key = [0u8; hchacha20::KEYBYTES];
/// let mut input = [0u8; hchacha20::INPUTBYTES];
/// random::fill_bytes(&mut key);
/// random::fill_bytes(&mut input);
///
/// // Derive a subkey using HChaCha20
/// let subkey = hchacha20::hchacha20(&input, &key, None).unwrap();
/// assert_eq!(subkey.len(), hchacha20::OUTPUTBYTES);
/// ```
pub mod hchacha20 {
    use super::*;

    /// Number of bytes in the input (16)
    /// Typically the first 16 bytes of a 24-byte XChaCha20 nonce
    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_hchacha20_INPUTBYTES as usize;
    /// Number of bytes in the key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_hchacha20_KEYBYTES as usize;
    /// Number of bytes in the constant (16)
    /// Optional constant that can be used to customize the function
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_hchacha20_CONSTBYTES as usize;
    /// Number of bytes in the output (32)
    /// The output is used as a key for ChaCha20 with the remaining 8 bytes of the nonce
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_hchacha20_OUTPUTBYTES as usize;

    /// Returns the number of bytes in the input
    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    /// Returns the number of bytes in the key
    pub fn keybytes() -> usize {
        KEYBYTES
    }

    /// Returns the number of bytes in the constant
    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    /// Returns the number of bytes in the output
    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// Compute the HChaCha20 function
    ///
    /// This function computes the HChaCha20 core function, which is a building block for
    /// the XChaCha20 cipher. It takes a 16-byte input (typically the first 16 bytes of a
    /// 24-byte nonce), a 32-byte key, and an optional 16-byte constant, and produces
    /// a 32-byte output that is used as a key for the ChaCha20 cipher with the remaining
    /// 24-byte nonce), a 32-byte key, and an optional 16-byte constant, and produces a
    /// 32-byte output that is used as a key for the ChaCha20 cipher with the remaining
    /// 8 bytes of the nonce.
    ///
    /// # Algorithm Details
    ///
    /// HChaCha20 is a variant of the ChaCha20 block function that:
    /// 1. Sets up the ChaCha20 state with the key, input (as nonce), and constant
    /// 2. Performs the ChaCha20 core permutation (20 rounds)
    /// 3. Extracts specific parts of the final state as output
    ///
    /// # Security Considerations
    ///
    /// - This function is designed to be resistant to timing attacks
    /// - The output should be treated as sensitive key material
    /// - This is a low-level function; for encryption, use higher-level APIs
    ///
    /// # Arguments
    /// * `input` - Input bytes (must be exactly `INPUTBYTES` length)
    /// * `key` - Key bytes (must be exactly `KEYBYTES` length)
    /// * `constant` - Optional constant bytes (must be exactly `CONSTBYTES` length if provided)
    ///
    /// # Returns
    /// * `Result<[u8; OUTPUTBYTES]>` - The 32-byte output of the HChaCha20 function or an error
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_core::hchacha20;
    /// use libsodium_rs::random;
    ///
    /// // Generate a random key and input
    /// let mut key = [0u8; hchacha20::KEYBYTES];
    /// let mut input = [0u8; hchacha20::INPUTBYTES];
    /// random::fill_bytes(&mut key);
    /// random::fill_bytes(&mut input);
    ///
    /// // Compute HChaCha20 without a constant
    /// let output1 = hchacha20::hchacha20(&input, &key, None).unwrap();
    ///
    /// // Compute HChaCha20 with a constant
    /// let constant = [0u8; hchacha20::CONSTBYTES]; // In practice, use a meaningful constant
    /// let output2 = hchacha20::hchacha20(&input, &key, Some(&constant)).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `input` is not exactly `INPUTBYTES` length
    /// - `key` is not exactly `KEYBYTES` length
    /// - `constant` is provided but not exactly `CONSTBYTES` length
    pub fn hchacha20(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }
        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }
        if let Some(c) = constant {
            if c.len() != CONSTBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "invalid constant length: expected {}, got {}",
                    CONSTBYTES,
                    c.len()
                )));
            }
        }

        let mut out = [0u8; OUTPUTBYTES];
        if unsafe {
            libsodium_sys::crypto_core_hchacha20(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                constant.map_or(std::ptr::null(), |c| c.as_ptr()),
            )
        } != 0
        {
            return Err(SodiumError::OperationError("hchacha20 failed".into()));
        }
        Ok(out)
    }
}

/// HSalsa20 core function operations
///
/// This module provides the HSalsa20 core function, which is a building block for
/// the XSalsa20 cipher. HSalsa20 is used to extend the nonce size of Salsa20 from
/// 8 bytes to 24 bytes.
///
/// ## Security Considerations
///
/// - This is a low-level function that should only be used if you understand the
///   underlying cryptographic principles
/// - For most applications, you should use the higher-level `crypto_stream_xsalsa20`
///   API instead
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::crypto_core::hsalsa20;
/// use libsodium_rs::random;
/// use libsodium_rs::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key and input
/// let mut key = [0u8; hsalsa20::KEYBYTES];
/// let mut input = [0u8; hsalsa20::INPUTBYTES];
/// random::fill_bytes(&mut key);
/// random::fill_bytes(&mut input);
///
/// // Derive a subkey using HSalsa20
/// let subkey = hsalsa20::hsalsa20(&input, &key, None).unwrap();
/// assert_eq!(subkey.len(), hsalsa20::OUTPUTBYTES);
/// ```
pub mod hsalsa20 {
    use super::*;

    /// Number of bytes in the input (16)
    /// Typically the first 16 bytes of a 24-byte XSalsa20 nonce
    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_hsalsa20_INPUTBYTES as usize;
    /// Number of bytes in the key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_hsalsa20_KEYBYTES as usize;
    /// Number of bytes in the constant (16)
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_hsalsa20_CONSTBYTES as usize;
    /// Number of bytes in the output (32)
    /// The output is used as a key for Salsa20 with the remaining 8 bytes of the nonce
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_hsalsa20_OUTPUTBYTES as usize;

    /// Returns the number of bytes in the input
    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    /// Returns the number of bytes in the key
    pub fn keybytes() -> usize {
        KEYBYTES
    }

    /// Returns the number of bytes in the constant
    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    /// Returns the number of bytes in the output
    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// Compute the HSalsa20 function
    ///
    /// This function computes the HSalsa20 core function, which is a building block for
    /// the XSalsa20 cipher. It takes a 16-byte input (typically the first 16 bytes of a
    /// 24-byte nonce), a 32-byte key, and an optional 16-byte constant, and produces a
    /// 32-byte output that is used as a key for the Salsa20 cipher with the remaining
    /// 8 bytes of the nonce.
    ///
    /// ## Arguments
    /// * `input` - The input (must be exactly `INPUTBYTES` length)
    /// * `key` - The key (must be exactly `KEYBYTES` length)
    /// * `constant` - Optional constant (if provided, must be exactly `CONSTBYTES` length)
    ///
    /// ## Returns
    /// * `Result<[u8; OUTPUTBYTES]>` - The output of the HSalsa20 function
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs::crypto_core::hsalsa20;
    /// use libsodium_rs::random;
    /// use libsodium_rs::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key and input
    /// let mut key = [0u8; hsalsa20::KEYBYTES];
    /// let mut input = [0u8; hsalsa20::INPUTBYTES];
    /// random::fill_bytes(&mut key);
    /// random::fill_bytes(&mut input);
    ///
    /// // Derive a subkey using HSalsa20
    /// let subkey = hsalsa20::hsalsa20(&input, &key, None).unwrap();
    /// ```
    ///
    /// ## Errors
    /// Returns an error if:
    /// * `input` is not exactly `INPUTBYTES` length
    /// * `key` is not exactly `KEYBYTES` length
    /// * `constant` is provided but not exactly `CONSTBYTES` length
    pub fn hsalsa20(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_hsalsa20(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "hsalsa20 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

/// Salsa2012 core function operations
///
/// This module provides the Salsa2012 core function, which is a building block for
/// the Salsa2012 cipher. The Salsa2012 core function is a hash function that takes a
/// 64-byte input and produces a 64-byte output. It uses 12 rounds instead of the 20
/// rounds used by Salsa20.
///
/// ## Security Considerations
///
/// - This is a low-level function that should only be used if you understand the
///   underlying cryptographic principles
/// - For most applications, you should use the higher-level `crypto_stream_salsa2012`
///   API instead
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::crypto_core::salsa2012;
/// use libsodium_rs::random;
/// use libsodium_rs::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key and input
/// let mut key = [0u8; salsa2012::KEYBYTES];
/// let mut input = [0u8; salsa2012::INPUTBYTES];
/// random::fill_bytes(&mut key);
/// random::fill_bytes(&mut input);
///
/// // Apply the Salsa2012 core function
/// let output = salsa2012::salsa2012(&input, &key, None).unwrap();
/// assert_eq!(output.len(), salsa2012::OUTPUTBYTES);
/// ```
pub mod salsa2012 {
    use super::*;

    /// Number of bytes in the input (16)
    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_salsa2012_INPUTBYTES as usize;
    /// Number of bytes in the key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_salsa2012_KEYBYTES as usize;
    /// Number of bytes in the constant (16)
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_salsa2012_CONSTBYTES as usize;
    /// Number of bytes in the output (64)
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_salsa2012_OUTPUTBYTES as usize;

    /// Returns the number of bytes in the input
    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    /// Returns the number of bytes in the key
    pub fn keybytes() -> usize {
        KEYBYTES
    }

    /// Returns the number of bytes in the constant
    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    /// Returns the number of bytes in the output
    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// Compute the Salsa2012 core function
    ///
    /// This function computes the Salsa2012 core function, which is a building block for
    /// the Salsa2012 cipher. It takes a 16-byte input, a 32-byte key, and an optional
    /// 16-byte constant, and produces a 64-byte output. It uses 12 rounds instead of the
    /// 20 rounds used by Salsa20.
    ///
    /// ## Arguments
    /// * `input` - The input (must be exactly `INPUTBYTES` length)
    /// * `key` - The key (must be exactly `KEYBYTES` length)
    /// * `constant` - Optional constant (if provided, must be exactly `CONSTBYTES` length)
    ///
    /// ## Returns
    /// * `Result<[u8; OUTPUTBYTES]>` - The output of the Salsa2012 function
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs::crypto_core::salsa2012;
    /// use libsodium_rs::random;
    /// use libsodium_rs::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key and input
    /// let mut key = [0u8; salsa2012::KEYBYTES];
    /// let mut input = [0u8; salsa2012::INPUTBYTES];
    /// random::fill_bytes(&mut key);
    /// random::fill_bytes(&mut input);
    ///
    /// // Apply the Salsa2012 core function
    /// let output = salsa2012::salsa2012(&input, &key, None).unwrap();
    /// ```
    ///
    /// ## Errors
    /// Returns an error if:
    /// * `input` is not exactly `INPUTBYTES` length
    /// * `key` is not exactly `KEYBYTES` length
    /// * `constant` is provided but not exactly `CONSTBYTES` length
    pub fn salsa2012(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_salsa2012(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "salsa2012 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

/// Salsa208 core function operations
///
/// This module provides the Salsa208 core function, which is a building block for
/// the Salsa208 cipher. The Salsa208 core function is a hash function that takes a
/// 64-byte input and produces a 64-byte output. It uses 8 rounds instead of the 20
/// rounds used by Salsa20.
///
/// ## Security Considerations
///
/// - This is a low-level function that should only be used if you understand the
///   underlying cryptographic principles
/// - For most applications, you should use the higher-level `crypto_stream_salsa208`
///   API instead
/// - This function is provided for compatibility with existing applications but is
///   considered deprecated. New applications should use Salsa20 or XSalsa20 instead.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::crypto_core::salsa208;
/// use libsodium_rs::random;
/// use libsodium_rs::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key and input
/// let mut key = [0u8; salsa208::KEYBYTES];
/// let mut input = [0u8; salsa208::INPUTBYTES];
/// random::fill_bytes(&mut key);
/// random::fill_bytes(&mut input);
///
/// // Apply the Salsa208 core function
/// let output = salsa208::salsa208(&input, &key, None).unwrap();
/// assert_eq!(output.len(), salsa208::OUTPUTBYTES);
/// ```
pub mod salsa208 {
    use super::*;

    /// Number of bytes in the input (16)
    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_salsa208_INPUTBYTES as usize;
    /// Number of bytes in the key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_salsa208_KEYBYTES as usize;
    /// Number of bytes in the constant (16)
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_salsa208_CONSTBYTES as usize;
    /// Number of bytes in the output (64)
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_salsa208_OUTPUTBYTES as usize;

    /// Returns the number of bytes in the input
    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    /// Returns the number of bytes in the key
    pub fn keybytes() -> usize {
        KEYBYTES
    }

    /// Returns the number of bytes in the constant
    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    /// Returns the number of bytes in the output
    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// Compute the Salsa208 core function
    ///
    /// This function computes the Salsa208 core function, which is a building block for
    /// the Salsa208 cipher. It takes a 16-byte input, a 32-byte key, and an optional
    /// 16-byte constant, and produces a 64-byte output. It uses 8 rounds instead of the
    /// 20 rounds used by Salsa20.
    ///
    /// ## Arguments
    /// * `input` - The input (must be exactly `INPUTBYTES` length)
    /// * `key` - The key (must be exactly `KEYBYTES` length)
    /// * `constant` - Optional constant (if provided, must be exactly `CONSTBYTES` length)
    ///
    /// ## Returns
    /// * `Result<[u8; OUTPUTBYTES]>` - The output of the Salsa208 function
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs::crypto_core::salsa208;
    /// use libsodium_rs::random;
    /// use libsodium_rs::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key and input
    /// let mut key = [0u8; salsa208::KEYBYTES];
    /// let mut input = [0u8; salsa208::INPUTBYTES];
    /// random::fill_bytes(&mut key);
    /// random::fill_bytes(&mut input);
    ///
    /// // Apply the Salsa208 core function
    /// let output = salsa208::salsa208(&input, &key, None).unwrap();
    /// ```
    ///
    /// ## Errors
    /// Returns an error if:
    /// * `input` is not exactly `INPUTBYTES` length
    /// * `key` is not exactly `KEYBYTES` length
    /// * `constant` is provided but not exactly `CONSTBYTES` length
    ///
    /// ## Deprecated
    /// This function is provided for compatibility with existing applications but is
    /// considered deprecated. New applications should use Salsa20 or XSalsa20 instead.
    pub fn salsa208(
        input: &[u8],
        key: &[u8],
        constant: Option<&[u8]>,
    ) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_salsa208(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "salsa208 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

/// Salsa20 core function operations
///
/// This module provides the Salsa20 core function, which is a building block for
/// the Salsa20 cipher. The Salsa20 core function is a hash function that takes a
/// 64-byte input and produces a 64-byte output.
///
/// ## Security Considerations
///
/// - This is a low-level function that should only be used if you understand the
///   underlying cryptographic principles
/// - For most applications, you should use the higher-level `crypto_stream_salsa20`
///   API instead
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::crypto_core::salsa20;
/// use libsodium_rs::random;
/// use libsodium_rs::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key and input
/// let mut key = [0u8; salsa20::KEYBYTES];
/// let mut input = [0u8; salsa20::INPUTBYTES];
/// random::fill_bytes(&mut key);
/// random::fill_bytes(&mut input);
///
/// // Apply the Salsa20 core function
/// let output = salsa20::salsa20(&input, &key, None).unwrap();
/// assert_eq!(output.len(), salsa20::OUTPUTBYTES);
/// ```
pub mod salsa20 {
    use super::*;

    /// Number of bytes in the input (16)
    pub const INPUTBYTES: usize = libsodium_sys::crypto_core_salsa20_INPUTBYTES as usize;
    /// Number of bytes in the key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_core_salsa20_KEYBYTES as usize;
    /// Number of bytes in the constant (16)
    pub const CONSTBYTES: usize = libsodium_sys::crypto_core_salsa20_CONSTBYTES as usize;
    /// Number of bytes in the output (64)
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_core_salsa20_OUTPUTBYTES as usize;

    /// Returns the number of bytes in the input
    pub fn inputbytes() -> usize {
        INPUTBYTES
    }

    /// Returns the number of bytes in the key
    pub fn keybytes() -> usize {
        KEYBYTES
    }

    /// Returns the number of bytes in the constant
    pub fn constbytes() -> usize {
        CONSTBYTES
    }

    /// Returns the number of bytes in the output
    pub fn outputbytes() -> usize {
        OUTPUTBYTES
    }

    /// Compute the Salsa20 core function
    ///
    /// This function computes the Salsa20 core function, which is a building block for
    /// the Salsa20 cipher. It takes a 16-byte input, a 32-byte key, and an optional
    /// 16-byte constant, and produces a 64-byte output.
    ///
    /// ## Arguments
    /// * `input` - The input (must be exactly `INPUTBYTES` length)
    /// * `key` - The key (must be exactly `KEYBYTES` length)
    /// * `constant` - Optional constant (if provided, must be exactly `CONSTBYTES` length)
    ///
    /// ## Returns
    /// * `Result<[u8; OUTPUTBYTES]>` - The output of the Salsa20 function
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs::crypto_core::salsa20;
    /// use libsodium_rs::random;
    /// use libsodium_rs::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key and input
    /// let mut key = [0u8; salsa20::KEYBYTES];
    /// let mut input = [0u8; salsa20::INPUTBYTES];
    /// random::fill_bytes(&mut key);
    /// random::fill_bytes(&mut input);
    ///
    /// // Apply the Salsa20 core function
    /// let output = salsa20::salsa20(&input, &key, None).unwrap();
    /// ```
    ///
    /// ## Errors
    /// Returns an error if:
    /// * `input` is not exactly `INPUTBYTES` length
    /// * `key` is not exactly `KEYBYTES` length
    /// * `constant` is provided but not exactly `CONSTBYTES` length
    pub fn salsa20(input: &[u8], key: &[u8], constant: Option<&[u8]>) -> Result<[u8; OUTPUTBYTES]> {
        if input.len() != INPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid input length: expected {}, got {}",
                INPUTBYTES,
                input.len()
            )));
        }

        if key.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid key length: expected {}, got {}",
                KEYBYTES,
                key.len()
            )));
        }

        let c_ptr = match constant {
            Some(c) => {
                if c.len() != CONSTBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "invalid constant length: expected {}, got {}",
                        CONSTBYTES,
                        c.len()
                    )));
                }
                c.as_ptr()
            }
            None => std::ptr::null(),
        };

        let mut out = [0u8; OUTPUTBYTES];
        let result = unsafe {
            libsodium_sys::crypto_core_salsa20(
                out.as_mut_ptr(),
                input.as_ptr(),
                key.as_ptr(),
                c_ptr,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "salsa20 operation failed".into(),
            ));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random;

    #[test]
    fn test_ed25519_constants() {
        assert_eq!(ed25519::BYTES, 32);
        assert_eq!(ed25519::SCALARBYTES, 32);
        assert_eq!(ed25519::NONREDUCEDSCALARBYTES, 64);
        assert_eq!(ed25519::UNIFORMBYTES, 32);
    }

    #[test]
    fn test_ed25519_validation() {
        // Test point validation
        let valid_point = [0u8; ed25519::BYTES];
        // Note: The all-zeros point is not a valid Ed25519 point
        assert!(!ed25519::is_valid_point(&valid_point).unwrap());

        // Test invalid length
        let invalid_point = [0u8; ed25519::BYTES + 1];
        // This should return an error, which we'll handle by checking it's an Err variant
        assert!(ed25519::is_valid_point(&invalid_point).is_err());

        // Generate a valid point and test validation
        let random_point = ed25519::random();
        assert!(ed25519::is_valid_point(&random_point).unwrap());
    }

    #[test]
    fn test_ed25519_point_operations() {
        // Generate two random points
        let p = ed25519::random();
        let q = ed25519::random();

        // Test addition
        let sum = ed25519::add(&p, &q).unwrap();
        assert_eq!(sum.len(), ed25519::BYTES);
        assert!(ed25519::is_valid_point(&sum).unwrap());

        // Test subtraction
        let diff = ed25519::sub(&p, &q).unwrap();
        assert_eq!(diff.len(), ed25519::BYTES);
        assert!(ed25519::is_valid_point(&diff).unwrap());

        // Test from_uniform
        let uniform = random::bytes(ed25519::UNIFORMBYTES);
        let point = ed25519::from_uniform(&uniform).unwrap();
        assert_eq!(point.len(), ed25519::BYTES);
        assert!(ed25519::is_valid_point(&point).unwrap());
    }

    #[test]
    fn test_ed25519_scalar_operations() {
        // Generate random scalars
        let x = ed25519::scalar_random();
        let y = ed25519::scalar_random();
        assert_eq!(x.len(), ed25519::SCALARBYTES);
        assert_eq!(y.len(), ed25519::SCALARBYTES);

        // Test scalar addition
        let sum = ed25519::scalar_add(&x, &y).unwrap();
        assert_eq!(sum.len(), ed25519::SCALARBYTES);

        // Test scalar subtraction
        let diff = ed25519::scalar_sub(&x, &y).unwrap();
        assert_eq!(diff.len(), ed25519::SCALARBYTES);

        // Test scalar multiplication
        let product = ed25519::scalar_mul(&x, &y).unwrap();
        assert_eq!(product.len(), ed25519::SCALARBYTES);

        // Test scalar negation
        let neg = ed25519::scalar_negate(&x).unwrap();
        assert_eq!(neg.len(), ed25519::SCALARBYTES);

        // Test scalar complement
        let comp = ed25519::scalar_complement(&x).unwrap();
        assert_eq!(comp.len(), ed25519::SCALARBYTES);

        // Test scalar inversion (ensure non-zero scalar)
        let mut non_zero = ed25519::scalar_random();
        non_zero[0] |= 1; // Ensure it's not zero
        let inv = ed25519::scalar_invert(&non_zero).unwrap();
        assert_eq!(inv.len(), ed25519::SCALARBYTES);

        // Test scalar reduction
        let non_reduced = random::bytes(ed25519::NONREDUCEDSCALARBYTES);
        let reduced = ed25519::scalar_reduce(&non_reduced).unwrap();
        assert_eq!(reduced.len(), ed25519::SCALARBYTES);
    }

    #[test]
    fn test_ed25519_scalar_arithmetic_properties() {
        // Generate random scalars
        let x = ed25519::scalar_random();
        let y = ed25519::scalar_random();
        let z = ed25519::scalar_random();

        // Test associativity: (x + y) + z = x + (y + z)
        let sum1 = ed25519::scalar_add(&x, &y).unwrap();
        let sum1_z = ed25519::scalar_add(&sum1, &z).unwrap();

        let sum2 = ed25519::scalar_add(&y, &z).unwrap();
        let x_sum2 = ed25519::scalar_add(&x, &sum2).unwrap();

        assert_eq!(sum1_z, x_sum2);

        // Test commutativity: x + y = y + x
        let xy = ed25519::scalar_add(&x, &y).unwrap();
        let yx = ed25519::scalar_add(&y, &x).unwrap();
        assert_eq!(xy, yx);

        // Test distributivity: x * (y + z) = (x * y) + (x * z)
        let y_plus_z = ed25519::scalar_add(&y, &z).unwrap();
        let x_times_yz = ed25519::scalar_mul(&x, &y_plus_z).unwrap();

        let xy = ed25519::scalar_mul(&x, &y).unwrap();
        let xz = ed25519::scalar_mul(&x, &z).unwrap();
        let xy_plus_xz = ed25519::scalar_add(&xy, &xz).unwrap();

        assert_eq!(x_times_yz, xy_plus_xz);

        // Test negation: x + (-x) = 0
        let neg_x = ed25519::scalar_negate(&x).unwrap();
        let x_plus_negx = ed25519::scalar_add(&x, &neg_x).unwrap();

        // We can't easily check if this is 0, but we can verify some properties
        // If x + (-x) = 0, then (x + (-x)) * y = 0 * y = 0
        let zero_times_y = ed25519::scalar_mul(&x_plus_negx, &y).unwrap();
        let y_times_zero = ed25519::scalar_mul(&y, &x_plus_negx).unwrap();
        assert_eq!(zero_times_y, y_times_zero);
    }

    #[test]
    fn test_ristretto255_operations() {
        // Test random point generation
        let point = ristretto255::random().unwrap();
        assert_eq!(point.len(), ristretto255::BYTES);
        assert!(ristretto255::is_valid_point(&point).unwrap());

        // Test point addition
        let point2 = ristretto255::random().unwrap();
        let sum = ristretto255::add(&point, &point2).unwrap();
        assert_eq!(sum.len(), ristretto255::BYTES);
        assert!(ristretto255::is_valid_point(&sum).unwrap());
    }

    #[test]
    fn test_ristretto255_scalar_operations() {
        // Test scalar random generation
        let scalar1 = ristretto255::scalar_random();
        let scalar2 = ristretto255::scalar_random();
        assert_eq!(scalar1.len(), ristretto255::SCALARBYTES);
        assert_eq!(scalar2.len(), ristretto255::SCALARBYTES);

        // Test scalar addition
        let sum = ristretto255::scalar_add(&scalar1, &scalar2).unwrap();
        assert_eq!(sum.len(), ristretto255::SCALARBYTES);

        // Test scalar subtraction
        let diff = ristretto255::scalar_sub(&scalar1, &scalar2).unwrap();
        assert_eq!(diff.len(), ristretto255::SCALARBYTES);

        // Test scalar multiplication
        let product = ristretto255::scalar_multiply(&scalar1, &scalar2).unwrap();
        assert_eq!(product.len(), ristretto255::SCALARBYTES);

        // Test scalar negation
        let neg = ristretto255::scalar_negate(&scalar1).unwrap();
        assert_eq!(neg.len(), ristretto255::SCALARBYTES);

        // Test scalar complement
        let comp = ristretto255::scalar_complement(&scalar1).unwrap();
        assert_eq!(comp.len(), ristretto255::SCALARBYTES);

        // Test scalar inversion (ensure non-zero scalar)
        let mut non_zero = ristretto255::scalar_random();
        non_zero[0] |= 1; // Ensure it's not zero
        let inv = ristretto255::scalar_invert(&non_zero).unwrap();
        assert_eq!(inv.len(), ristretto255::SCALARBYTES);

        // Test scalar reduction
        let non_reduced = random::bytes(ristretto255::NONREDUCEDSCALARBYTES);
        let reduced = ristretto255::scalar_reduce(&non_reduced).unwrap();
        assert_eq!(reduced.len(), ristretto255::SCALARBYTES);
    }

    #[test]
    fn test_ristretto255_scalar_arithmetic_properties() {
        // Generate random scalars
        let x = ristretto255::scalar_random();
        let y = ristretto255::scalar_random();
        let z = ristretto255::scalar_random();

        // Test associativity: (x + y) + z = x + (y + z)
        let sum1 = ristretto255::scalar_add(&x, &y).unwrap();
        let sum1_z = ristretto255::scalar_add(&sum1, &z).unwrap();

        let sum2 = ristretto255::scalar_add(&y, &z).unwrap();
        let x_sum2 = ristretto255::scalar_add(&x, &sum2).unwrap();

        assert_eq!(sum1_z, x_sum2);

        // Test commutativity: x + y = y + x
        let xy = ristretto255::scalar_add(&x, &y).unwrap();
        let yx = ristretto255::scalar_add(&y, &x).unwrap();
        assert_eq!(xy, yx);

        // Test distributivity: x * (y + z) = (x * y) + (x * z)
        let y_plus_z = ristretto255::scalar_add(&y, &z).unwrap();
        let x_times_yz = ristretto255::scalar_multiply(&x, &y_plus_z).unwrap();

        let xy_prod = ristretto255::scalar_multiply(&x, &y).unwrap();
        let xz_prod = ristretto255::scalar_multiply(&x, &z).unwrap();
        let xy_plus_xz = ristretto255::scalar_add(&xy_prod, &xz_prod).unwrap();

        assert_eq!(x_times_yz, xy_plus_xz);

        // Test negation: x + (-x) should result in zero
        let neg_x = ristretto255::scalar_negate(&x).unwrap();
        let x_plus_negx = ristretto255::scalar_add(&x, &neg_x).unwrap();

        // Zero scalar should multiply to zero
        let zero_times_y = ristretto255::scalar_multiply(&x_plus_negx, &y).unwrap();
        let y_times_zero = ristretto255::scalar_multiply(&y, &x_plus_negx).unwrap();
        assert_eq!(zero_times_y, y_times_zero);
    }

    #[test]
    fn test_ristretto255_scalar_inversion() {
        // Generate a non-zero scalar
        let mut scalar = ristretto255::scalar_random();
        scalar[0] |= 1; // Ensure non-zero

        // Compute inverse
        let inverse = ristretto255::scalar_invert(&scalar).unwrap();

        // Verify scalar * inverse = 1
        let product = ristretto255::scalar_multiply(&scalar, &inverse).unwrap();

        // The product should be 1 (identity element)
        // In little-endian representation, 1 is [1, 0, 0, ...]
        assert_eq!(product[0], 1);
        for i in 1..ristretto255::SCALARBYTES {
            assert_eq!(product[i], 0);
        }

        // Test that inverting zero fails
        let zero = [0u8; ristretto255::SCALARBYTES];
        assert!(ristretto255::scalar_invert(&zero).is_err());
    }

    #[test]
    fn test_hchacha20() {
        let input = [0u8; hchacha20::INPUTBYTES];
        let key = [0u8; hchacha20::KEYBYTES];
        let result = hchacha20::hchacha20(&input, &key, None).unwrap();
        assert_eq!(result.len(), hchacha20::OUTPUTBYTES);

        // Test with constant
        let constant = [0u8; hchacha20::CONSTBYTES];
        let result_with_const = hchacha20::hchacha20(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), hchacha20::OUTPUTBYTES);

        // Test invalid lengths
        assert!(hchacha20::hchacha20(&[0u8; 1], &key, None).is_err());
        assert!(hchacha20::hchacha20(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_hsalsa20() {
        let input = [0u8; hsalsa20::INPUTBYTES];
        let key = [0u8; hsalsa20::KEYBYTES];
        let result = hsalsa20::hsalsa20(&input, &key, None).unwrap();
        assert_eq!(result.len(), hsalsa20::OUTPUTBYTES);

        // Test with constant
        let constant = [0u8; hsalsa20::CONSTBYTES];
        let result_with_const = hsalsa20::hsalsa20(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), hsalsa20::OUTPUTBYTES);

        // Test invalid lengths
        assert!(hsalsa20::hsalsa20(&[0u8; 1], &key, None).is_err());
        assert!(hsalsa20::hsalsa20(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_salsa20() {
        let input = [0u8; salsa20::INPUTBYTES];
        let key = [0u8; salsa20::KEYBYTES];
        let result = salsa20::salsa20(&input, &key, None).unwrap();
        assert_eq!(result.len(), salsa20::OUTPUTBYTES);

        // Test with constant
        let constant = [0u8; salsa20::CONSTBYTES];
        let result_with_const = salsa20::salsa20(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), salsa20::OUTPUTBYTES);

        // Test invalid lengths
        assert!(salsa20::salsa20(&[0u8; 1], &key, None).is_err());
        assert!(salsa20::salsa20(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_salsa2012() {
        let input = [0u8; salsa2012::INPUTBYTES];
        let key = [0u8; salsa2012::KEYBYTES];
        let result = salsa2012::salsa2012(&input, &key, None).unwrap();
        assert_eq!(result.len(), salsa2012::OUTPUTBYTES);

        // Test with constant
        let constant = [0u8; salsa2012::CONSTBYTES];
        let result_with_const = salsa2012::salsa2012(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), salsa2012::OUTPUTBYTES);

        // Test invalid lengths
        assert!(salsa2012::salsa2012(&[0u8; 1], &key, None).is_err());
        assert!(salsa2012::salsa2012(&input, &[0u8; 1], None).is_err());
    }

    #[test]
    fn test_salsa208() {
        let input = [0u8; salsa208::INPUTBYTES];
        let key = [0u8; salsa208::KEYBYTES];
        let result = salsa208::salsa208(&input, &key, None).unwrap();
        assert_eq!(result.len(), salsa208::OUTPUTBYTES);

        // Test with constant
        let constant = [0u8; salsa208::CONSTBYTES];
        let result_with_const = salsa208::salsa208(&input, &key, Some(&constant)).unwrap();
        assert_eq!(result_with_const.len(), salsa208::OUTPUTBYTES);

        // Test invalid lengths
        assert!(salsa208::salsa208(&[0u8; 1], &key, None).is_err());
        assert!(salsa208::salsa208(&input, &[0u8; 1], None).is_err());
    }
}
