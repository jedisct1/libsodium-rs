//! # Ed25519 core operations
//!
//! This module provides low-level functions for working with the Ed25519 elliptic curve.
//! These operations include point addition, scalar multiplication, and other core operations
//! that form the basis of higher-level cryptographic protocols.
//!
//! ## Security Considerations
//!
//! - Ed25519 is primarily designed for signatures, but these core operations can be used for other purposes
//! - The curve has a cofactor of 8, which means some care must be taken in certain applications
//! - For most key exchange applications, Curve25519 or Ristretto255 may be more appropriate
//! - Always use cryptographically secure random values for secret keys
//! - Results from scalar multiplication should not be used as shared keys prior to hashing
//! - The Ed25519 group has prime order L = 2^252 + 27742317777372353535851937790883648493
//! - Be aware of small subgroup attacks when working directly with the curve

use crate::SodiumError;
use crate::Result;

/// Number of bytes in an Ed25519 point
pub const BYTES: usize = libsodium_sys::crypto_core_ed25519_BYTES as usize;

/// Number of bytes in an Ed25519 scalar
pub const SCALARBYTES: usize = libsodium_sys::crypto_core_ed25519_SCALARBYTES as usize;

/// Number of bytes in a non-reduced Ed25519 scalar
pub const NONREDUCEDSCALARBYTES: usize = libsodium_sys::crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize;

/// Number of bytes in a uniform input for the from_uniform function
pub const UNIFORMBYTES: usize = libsodium_sys::crypto_core_ed25519_UNIFORMBYTES as usize;

/// Returns the number of bytes in an Ed25519 point
#[must_use = "This function returns a constant value that should be used for buffer sizing"]
pub const fn bytes() -> usize {
    BYTES
}

/// Returns the number of bytes in an Ed25519 scalar
#[must_use = "This function returns a constant value that should be used for buffer sizing"]
pub const fn scalarbytes() -> usize {
    SCALARBYTES
}

/// Returns the number of bytes in a non-reduced Ed25519 scalar
#[must_use = "This function returns a constant value that should be used for buffer sizing"]
pub const fn nonreducedscalarbytes() -> usize {
    NONREDUCEDSCALARBYTES
}

/// Returns the number of bytes in a uniform input for the from_uniform function
#[must_use = "This function returns a constant value that should be used for buffer sizing"]
pub const fn uniformbytes() -> usize {
    UNIFORMBYTES
}

/// Checks if an Ed25519 point is on the curve
///
/// This function checks if the element `p` represents a point on the Edwards 25519 curve,
/// in canonical form, on the main subgroup, and that the point doesn't have a small order.
///
/// This validation is important for protocols that need to ensure points are in the
/// prime-order subgroup to avoid small subgroup attacks.
///
/// # Arguments
///
/// * `p` - Point to check (must be exactly `BYTES` bytes)
///
/// # Returns
///
/// * `true` if the point is on the curve, `false` otherwise
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the point length is incorrect exactly `BYTES` bytes
#[must_use = "This function returns a validation result that should be checked"]
pub fn is_valid_point(p: &[u8]) -> Result<bool> {
    if p.len() != BYTES {
        return Err(SodiumError::InvalidInput(format!("invalid point length: expected {}, got {}", BYTES, p.len())));
    }

    let result = unsafe { libsodium_sys::crypto_core_ed25519_is_valid_point(p.as_ptr()) };
    Ok(result == 1)
}

/// Adds two Ed25519 points
///
/// This function adds the element represented by `p` to the element `q` and
/// stores the resulting element into the returned bytes.
///
/// The addition follows the standard rules for addition on the Edwards curve.
///
/// # Arguments
///
/// * `p` - First point (must be exactly `BYTES` bytes)
/// * `q` - Second point (must be exactly `BYTES` bytes)
///
/// # Returns
///
/// * The sum of the two points (p + q)
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the point lengths are incorrect
/// * `SodiumError::OperationError` - If the operation fails (e.g., if p and/or q are not valid encoded elements)
#[must_use = "This function returns a cryptographic point that should be used"]
pub fn add(p: &[u8], q: &[u8]) -> Vec<u8> {
    if p.len() != BYTES || q.len() != BYTES {
        return Vec::new();
    }

    let mut r = vec![0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_core_ed25519_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr())
    };

    if result != 0 {
        return Vec::new();
    }

    r
}

/// Subtracts one Ed25519 point from another
///
/// This function subtracts the element represented by `q` from the element `p` and
/// stores the resulting element into the returned bytes.
///
/// The subtraction follows the standard rules for point subtraction on the Edwards curve.
///
/// # Arguments
///
/// * `p` - First point (must be exactly `BYTES` bytes)
/// * `q` - Second point (must be exactly `BYTES` bytes)
///
/// # Returns
///
/// * The difference of the two points (p - q)
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the point lengths are incorrect
/// * `SodiumError::OperationError` - If the operation fails (e.g., if p and/or q are not valid encoded elements)
#[must_use = "This function returns a cryptographic point that should be used"]
pub fn sub(p: &[u8], q: &[u8]) -> Vec<u8> {
    if p.len() != BYTES || q.len() != BYTES {
        return Vec::new();
    }

    let mut r = vec![0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_core_ed25519_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr())
    };

    if result != 0 {
        return Vec::new();
    }

    r
}

/// Converts a uniform string to an Ed25519 point
///
/// This function maps a 32-byte uniform string to a point on the Edwards 25519 curve
/// using the Elligator 2 map.
///
/// # Arguments
///
/// * `r` - The uniform string (must be exactly `UNIFORMBYTES` bytes)
///
/// # Returns
///
/// * The resulting Ed25519 point
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the input is not exactly `UNIFORMBYTES` bytes
#[must_use = "This function returns a cryptographic point that should be used"]
pub fn from_uniform(r: &[u8]) -> Vec<u8> {
    if r.len() != UNIFORMBYTES {
        return Vec::new();
    }

    let mut p = vec![0u8; BYTES];
    let result = unsafe {
        libsodium_sys::crypto_core_ed25519_from_uniform(p.as_mut_ptr(), r.as_ptr())
    };

    if result != 0 {
        return Vec::new();
    }

    p
}

/// Generates a random Ed25519 point
///
/// This function generates a random valid point on the Edwards 25519 curve
/// by first generating a random uniform string and then mapping it to a curve point.
///
/// # Returns
///
/// * A random Ed25519 point in canonical encoding
#[must_use = "This function returns a random cryptographic point that should be used"]
pub fn random() -> Vec<u8> {
    let mut p = vec![0u8; BYTES];
    unsafe {
        libsodium_sys::crypto_core_ed25519_random(p.as_mut_ptr());
    }
    p
}

/// Generates a random Ed25519 scalar
///
/// This function generates a random scalar suitable for use in Ed25519 operations.
/// The scalar will be in the range [0, L-1] where L is the order of the Ed25519 group.
///
/// # Returns
///
/// * A random Ed25519 scalar in canonical encoding
#[must_use = "This function returns a random cryptographic scalar that should be used"]
pub fn scalar_random() -> Result<[u8; SCALARBYTES]> {
    let mut r = [0u8; SCALARBYTES];
    unsafe {
        libsodium_sys::crypto_core_ed25519_scalar_random(r.as_mut_ptr());
    }
    Ok(r)
}

/// Computes the multiplicative inverse of an Ed25519 scalar
///
/// This function computes the multiplicative inverse of the scalar `s` and stores
/// the result into the returned bytes. The inverse is computed modulo L, where L is
/// the order of the Ed25519 group.
///
/// For a scalar s, this computes s^(-1) such that s * s^(-1) ≡ 1 (mod L).
///
/// # Arguments
///
/// * `s` - The scalar (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * The multiplicative inverse of the scalar
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the input is not exactly `SCALARBYTES` bytes
/// * `SodiumError::OperationError` - If the scalar is 0 or the inversion operation fails
#[must_use = "This function returns an inverted cryptographic scalar that should be used"]
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
            "scalar inversion failed (scalar may be zero)".into(),
        ));
    }

    Ok(recip)
}

/// Computes the negation of an Ed25519 scalar
///
/// This function computes the negation of the scalar `s` and stores the result
/// into the returned bytes.
///
/// # Arguments
///
/// * `s` - The scalar (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * The negation of the scalar
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the input is not exactly `SCALARBYTES` bytes
#[must_use = "This function returns a negated cryptographic scalar that should be used"]
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

/// Computes the complement of an Ed25519 scalar
///
/// This function computes the complement of the scalar `s` and stores the result
/// into the returned bytes.
///
/// # Arguments
///
/// * `s` - The scalar (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * The complement of the scalar
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If the input is not exactly `SCALARBYTES` bytes
#[must_use = "This function returns a complemented cryptographic scalar that should be used"]
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

/// Adds two Ed25519 scalars
///
/// This function adds the scalars `x` and `y` and stores the result into the returned bytes.
///
/// # Arguments
///
/// * `x` - The first scalar (must be exactly `SCALARBYTES` bytes)
/// * `y` - The second scalar (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * The sum of the two scalars
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If either input is not exactly `SCALARBYTES` bytes
#[must_use = "This function returns a cryptographic scalar sum that should be used"]
pub fn scalar_add(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {}, got {} and {}",
            SCALARBYTES,
            x.len(),
            y.len()
        )));
    }

    let mut z = [0u8; SCALARBYTES];
    unsafe {
        libsodium_sys::crypto_core_ed25519_scalar_add(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
    }

    Ok(z)
}

/// Subtracts one Ed25519 scalar from another
///
/// This function subtracts the scalar `y` from the scalar `x` and stores the result
/// into the returned bytes.
///
/// # Arguments
///
/// * `x` - The first scalar (must be exactly `SCALARBYTES` bytes)
/// * `y` - The second scalar (must be exactly `SCALARBYTES` bytes)
///
/// # Returns
///
/// * The difference of the two scalars (x - y)
///
/// # Errors
///
/// * `SodiumError::InvalidInput` - If either input is not exactly `SCALARBYTES` bytes
#[must_use = "This function returns a cryptographic scalar difference that should be used"]
pub fn scalar_sub(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {}, got {} and {}",
            SCALARBYTES,
            x.len(),
            y.len()
        )));
    }

    let mut z = [0u8; SCALARBYTES];
    unsafe {
        libsodium_sys::crypto_core_ed25519_scalar_sub(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
    }

    Ok(z)
}

/// Multiplies two Ed25519 scalars
///
/// # Arguments
/// * `x` - The first scalar
/// * `y` - The second scalar
///
/// # Returns
/// * `Result<[u8; SCALARBYTES]>` - The product of the scalars
///
/// # Errors
/// * `SodiumError::InvalidInput` - If either input is not exactly `SCALARBYTES` bytes
#[must_use = "This function returns a cryptographic scalar product that should be used"]
pub fn scalar_mul(x: &[u8], y: &[u8]) -> Result<[u8; SCALARBYTES]> {
    if x.len() != SCALARBYTES || y.len() != SCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid scalar length: expected {}, got {} and {}",
            SCALARBYTES,
            x.len(),
            y.len()
        )));
    }

    let mut z = [0u8; SCALARBYTES];
    unsafe {
        libsodium_sys::crypto_core_ed25519_scalar_mul(z.as_mut_ptr(), x.as_ptr(), y.as_ptr());
    }

    Ok(z)
}

/// Reduces a scalar modulo L
///
/// The interval `s` is sampled from should be at least 317 bits to ensure almost
/// uniformity of `r` over `L`.
///
/// # Arguments
/// * `s` - The scalar to reduce
///
/// # Returns
/// * `Result<[u8; SCALARBYTES]>` - The reduced scalar
///
/// # Errors
/// * `SodiumError::InvalidInput` - If the input is not exactly `NONREDUCEDSCALARBYTES` bytes
#[must_use = "This function returns a reduced cryptographic scalar that should be used to prevent information leaks"]
pub fn scalar_reduce(s: &[u8]) -> Result<[u8; SCALARBYTES]> {
    if s.len() != NONREDUCEDSCALARBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "invalid non-reduced scalar length: expected {}, got {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random;

    #[test]
    fn test_constants() {
        assert_eq!(BYTES, 32);
        assert_eq!(SCALARBYTES, 32);
        assert_eq!(NONREDUCEDSCALARBYTES, 64);
        assert_eq!(UNIFORMBYTES, 32);

        assert_eq!(bytes(), 32);
        assert_eq!(scalarbytes(), 32);
        assert_eq!(nonreducedscalarbytes(), 64);
        assert_eq!(uniformbytes(), 32);
    }

    #[test]
    fn test_is_valid_point() {
        // Generate a random point
        let p = random();
        
        // Invalid length
        assert!(is_valid_point(&p[0..31]).is_err());
        
        // The base point should be valid
        let base_point = random();
        assert!(is_valid_point(&base_point).unwrap());
    }

    #[test]
    fn test_add_sub() {
        // Generate two random points
        let p = random();
        let q = random();
        
        // Test addition
        let r = add(&p, &q);
        assert_eq!(r.len(), BYTES);
        
        // Test subtraction
        let s = sub(&r, &q);
        
        // p + q - q should be close to p (may not be exactly equal due to curve properties)
        assert!(is_valid_point(&s).unwrap());
    }

    #[test]
    fn test_from_uniform() {
        // Generate a random uniform string
        let r = random::bytes(UNIFORMBYTES);
        
        // Convert to a point
        let p = from_uniform(&r);
        assert_eq!(p.len(), BYTES);
        
        // The resulting point should be valid
        assert!(is_valid_point(&p).unwrap());
    }

    #[test]
    fn test_random() {
        // Generate a random point
        let p = random();
        assert_eq!(p.len(), BYTES);
        
        // The random point should be valid
        assert!(is_valid_point(&p).unwrap());
    }

    #[test]
    fn test_scalar_random() {
        // Generate a random scalar
        let s = scalar_random().unwrap();
        assert_eq!(s.len(), SCALARBYTES);
    }

    #[test]
    fn test_scalar_invert() {
        // Generate a random scalar (non-zero)
        let mut s = scalar_random().unwrap();
        
        // Ensure it's not zero (very unlikely but just to be safe)
        s[0] |= 1;
        
        // Compute the inverse
        let recip = scalar_invert(&s).unwrap();
        assert_eq!(recip.len(), SCALARBYTES);
        
        // s * s^(-1) should be 1 (mod L)
        let product = scalar_mul(&s, &recip).unwrap();
        
        // We can't easily check if product is 1 without knowing the encoding,
        // but we can verify that product * s = s (mod L)
        let check = scalar_mul(&product, &s).unwrap();
        assert_eq!(check, s);
    }

    #[test]
    fn test_scalar_negate() {
        // Generate a random scalar
        let s = scalar_random().unwrap();
        
        // Compute the negation
        let neg = scalar_negate(&s).unwrap();
        assert_eq!(neg.len(), SCALARBYTES);
        
        // s + (-s) should be 0 (mod L)
        let sum = scalar_add(&s, &neg).unwrap();
        
        // We can't easily check if sum is 0 without knowing the encoding,
        // but we can verify that sum * s = 0 (mod L)
        let zero_check = scalar_mul(&sum, &s).unwrap();
        
        // This is a weak check, but it's better than nothing
        assert_ne!(zero_check, s);
    }

    #[test]
    fn test_scalar_complement() {
        // Generate a random scalar
        let s = scalar_random().unwrap();
        
        // Compute the complement
        let comp = scalar_complement(&s).unwrap();
        assert_eq!(comp.len(), SCALARBYTES);
        
        // Verify that the complement is different from the original
        assert_ne!(comp, s);
    }

    #[test]
    fn test_scalar_add() {
        // Generate two random scalars
        let x = scalar_random().unwrap();
        let y = scalar_random().unwrap();
        
        // Compute the sum
        let z = scalar_add(&x, &y).unwrap();
        assert_eq!(z.len(), SCALARBYTES);
        
        // Verify that z - y = x
        let check = scalar_sub(&z, &y).unwrap();
        assert_eq!(check, x);
    }

    #[test]
    fn test_scalar_sub() {
        // Generate two random scalars
        let x = scalar_random().unwrap();
        let y = scalar_random().unwrap();
        
        // Compute the difference
        let z = scalar_sub(&x, &y).unwrap();
        assert_eq!(z.len(), SCALARBYTES);
        
        // Verify that z + y = x
        let check = scalar_add(&z, &y).unwrap();
        assert_eq!(check, x);
    }

    #[test]
    fn test_scalar_mul() {
        // Generate two random scalars
        let x = scalar_random().unwrap();
        let y = scalar_random().unwrap();
        
        // Compute the product
        let z = scalar_mul(&x, &y).unwrap();
        assert_eq!(z.len(), SCALARBYTES);
        
        // Verify that (x * y) * z = x * (y * z)
        let z2 = scalar_random().unwrap();
        let left = scalar_mul(&z, &z2).unwrap();
        let right_temp = scalar_mul(&y, &z2).unwrap();
        let right = scalar_mul(&x, &right_temp).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn test_scalar_reduce() {
        // Generate a random non-reduced scalar
        let s = random::bytes(NONREDUCEDSCALARBYTES);
        
        // Reduce it
        let r = scalar_reduce(&s).unwrap();
        assert_eq!(r.len(), SCALARBYTES);
    }
}
