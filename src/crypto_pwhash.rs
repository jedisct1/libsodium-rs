//! # Password Hashing (Argon2)
//!
//! This module provides functions for secure password hashing and verification using
//! the Argon2 algorithm (specifically Argon2id by default).
//!
//! ## Overview
//!
//! Password hashing serves two main purposes:
//!
//! 1. **Password storage**: Securely store what it takes to verify a password without
//!    storing the actual password. This protects user credentials in case of a database breach.
//! 2. **Key derivation**: Derive a secret key of any size from a password and salt for
//!    use in encryption or other cryptographic operations.
//!
//! ## Why Use Specialized Password Hashing?
//!
//! Regular cryptographic hash functions (like SHA-256 or BLAKE2) are designed to be fast,
//! which makes them unsuitable for password hashing. Password hashing functions are
//! deliberately slow and memory-intensive to defend against:
//!
//! - **Brute force attacks**: By making each hash attempt costly in terms of time and resources
//! - **Dictionary attacks**: By ensuring even common passwords require significant resources to check
//! - **Rainbow table attacks**: By using unique salts for each password
//! - **Hardware acceleration attacks**: By requiring large amounts of memory, making GPU/ASIC attacks less effective
//!
//! ## Argon2 Algorithm
//!
//! Argon2 is the winner of the Password Hashing Competition (2015) and provides three variants:
//!
//! - **Argon2d**: Provides the highest resistance against GPU cracking attacks but is vulnerable to side-channel attacks
//! - **Argon2i**: Provides resistance against side-channel attacks but is more vulnerable to GPU cracking
//! - **Argon2id** (default): Hybrid approach that combines the security benefits of both Argon2i and Argon2d
//!
//! This module primarily uses Argon2id, which is the recommended variant for most applications.
//! For specialized use cases, Argon2i and scrypt are also available in submodules.
//!
//! ## Security Parameters
//!
//! Argon2 has three main parameters that control its security:
//!
//! 1. **Operations limit (time cost)**: Controls the number of iterations
//! 2. **Memory limit (memory cost)**: Controls the memory usage in bytes
//! 3. **Parallelism degree**: Controls the number of threads (fixed in libsodium)
//!
//! Three predefined security levels are provided:
//!
//! - **Interactive**: For online operations (e.g., web login) with ~1 second computation time
//! - **Moderate**: For operations with moderate security requirements (~0.7s on modern hardware)
//! - **Sensitive**: For highly sensitive operations with ~5 second computation time
//!
//! ## Best Practices
//!
//! - Always use a unique random salt for each password
//! - Store the complete hash string (which includes algorithm, salt, and parameters)
//! - Use `pwhash_str_needs_rehash` to check if passwords need to be rehashed with stronger parameters
//! - For interactive applications, use at least the `OPSLIMIT_INTERACTIVE` and `MEMLIMIT_INTERACTIVE` parameters
//! - For sensitive data, use the `OPSLIMIT_SENSITIVE` and `MEMLIMIT_SENSITIVE` parameters
//! - Never store passwords in plain text, even temporarily
//!
//! ## Example: Key Derivation
//!
//! ```rust
//! use libsodium_rs::crypto_pwhash;
//! use libsodium_rs::random;
//!
//! // Password to hash
//! let password = b"Correct Horse Battery Staple";
//!
//! // Generate a random salt
//! let mut salt = [0u8; crypto_pwhash::SALTBYTES];
//! random::fill_bytes(&mut salt);
//!
//! // Derive a 32-byte key from the password
//! let key = crypto_pwhash::pwhash(
//!     32,
//!     password,
//!     &salt,
//!     crypto_pwhash::OPSLIMIT_INTERACTIVE,
//!     crypto_pwhash::MEMLIMIT_INTERACTIVE,
//!     crypto_pwhash::ALG_DEFAULT
//! ).unwrap();
//!
//! // The key can now be used for encryption or other cryptographic operations
//! ```
//!
//! ## Example: Password Storage
//!
//! ```rust
//! use libsodium_rs::crypto_pwhash;
//!
//! // Password to hash and store
//! let password = b"Correct Horse Battery Staple";
//!
//! // Create a password hash for storage
//! let hash_str = crypto_pwhash::pwhash_str(
//!     password,
//!     crypto_pwhash::OPSLIMIT_INTERACTIVE,
//!     crypto_pwhash::MEMLIMIT_INTERACTIVE
//! ).unwrap();
//!
//! // Later, verify a password against the stored hash
//! let is_valid = crypto_pwhash::pwhash_str_verify(&hash_str, password).unwrap();
//! assert!(is_valid);
//!
//! // Check if the hash needs to be updated (e.g., if security parameters have changed)
//! let needs_rehash = crypto_pwhash::pwhash_str_needs_rehash(
//!     &hash_str,
//!     crypto_pwhash::OPSLIMIT_INTERACTIVE,
//!     crypto_pwhash::MEMLIMIT_INTERACTIVE
//! ).unwrap();
//! ```

use crate::{Result, SodiumError};
use libc;

/// The default algorithm (currently Argon2id)
pub const ALG_DEFAULT: i32 = libsodium_sys::crypto_pwhash_ALG_DEFAULT as i32;
/// The Argon2id algorithm (version 1.3)
pub const ALG_ARGON2ID13: i32 = libsodium_sys::crypto_pwhash_ALG_ARGON2ID13 as i32;
/// The Argon2i algorithm (version 1.3)
pub const ALG_ARGON2I13: i32 = libsodium_sys::crypto_pwhash_ALG_ARGON2I13 as i32;

/// Minimum output bytes for the derived key
pub const BYTES_MIN: usize = libsodium_sys::crypto_pwhash_BYTES_MIN as usize;
/// Maximum output bytes for the derived key (hardcoded value from libsodium)
pub const BYTES_MAX: usize = 0x001f_ffff_ffe0; // Value from libsodium
/// Minimum password length in bytes
pub const PASSWD_MIN: usize = libsodium_sys::crypto_pwhash_PASSWD_MIN as usize;
/// Maximum password length in bytes
pub const PASSWD_MAX: usize = libsodium_sys::crypto_pwhash_PASSWD_MAX as usize;
/// Required salt size in bytes
pub const SALTBYTES: usize = libsodium_sys::crypto_pwhash_SALTBYTES as usize;
/// Size of the string representation of a password hash
pub const STRBYTES: usize = libsodium_sys::crypto_pwhash_STRBYTES as usize;

/// Minimum operations limit parameter
pub const OPSLIMIT_MIN: u64 = libsodium_sys::crypto_pwhash_OPSLIMIT_MIN as u64;
/// Maximum operations limit parameter
pub const OPSLIMIT_MAX: u64 = libsodium_sys::crypto_pwhash_OPSLIMIT_MAX as u64;
/// Minimum memory limit parameter in bytes
pub const MEMLIMIT_MIN: usize = libsodium_sys::crypto_pwhash_MEMLIMIT_MIN as usize;
/// Maximum memory limit parameter in bytes (hardcoded value from libsodium)
pub const MEMLIMIT_MAX: usize = 4_398_046_510_080; // Value from libsodium

/// Operations limit for interactive use (e.g., web login)
pub const OPSLIMIT_INTERACTIVE: u64 = libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64;
/// Memory limit for interactive use in bytes
pub const MEMLIMIT_INTERACTIVE: usize = libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize;
/// Operations limit for moderate security requirements
pub const OPSLIMIT_MODERATE: u64 = libsodium_sys::crypto_pwhash_OPSLIMIT_MODERATE as u64;
/// Memory limit for moderate security requirements in bytes
pub const MEMLIMIT_MODERATE: usize = libsodium_sys::crypto_pwhash_MEMLIMIT_MODERATE as usize;
/// Operations limit for sensitive operations (higher security)
pub const OPSLIMIT_SENSITIVE: u64 = libsodium_sys::crypto_pwhash_OPSLIMIT_SENSITIVE as u64;
/// Memory limit for sensitive operations in bytes (higher security)
pub const MEMLIMIT_SENSITIVE: usize = libsodium_sys::crypto_pwhash_MEMLIMIT_SENSITIVE as usize;

/// Derives a key from a password using Argon2
///
/// This function derives a key of any length from a password and salt using the Argon2
/// password hashing algorithm. The derived key can be used for encryption or other
/// cryptographic operations.
///
/// ## Security Considerations
///
/// - The derived key's security depends on both the password strength and the hashing parameters
/// - Higher `opslimit` and `memlimit` values provide better security but require more resources
/// - The salt must be unique for each password to prevent precomputation attacks
/// - For sensitive applications, consider using `OPSLIMIT_SENSITIVE` and `MEMLIMIT_SENSITIVE`
/// - The default algorithm (Argon2id) provides a good balance of security against various attacks
///
/// ## Use Cases
///
/// - **Encryption keys**: Derive encryption keys from user passwords
/// - **Authentication tokens**: Generate tokens based on user credentials
/// - **File encryption**: Protect files with password-based encryption
/// - **Secure storage**: Derive keys for encrypting sensitive data
///
/// ## Parameters Guidance
///
/// - **Interactive**: Use for login forms and other user-facing applications (~1 second)
/// - **Moderate**: Use for semi-interactive applications where slightly longer delays are acceptable
/// - **Sensitive**: Use for high-security operations where performance is less critical (~5 seconds)
///
/// # Arguments
///
/// * `out_len` - Length of the derived key in bytes (between `BYTES_MIN` and `BYTES_MAX`)
/// * `password` - Password to derive the key from (can be any length up to `PASSWD_MAX`)
/// * `salt` - Salt value (must be exactly `SALTBYTES` bytes, typically random)
/// * `opslimit` - Computational cost parameter (higher is more secure but slower)
/// * `memlimit` - Memory cost parameter in bytes (higher is more secure but uses more memory)
/// * `alg` - Algorithm to use (typically `ALG_DEFAULT` which is Argon2id)
///
/// # Returns
///
/// * `Result<Vec<u8>>` - The derived key of length `out_len` or an error
///
/// # Example
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
/// use libsodium_rs::random;
///
/// // Generate a random salt
/// let mut salt = [0u8; crypto_pwhash::SALTBYTES];
/// random::fill_bytes(&mut salt);
///
/// // Derive a 32-byte key from a password with interactive parameters
/// let key = crypto_pwhash::pwhash(
///     32,
///     b"secure password",
///     &salt,
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE,
///     crypto_pwhash::ALG_DEFAULT
/// ).unwrap();
///
/// // The key can now be used for encryption or other cryptographic operations
/// ```
///
/// ## Example: Using Sensitive Parameters
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
/// use libsodium_rs::random;
///
/// // Generate a random salt
/// let mut salt = [0u8; crypto_pwhash::SALTBYTES];
/// random::fill_bytes(&mut salt);
///
/// // Derive a key with sensitive parameters for high-security applications
/// let key = crypto_pwhash::pwhash(
///     32,
///     b"secure password",
///     &salt,
///     crypto_pwhash::OPSLIMIT_SENSITIVE,
///     crypto_pwhash::MEMLIMIT_SENSITIVE,
///     crypto_pwhash::ALG_DEFAULT
/// ).unwrap();
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - `out_len` is not between `BYTES_MIN` and `BYTES_MAX`
/// - `password` is longer than `PASSWD_MAX`
/// - `salt` is not exactly `SALTBYTES` bytes
/// - `opslimit` is not between `OPSLIMIT_MIN` and `OPSLIMIT_MAX`
/// - `memlimit` is not between `MEMLIMIT_MIN` and `MEMLIMIT_MAX`
/// - The operation fails due to insufficient memory
pub fn pwhash(
    out_len: usize,
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
    alg: i32,
) -> Result<Vec<u8>> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&out_len) {
        return Err(SodiumError::InvalidInput(format!(
            "output length must be between {BYTES_MIN} and {BYTES_MAX} bytes"
        )));
    }

    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be at most {PASSWD_MAX} bytes"
        )));
    }

    if salt.len() != SALTBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "salt must be exactly {SALTBYTES} bytes"
        )));
    }

    if !(OPSLIMIT_MIN..=OPSLIMIT_MAX).contains(&opslimit) {
        return Err(SodiumError::InvalidInput(format!(
            "opslimit must be between {OPSLIMIT_MIN} and {OPSLIMIT_MAX}"
        )));
    }

    if !(MEMLIMIT_MIN..=MEMLIMIT_MAX).contains(&memlimit) {
        return Err(SodiumError::InvalidInput(format!(
            "memlimit must be between {MEMLIMIT_MIN} and {MEMLIMIT_MAX}"
        )));
    }

    let mut output = vec![0u8; out_len];
    let result = unsafe {
        libsodium_sys::crypto_pwhash(
            output.as_mut_ptr(),
            out_len as libc::c_ulonglong,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
            salt.as_ptr(),
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
            alg,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "password hashing failed".into(),
        ));
    }

    Ok(output)
}

/// Creates a password hash string for storage
///
/// This function creates a password hash string that includes the salt, algorithm,
/// and parameters, suitable for storage in a database. The resulting string can later
/// be used with `pwhash_str_verify` to verify passwords.
///
/// ## Hash String Format
///
/// The hash string contains all the information needed for verification:
/// - The algorithm identifier (Argon2id)
/// - The salt (randomly generated)
/// - The operations limit parameter
/// - The memory limit parameter
/// - The derived hash
///
/// This means you don't need to store these parameters separately - they're embedded
/// in the hash string itself.
///
/// ## Security Considerations
///
/// - The hash string already contains a randomly generated salt, so you don't need to generate one
/// - Higher `opslimit` and `memlimit` values provide better security but require more resources
/// - For user authentication, use at least `OPSLIMIT_INTERACTIVE` and `MEMLIMIT_INTERACTIVE`
/// - For highly sensitive passwords, use `OPSLIMIT_SENSITIVE` and `MEMLIMIT_SENSITIVE`
/// - Periodically check if passwords need rehashing using `pwhash_str_needs_rehash`
/// - The hash string can be stored directly in a database - no additional encoding is needed
///
/// # Arguments
///
/// * `password` - Password to hash (can be any length up to `PASSWD_MAX`)
/// * `opslimit` - Computational cost parameter (higher is more secure but slower)
/// * `memlimit` - Memory cost parameter in bytes (higher is more secure but uses more memory)
///
/// # Returns
///
/// * `Result<String>` - The password hash string ready for storage, or an error
///
/// # Example: Creating and Storing a Password Hash
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
///
/// // Create a password hash for storage with interactive parameters
/// let hash_str = crypto_pwhash::pwhash_str(
///     b"secure password",
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // The hash string can be stored in a database
/// // It will look something like: "$argon2id$v=19$m=65536,t=2,p=1$...salt...$...hash..."
/// ```
///
/// ## Example: Creating a Hash with Sensitive Parameters
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
///
/// // Create a password hash with sensitive parameters for high-security applications
/// let hash_str = crypto_pwhash::pwhash_str(
///     b"secure password",
///     crypto_pwhash::OPSLIMIT_SENSITIVE,
///     crypto_pwhash::MEMLIMIT_SENSITIVE
/// ).unwrap();
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - `password` is longer than `PASSWD_MAX`
/// - `opslimit` is not between `OPSLIMIT_MIN` and `OPSLIMIT_MAX`
/// - `memlimit` is not between `MEMLIMIT_MIN` and `MEMLIMIT_MAX`
/// - The operation fails due to insufficient memory
/// - The resulting string is not valid UTF-8
pub fn pwhash_str(password: &[u8], opslimit: u64, memlimit: usize) -> Result<String> {
    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be at most {PASSWD_MAX} bytes"
        )));
    }

    if !(OPSLIMIT_MIN..=OPSLIMIT_MAX).contains(&opslimit) {
        return Err(SodiumError::InvalidInput(format!(
            "opslimit must be between {OPSLIMIT_MIN} and {OPSLIMIT_MAX}"
        )));
    }

    if !(MEMLIMIT_MIN..=MEMLIMIT_MAX).contains(&memlimit) {
        return Err(SodiumError::InvalidInput(format!(
            "memlimit must be between {MEMLIMIT_MIN} and {MEMLIMIT_MAX}"
        )));
    }

    let mut output = vec![0u8; STRBYTES];
    let result = unsafe {
        libsodium_sys::crypto_pwhash_str(
            output.as_mut_ptr() as *mut libc::c_char,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "password hashing failed".into(),
        ));
    }

    // Find the null terminator
    let null_pos = output.iter().position(|&b| b == 0).unwrap_or(output.len());
    output.truncate(null_pos);

    String::from_utf8(output)
        .map_err(|_| SodiumError::OperationError("invalid UTF-8 in hash string".into()))
}

/// Verifies a password against a hash string
///
/// This function verifies if a password matches a hash string created by `pwhash_str`.
/// It extracts the algorithm, salt, and parameters from the hash string and performs
/// the verification.
///
/// ## Security Considerations
///
/// - This function is designed to be constant-time to prevent timing attacks
/// - The verification process automatically uses the parameters stored in the hash string
/// - After successful verification, consider checking if the hash needs rehashing with
///   stronger parameters using `pwhash_str_needs_rehash`
///
/// ## Timing Attacks Protection
///
/// This function is designed to take the same amount of time whether the password is
/// correct or not. This prevents attackers from determining if a password is partially
/// correct based on how quickly the function returns.
///
/// # Arguments
///
/// * `hash_str` - Hash string to verify against (created by `pwhash_str`)
/// * `password` - Password to verify
///
/// # Returns
///
/// * `Result<bool>` - `true` if the password matches, `false` otherwise
///
/// # Example: Basic Password Verification
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
///
/// // Hash a password for storage
/// let hash_str = crypto_pwhash::pwhash_str(
///     b"correct password",
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // Later, verify a password against the stored hash
/// let is_valid = crypto_pwhash::pwhash_str_verify(&hash_str, b"correct password").unwrap();
/// assert!(is_valid);
///
/// // Verify an incorrect password
/// let is_valid = crypto_pwhash::pwhash_str_verify(&hash_str, b"wrong password").unwrap();
/// assert!(!is_valid);
/// ```
///
/// ## Example: Complete Authentication Flow
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
///
/// // In a real application, you would retrieve the hash from a database
/// let stored_hash = crypto_pwhash::pwhash_str(
///     b"user_password",
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // When the user tries to log in, verify their password
/// let user_input = b"user_password";
/// let is_valid = crypto_pwhash::pwhash_str_verify(&stored_hash, user_input).unwrap();
///
/// if is_valid {
///     // Password is correct, user is authenticated
///     
///     // Check if the hash needs to be updated with stronger parameters
///     let needs_rehash = crypto_pwhash::pwhash_str_needs_rehash(
///         &stored_hash,
///         crypto_pwhash::OPSLIMIT_INTERACTIVE,
///         crypto_pwhash::MEMLIMIT_INTERACTIVE
///     ).unwrap();
///     
///     if needs_rehash {
///         // Create a new hash with updated parameters and store it
///         let new_hash = crypto_pwhash::pwhash_str(
///             user_input,
///             crypto_pwhash::OPSLIMIT_INTERACTIVE,
///             crypto_pwhash::MEMLIMIT_INTERACTIVE
///         ).unwrap();
///         
///         // In a real application, you would update the hash in your database
///     }
/// } else {
///     // Password is incorrect, authentication failed
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - `password` is longer than `PASSWD_MAX`
pub fn pwhash_str_verify(hash_str: &str, password: &[u8]) -> Result<bool> {
    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be at most {PASSWD_MAX} bytes"
        )));
    }

    // Create a null-terminated C string for the hash
    let c_hash = std::ffi::CString::new(hash_str)
        .map_err(|_| SodiumError::InvalidInput("hash string contains null bytes".into()))?;

    let result = unsafe {
        libsodium_sys::crypto_pwhash_str_verify(
            c_hash.as_ptr(),
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
        )
    };

    Ok(result == 0)
}

/// Checks if a password hash needs to be rehashed
///
/// This function checks if a password hash needs to be rehashed, which may be necessary if:
/// - The hash was created with different parameters than those provided
/// - The hash uses an older or less secure algorithm
/// - The hash format has been updated
///
/// ## Why Rehashing is Important
///
/// Over time, security standards evolve and computational power increases. What was once
/// considered secure may become vulnerable to attacks. Rehashing allows you to:
///
/// - Gradually upgrade all password hashes to use stronger parameters
/// - Migrate to newer, more secure algorithms as they become available
/// - Ensure all passwords in your system meet current security standards
///
/// ## When to Check for Rehashing
///
/// It's good practice to check if a hash needs rehashing whenever a user successfully
/// authenticates. This allows you to incrementally upgrade security parameters without
/// requiring all users to reset their passwords.
///
/// ## Implementation Strategy
///
/// 1. When a user logs in successfully, check if their password hash needs rehashing
/// 2. If it does, rehash their password with the current parameters
/// 3. Update the stored hash in your database
///
/// # Arguments
/// * `hash_str` - Hash string to check (created by `pwhash_str`)
/// * `opslimit` - Current computational cost parameter to compare against
/// * `memlimit` - Current memory cost parameter to compare against
///
/// # Returns
/// * `Result<bool>` - `true` if the hash needs to be rehashed, `false` otherwise
///
/// # Example: Basic Usage
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
///
/// // Create a password hash with interactive parameters
/// let hash_str = crypto_pwhash::pwhash_str(
///     b"my secure password",
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // Check if the hash needs to be rehashed with the same parameters
/// let needs_rehash = crypto_pwhash::pwhash_str_needs_rehash(
///     &hash_str,
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE
/// ).unwrap();
/// assert!(!needs_rehash); // Should not need rehashing
///
/// // Check if the hash needs to be rehashed with more secure parameters
/// let needs_rehash = crypto_pwhash::pwhash_str_needs_rehash(
///     &hash_str,
///     crypto_pwhash::OPSLIMIT_SENSITIVE,
///     crypto_pwhash::MEMLIMIT_SENSITIVE
/// ).unwrap();
/// assert!(needs_rehash); // Should need rehashing with more secure parameters
/// ```
///
/// ## Example: Complete Rehashing Flow
///
/// ```rust
/// use libsodium_rs::crypto_pwhash;
///
/// // In a real application, you would retrieve this from a database
/// let stored_hash = crypto_pwhash::pwhash_str(
///     b"user_password",
///     crypto_pwhash::OPSLIMIT_INTERACTIVE,
///     crypto_pwhash::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // When a user logs in and their password is verified successfully
/// let user_input = b"user_password";
/// let is_valid = crypto_pwhash::pwhash_str_verify(&stored_hash, user_input).unwrap();
///
/// if is_valid {
///     // Check if we need to upgrade the hash to stronger parameters
///     let target_ops = crypto_pwhash::OPSLIMIT_MODERATE; // Stronger parameters
///     let target_mem = crypto_pwhash::MEMLIMIT_MODERATE; // Stronger parameters
///     
///     let needs_rehash = crypto_pwhash::pwhash_str_needs_rehash(
///         &stored_hash,
///         target_ops,
///         target_mem
///     ).unwrap();
///     
///     if needs_rehash {
///         // Create a new hash with the stronger parameters
///         let new_hash = crypto_pwhash::pwhash_str(
///             user_input,
///             target_ops,
///             target_mem
///         ).unwrap();
///         
///         // In a real application, you would update the hash in your database
///         // database.update_user_hash(user_id, new_hash);
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - `hash_str` is not a valid password hash string
pub fn pwhash_str_needs_rehash(hash_str: &str, opslimit: u64, memlimit: usize) -> Result<bool> {
    let result = unsafe {
        libsodium_sys::crypto_pwhash_str_needs_rehash(
            hash_str.as_ptr() as *const libc::c_char,
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
        )
    };

    if result == -1 {
        return Err(SodiumError::InvalidInput("invalid hash string".into()));
    }

    Ok(result != 0)
}

// Include submodules for specific algorithms
/// Argon2i algorithm implementation (memory-hard, side-channel resistant)
pub mod argon2i;
/// Argon2id algorithm implementation (default, combines Argon2i and Argon2d properties)
pub mod argon2id;
/// Scrypt algorithm implementation (alternative memory-hard function)
pub mod scryptsalsa208sha256;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random;

    #[test]
    fn test_pwhash() {
        let password = b"test password";
        let mut salt = [0u8; SALTBYTES];
        random::fill_bytes(&mut salt);

        let key = pwhash(
            32,
            password,
            &salt,
            OPSLIMIT_INTERACTIVE,
            MEMLIMIT_INTERACTIVE,
            ALG_DEFAULT,
        )
        .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pwhash_str() {
        let password = b"test password";
        let hash_str = pwhash_str(password, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();

        assert!(pwhash_str_verify(&hash_str, password).unwrap());
        assert!(!pwhash_str_verify(&hash_str, b"wrong password").unwrap());
    }

    #[test]
    fn test_pwhash_str_needs_rehash() {
        let password = b"test password";
        let hash_str = pwhash_str(password, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();

        // Same parameters, shouldn't need rehash
        assert!(
            !pwhash_str_needs_rehash(&hash_str, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE,)
                .unwrap()
        );

        // Different parameters, should need rehash
        assert!(
            pwhash_str_needs_rehash(&hash_str, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE,).unwrap()
        );
    }
}
