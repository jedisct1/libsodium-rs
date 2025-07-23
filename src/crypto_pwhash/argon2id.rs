//! # Argon2id Password Hashing
//!
//! This module provides functions for password hashing and verification using the
//! Argon2id algorithm, which is the recommended variant of Argon2 for most applications.
//!
//! ## About Argon2id
//!
//! Argon2id is a hybrid variant of Argon2 that combines:
//! - The data-dependent memory access of Argon2d (resistant to GPU attacks)
//! - The data-independent memory access of Argon2i (resistant to side-channel attacks)
//!
//! It provides a good balance of security against both types of attacks, making it
//! suitable for most password hashing scenarios. Argon2id was selected as the winner
//! of the Password Hashing Competition in 2015.
//!
//! ## Security Properties
//!
//! - **Memory-hard**: Requires a significant amount of memory to compute, making it
//!   resistant to hardware acceleration attacks
//! - **Time-cost adjustable**: Can be configured to take more or less time to compute
//! - **Parallelism**: Can utilize multiple CPU cores for faster computation
//! - **Side-channel resistance**: First-pass memory access is data-independent to resist
//!   side-channel attacks
//!
//! ## When to Use Argon2id
//!
//! Argon2id is recommended for:
//! - Password storage in databases
//! - Key derivation from passwords for encryption
//! - Any application where passwords need to be securely stored or verified
//!
//! ## Predefined Parameter Sets
//!
//! This module provides three predefined parameter sets:
//! - **Interactive**: For online operations (e.g., web login) with ~1 second computation time
//! - **Moderate**: For operations with moderate security requirements (~0.7s on modern hardware)
//! - **Sensitive**: For highly sensitive operations with ~5 second computation time

use crate::{Result, SodiumError};
use libc;

/// The Argon2id algorithm version 1.3
pub const ALG: i32 = libsodium_sys::crypto_pwhash_argon2id_ALG_ARGON2ID13 as i32;

/// Minimum number of bytes in a derived key (16)
pub const BYTES_MIN: usize = libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize;
/// Maximum number of bytes in a derived key (0x001f_ffff_ffe0, very large)
///
/// Using a hardcoded value since we can't call functions in const contexts
pub const BYTES_MAX: usize = 0x001f_ffff_ffe0; // Value from libsodium
/// Minimum password length in bytes (0)
pub const PASSWD_MIN: usize = libsodium_sys::crypto_pwhash_argon2id_PASSWD_MIN as usize;
/// Maximum password length in bytes (4294967295, very large)
pub const PASSWD_MAX: usize = libsodium_sys::crypto_pwhash_argon2id_PASSWD_MAX as usize;
/// Required salt size in bytes (16)
///
/// The salt should be unique for each password and generated using a
/// cryptographically secure random number generator.
pub const SALTBYTES: usize = libsodium_sys::crypto_pwhash_argon2id_SALTBYTES as usize;
/// Size of the password hash string in bytes (including null terminator)
pub const STRBYTES: usize = libsodium_sys::crypto_pwhash_argon2id_STRBYTES as usize;

/// Minimum operations limit parameter (1)
///
/// This is the absolute minimum number of iterations. In practice, you should use
/// much higher values for security.
pub const OPSLIMIT_MIN: u64 = libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN as u64;
/// Maximum operations limit parameter (4294967295)
pub const OPSLIMIT_MAX: u64 = libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX as u64;
/// Minimum memory limit parameter in bytes (8192)
///
/// This is the absolute minimum memory usage. In practice, you should use
/// much higher values for security.
pub const MEMLIMIT_MIN: usize = libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN as usize;
/// Maximum memory limit parameter in bytes (4398046510080, ~4TB)
///
/// Using a hardcoded value since we can't call functions in const contexts
pub const MEMLIMIT_MAX: usize = 4_398_046_510_080; // Value from libsodium

/// Operations limit for interactive operations (2)
///
/// This parameter is suitable for interactive operations like web authentication,
/// where the computation should complete in about 1 second on modern hardware.
pub const OPSLIMIT_INTERACTIVE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE as u64;
/// Memory limit for interactive operations in bytes (67108864, 64 MB)
///
/// This parameter is suitable for interactive operations like web authentication,
/// where the computation should complete in about 1 second on modern hardware.
pub const MEMLIMIT_INTERACTIVE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE as usize;
/// Operations limit for moderate operations (3)
///
/// This parameter is suitable for operations with moderate security requirements,
/// where the computation should complete in about 0.7 seconds on modern hardware.
pub const OPSLIMIT_MODERATE: u64 = libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MODERATE as u64;
/// Memory limit for moderate operations in bytes (268435456, 256 MB)
///
/// This parameter is suitable for operations with moderate security requirements,
/// where the computation should complete in about 0.7 seconds on modern hardware.
pub const MEMLIMIT_MODERATE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MODERATE as usize;
/// Operations limit for sensitive operations (4)
///
/// This parameter is suitable for highly sensitive operations where security is
/// critical, and the computation may take up to 5 seconds on modern hardware.
pub const OPSLIMIT_SENSITIVE: u64 = libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE as u64;
/// Memory limit for sensitive operations in bytes (1073741824, 1 GB)
///
/// This parameter is suitable for highly sensitive operations where security is
/// critical, and the computation may take up to 5 seconds on modern hardware.
pub const MEMLIMIT_SENSITIVE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE as usize;

/// Derives a key from a password using Argon2id
///
/// This function derives a key of any length from a password and salt using the Argon2id
/// password hashing algorithm. The derived key can be used for encryption or other
/// cryptographic operations.
///
/// ## Security Considerations
///
/// - The derived key's security depends on both the password strength and the hashing parameters
/// - Higher `opslimit` and `memlimit` values provide better security but require more resources
/// - The salt must be unique for each password to prevent precomputation attacks
/// - For sensitive applications, consider using `OPSLIMIT_SENSITIVE` and `MEMLIMIT_SENSITIVE`
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
pub fn pwhash(
    out_len: usize,
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> Result<Vec<u8>> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&out_len) {
        return Err(SodiumError::InvalidInput(format!(
            "output length must be between {BYTES_MIN} and {BYTES_MAX} bytes"
        )));
    }

    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be between {PASSWD_MIN} and {PASSWD_MAX} bytes"
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
        libsodium_sys::crypto_pwhash_argon2id(
            output.as_mut_ptr(),
            out_len as libc::c_ulonglong,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
            salt.as_ptr(),
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
            ALG,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "password hashing failed".into(),
        ));
    }

    Ok(output)
}

/// Creates a password hash string for storage using Argon2id
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
pub fn pwhash_str(password: &[u8], opslimit: u64, memlimit: usize) -> Result<String> {
    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be between {PASSWD_MIN} and {PASSWD_MAX} bytes"
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
        libsodium_sys::crypto_pwhash_argon2id_str(
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

/// Verifies a password against a hash string using Argon2id
///
/// This function verifies that a password matches the password hash stored in a hash string.
/// The hash string is typically generated using the `pwhash_str` function.
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
/// ## Example: Authentication Flow
///
/// ```rust
/// use libsodium_rs::crypto_pwhash::argon2id;
///
/// // In a real application, you would retrieve this from a database
/// let stored_hash = argon2id::pwhash_str(
///     b"user_password",
///     argon2id::OPSLIMIT_INTERACTIVE,
///     argon2id::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // When the user tries to log in, verify their password
/// let user_input = b"user_password";
/// let is_valid = argon2id::pwhash_str_verify(&stored_hash, user_input);
///
/// if is_valid {
///     // Password is correct, user is authenticated
///     
///     // Check if the hash needs to be updated with stronger parameters
///     let needs_rehash = argon2id::pwhash_str_needs_rehash(
///         &stored_hash,
///         argon2id::OPSLIMIT_INTERACTIVE,
///         argon2id::MEMLIMIT_INTERACTIVE
///     );
///     
///     if needs_rehash == Some(true) {
///         // Create a new hash with updated parameters and store it
///         let new_hash = argon2id::pwhash_str(
///             user_input,
///             argon2id::OPSLIMIT_INTERACTIVE,
///             argon2id::MEMLIMIT_INTERACTIVE
///         ).unwrap();
///         
///         // In a real application, you would update the hash in your database
///     }
/// } else {
///     // Password is incorrect, authentication failed
/// }
/// ```
///
/// # Arguments
///
/// * `hash_str` - The password hash string to verify against
/// * `password` - The password to verify
///
/// # Returns
///
/// * `bool` - `true` if the password matches the hash, `false` otherwise
///
/// # Panics
///
/// This function will panic if the password length exceeds `PASSWD_MAX` (which is a very large value).
pub fn pwhash_str_verify(hash_str: &str, password: &[u8]) -> bool {
    assert!(
        password.len() <= PASSWD_MAX,
        "password length must be between {PASSWD_MIN} and {PASSWD_MAX} bytes"
    );

    let result = unsafe {
        libsodium_sys::crypto_pwhash_argon2id_str_verify(
            hash_str.as_ptr() as *const libc::c_char,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
        )
    };

    result == 0
}

/// Checks if a password hash needs to be rehashed using Argon2id
///
/// This function checks if a password hash needs to be rehashed with different parameters.
/// It's useful for upgrading security parameters over time.
///
/// ## Why Rehashing is Important
///
/// Over time, security standards evolve and computational power increases. What was once
/// considered secure may become vulnerable to attacks. Rehashing allows you to:
///
/// - Gradually upgrade all password hashes to use stronger parameters
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
/// ## Example: Upgrading Security Parameters
///
/// ```rust
/// use libsodium_rs::crypto_pwhash::argon2id;
///
/// // In a real application, you would retrieve this from a database
/// let stored_hash = argon2id::pwhash_str(
///     b"user_password",
///     argon2id::OPSLIMIT_INTERACTIVE,
///     argon2id::MEMLIMIT_INTERACTIVE
/// ).unwrap();
///
/// // When a user logs in and their password is verified successfully
/// let user_input = b"user_password";
/// let is_valid = argon2id::pwhash_str_verify(&stored_hash, user_input);
///
/// if is_valid {
///     // Check if we need to upgrade the hash to stronger parameters
///     let target_ops = argon2id::OPSLIMIT_MODERATE; // Stronger parameters
///     let target_mem = argon2id::MEMLIMIT_MODERATE; // Stronger parameters
///     
///     let needs_rehash = argon2id::pwhash_str_needs_rehash(
///         &stored_hash,
///         target_ops,
///         target_mem
///     );
///     
///     if needs_rehash == Some(true) {
///         // Create a new hash with the stronger parameters
///         let new_hash = argon2id::pwhash_str(
///             user_input,
///             target_ops,
///             target_mem
///         ).unwrap();
///         
///         // In a real application, you would update the hash in your database
///     }
/// }
/// ```
///
/// # Arguments
///
/// * `hash_str` - The password hash string to check
/// * `opslimit` - The operations limit parameter to compare against
/// * `memlimit` - The memory limit parameter to compare against
///
/// # Returns
///
/// * `Option<bool>` - `Some(true)` if the hash needs rehashing, `Some(false)` if it doesn't,
///   or `None` if the hash string is invalid
pub fn pwhash_str_needs_rehash(hash_str: &str, opslimit: u64, memlimit: usize) -> Option<bool> {
    let result = unsafe {
        libsodium_sys::crypto_pwhash_argon2id_str_needs_rehash(
            hash_str.as_ptr() as *const libc::c_char,
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
        )
    };

    match result {
        -1 => None,       // Invalid hash string
        0 => Some(false), // No need to rehash
        _ => Some(true),  // Need to rehash
    }
}

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
        )
        .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pwhash_str() {
        let password = b"test password";
        let hash_str = pwhash_str(password, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();

        assert!(pwhash_str_verify(&hash_str, password));
        assert!(!pwhash_str_verify(&hash_str, b"wrong password"));
    }

    #[test]
    fn test_pwhash_str_needs_rehash() {
        let password = b"test password";
        let hash_str = pwhash_str(password, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();

        // Same parameters, shouldn't need rehash
        assert_eq!(
            pwhash_str_needs_rehash(&hash_str, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE),
            Some(false)
        );

        // Different parameters, should need rehash
        assert_eq!(
            pwhash_str_needs_rehash(&hash_str, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE),
            Some(true)
        );
    }
}
