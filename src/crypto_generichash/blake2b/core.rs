//! Core constants and definitions for BLAKE2b
//!
//! This module defines the constants used by the BLAKE2b hash function implementation.
//! BLAKE2b is a cryptographic hash function optimized for 64-bit platforms that
//! produces hash values of any size between 1 and 64 bytes.
//!
//! These constants define the valid ranges for hash output sizes, key sizes, and the
//! sizes of salt and personalization parameters. They are derived directly from the
//! underlying libsodium library.

/// Minimum number of bytes in a hash output (1)
///
/// This is the minimum length of a hash that can be produced by the BLAKE2b hash function.
/// While BLAKE2b technically supports outputs as small as 1 byte, shorter outputs provide
/// less security against collisions and preimage attacks. For most applications, using
/// at least 32 bytes (256 bits) is recommended.
pub const BYTES_MIN: usize = libsodium_sys::crypto_generichash_blake2b_BYTES_MIN as usize;

/// Maximum number of bytes in a hash output (64)
///
/// This is the maximum length of a hash that can be produced by the BLAKE2b hash function.
/// A 64-byte (512-bit) output provides the maximum security level available from BLAKE2b,
/// which is suitable for the most security-critical applications. However, for most
/// applications, the default size of 32 bytes provides sufficient security.
pub const BYTES_MAX: usize = libsodium_sys::crypto_generichash_blake2b_BYTES_MAX as usize;

/// Default number of bytes in a hash output (32)
///
/// This is the recommended length for most applications, providing a good balance
/// between security and size. A 32-byte (256-bit) output provides 128 bits of security
/// against collision attacks, which is considered sufficient for most cryptographic
/// applications today.
///
/// ## Security Considerations
///
/// - 32 bytes (256 bits) provides 128-bit security against collision attacks
/// - This is the same output size as SHA-256
/// - Suitable for most applications, including digital signatures and general-purpose hashing
/// - If you need maximum security (e.g., for long-term security), consider using the maximum
///   output size of 64 bytes
pub const BYTES: usize = libsodium_sys::crypto_generichash_blake2b_BYTES as usize;

/// Minimum number of bytes in a key (0)
///
/// This is the minimum length of a key that can be used for keyed hashing. A key length
/// of 0 effectively means no key is used, resulting in the standard unkeyed hash function.
/// For keyed hashing (MAC functionality), using a key of at least 16-32 bytes is recommended
/// to provide adequate security.
pub const KEYBYTES_MIN: usize = libsodium_sys::crypto_generichash_blake2b_KEYBYTES_MIN as usize;

/// Maximum number of bytes in a key (64)
///
/// This is the maximum length of a key that can be used for keyed hashing. Using the
/// maximum key size provides the highest level of security for MAC operations, though
/// the default key size of 32 bytes is sufficient for most applications. Keys longer
/// than 64 bytes do not provide additional security in BLAKE2b.
pub const KEYBYTES_MAX: usize = libsodium_sys::crypto_generichash_blake2b_KEYBYTES_MAX as usize;

/// Default number of bytes in a key (32)
///
/// This is the recommended key length for most applications, providing a good balance
/// between security and size. A 32-byte (256-bit) key provides 256 bits of security
/// against brute force attacks on the key, which is considered highly secure for
/// current and foreseeable computing capabilities.
///
/// ## Security Considerations
///
/// - 32-byte keys provide 256 bits of security against key-recovery attacks
/// - This is suitable for all common MAC (Message Authentication Code) applications
/// - Keys should be generated using a cryptographically secure random number generator
/// - Keys should be kept secret, unlike salt and personalization parameters
pub const KEYBYTES: usize = libsodium_sys::crypto_generichash_blake2b_KEYBYTES as usize;

/// Size of the BLAKE2b salt in bytes (16)
///
/// The salt is an optional input to the BLAKE2b hash function that can be used
/// to customize the hash output. Unlike the key, the salt does not need to be kept
/// secret and can be public knowledge.
///
/// ## Usage
///
/// - The salt allows creating multiple independent hash functions from the same algorithm
/// - It can be used to mitigate certain types of attacks by creating independent hash instances
/// - Salt values are typically random but can be chosen deterministically for specific applications
/// - Unlike keys, salts do NOT need to be kept secret
///
/// ## Constraints
///
/// - Must be exactly 16 bytes if provided
/// - If not provided, an all-zero salt is used internally
pub const SALTBYTES: usize = libsodium_sys::crypto_generichash_blake2b_SALTBYTES as usize;

/// Size of the BLAKE2b personalization in bytes (16)
///
/// The personalization is an optional input to the BLAKE2b hash function that can be used
/// to customize the hash output for a specific application or context. Like the salt,
/// the personalization string does not need to be kept secret.
///
/// ## Usage
///
/// - Provides domain separation between different applications or contexts
/// - Prevents hash values from one context being used in another context
/// - Typically contains a fixed application-specific string (e.g., "my-app-v1.0")
/// - Helps prevent cross-protocol attacks by ensuring hash values are specific to a context
///
/// ## Constraints
///
/// - Must be exactly 16 bytes if provided
/// - If not provided, an all-zero personalization is used internally
///
/// ## Example
///
/// Different personalization strings can be used to create different hash functions for
/// different purposes within the same application:
///
/// - "my-app-signatures" for digital signature verification
/// - "my-app-file-hash" for file integrity verification
/// - "my-app-password" for password hashing
pub const PERSONALBYTES: usize = libsodium_sys::crypto_generichash_blake2b_PERSONALBYTES as usize;
