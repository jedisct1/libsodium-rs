//! # Key Derivation Functions
//!
//! This module provides key derivation functions (KDFs) that can be used to derive
//! multiple subkeys from a single master key. This is useful for deriving different
//! keys for different purposes (e.g., encryption, authentication) from a single master key.
//!
//! ## What is a Key Derivation Function?
//!
//! A key derivation function (KDF) is a cryptographic algorithm that derives one or more
//! secret keys from a master key. KDFs are designed to be computationally intensive and
//! resistant to various cryptographic attacks, ensuring that derived keys maintain high
//! security properties.
//!
//! ## Key Properties of KDFs
//!
//! - **Deterministic**: The same inputs always produce the same outputs
//! - **Collision-resistant**: It's computationally infeasible to find two different inputs that produce the same output
//! - **Pseudorandom**: Output keys appear random and are statistically independent from each other
//! - **Domain separation**: Different subkey IDs produce independent keys
//! - **Context binding**: Keys are bound to specific application contexts
//!
//! ## Available KDF Algorithms
//!
//! - **Default KDF**: Based on the BLAKE2b hash function (same as `blake2b` submodule)
//! - **`blake2b`**: Explicitly uses the BLAKE2b hash function, which is optimized for 64-bit platforms and provides
//!   excellent security and performance
//! - **`hkdf_sha256`**: HMAC-based Key Derivation Function using SHA-256, suitable for environments where
//!   BLAKE2b might not be available or when SHA-256 is specifically required
//! - **`hkdf_sha512`**: HMAC-based Key Derivation Function using SHA-512, offering increased security
//!   margin at the cost of slightly lower performance
//!
//! ## Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_kdf;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a master key
//! let master_key = crypto_kdf::Key::generate().unwrap();
//!
//! // Define a context for the key derivation
//! // Must be exactly CONTEXTBYTES (8) bytes
//! let context = b"MyAppV01"; // Application-specific context
//!
//! // Derive different subkeys for different purposes
//! let encryption_key = crypto_kdf::derive_from_key(32, 1, context, &master_key).expect("Failed to derive encryption key");
//! let authentication_key = crypto_kdf::derive_from_key(32, 2, context, &master_key).expect("Failed to derive authentication key");
//! let database_key = crypto_kdf::derive_from_key(32, 3, context, &master_key).expect("Failed to derive database key");
//!
//! // Each subkey is unique and independent
//! assert_ne!(encryption_key, authentication_key);
//! assert_ne!(encryption_key, database_key);
//! assert_ne!(authentication_key, database_key);
//! ```
//!
//! ## Security Considerations
//!
//! - **Master Key Protection**: The master key should be kept secret and securely stored.
//!   Compromise of the master key compromises all derived subkeys.
//!
//! - **Subkey ID Uniqueness**: Each subkey ID should be unique within the application.
//!   Reusing IDs with the same master key and context will produce identical subkeys.
//!
//! - **Context Uniqueness**: The context should be unique to the application to prevent
//!   key reuse across applications. This provides domain separation between different
//!   applications or protocol versions.
//!
//! - **Subkey Independence**: Subkeys derived from the same master key with different IDs
//!   are cryptographically independent. Knowledge of one subkey does not reveal information
//!   about other subkeys or the master key.
//!
//! - **Algorithm Selection**: The default BLAKE2b-based KDF is suitable for most applications,
//!   but specialized KDFs are available in the submodules for specific requirements or
//!   compliance needs.
//!
//! - **Deterministic Derivation**: The KDF is deterministic - the same inputs will always
//!   produce the same subkey. This allows keys to be rederived when needed rather than stored.
//!
//! - **Attack Resistance**: The BLAKE2b-based KDF is resistant to length extension attacks
//!   and other common cryptographic vulnerabilities.
//!
//! - **Key Length Selection**: The subkey length should be appropriate for the intended use
//!   (e.g., AES-256 keys should be 32 bytes, Ed25519 keys should be 32 bytes).
//!
//! - **Forward Secrecy**: KDFs do not provide forward secrecy by themselves. If this property
//!   is required, consider using additional key exchange protocols.

use crate::{Result, SodiumError};
use libc;

/// Minimum number of bytes in a derived subkey (16)
///
/// This is the minimum length of a subkey that can be derived using the KDF.
pub const BYTES_MIN: usize = libsodium_sys::crypto_kdf_BYTES_MIN as usize;

/// Maximum number of bytes in a derived subkey (64)
///
/// This is the maximum length of a subkey that can be derived using the KDF.
pub const BYTES_MAX: usize = libsodium_sys::crypto_kdf_BYTES_MAX as usize;

/// Number of bytes in a context (8)
///
/// The context is a fixed-size bytes that should be unique to the application.
/// It helps ensure that subkeys derived in different contexts are independent.
pub const CONTEXTBYTES: usize = libsodium_sys::crypto_kdf_CONTEXTBYTES as usize;

/// Number of bytes in a master key (32)
///
/// The master key is used to derive subkeys and should be kept secret.
pub const KEYBYTES: usize = libsodium_sys::crypto_kdf_KEYBYTES as usize;

/// A master key for the key derivation function
///
/// This key is used to derive multiple subkeys for different purposes.
/// It must be exactly 32 bytes (256 bits) long and should be generated
/// using a cryptographically secure random number generator.
///
/// ## Security Properties
///
/// - **High entropy**: Contains 256 bits of entropy when generated properly
/// - **Secret**: Must be kept confidential to maintain security of all derived subkeys
/// - **Single source of truth**: Allows multiple application-specific keys to be derived
///   from a single master key
///
/// ## Best Practices
///
/// - Generate using the `generate()` method, which uses libsodium's secure RNG
/// - Store securely, preferably in a hardware security module or secure enclave
/// - Rotate periodically according to your security policy
/// - Consider using a key management service for production applications
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_kdf;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a master key
/// let master_key = crypto_kdf::Key::generate().unwrap();
///
/// // Or create from existing bytes
/// let key_bytes = [0x42; crypto_kdf::KEYBYTES]; // Example bytes
/// let master_key = crypto_kdf::Key::from_slice(&key_bytes).unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = crate::SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        if slice.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {KEYBYTES} bytes"
            )));
        }
        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(slice);
        Ok(Key(key))
    }
}

impl From<[u8; KEYBYTES]> for Key {
    fn from(bytes: [u8; KEYBYTES]) -> Self {
        Key(bytes)
    }
}

impl From<Key> for [u8; KEYBYTES] {
    fn from(key: Key) -> Self {
        key.0
    }
}

impl Key {
    /// Generates a new random key for key derivation
    ///
    /// This function generates a new random master key suitable for deriving subkeys.
    /// The key is generated using libsodium's secure random number generator.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kdf;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a master key
    /// let master_key = crypto_kdf::Key::generate().unwrap();
    /// ```
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new randomly generated key or an error
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_kdf_keygen(key.as_mut_ptr());
        }
        Ok(Key(key))
    }

    /// Creates a key from an existing byte slice
    ///
    /// This function creates a master key from an existing byte slice.
    /// The slice must be exactly `KEYBYTES` (32) bytes long.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kdf;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a key from existing bytes
    /// let key_bytes = [0x42; crypto_kdf::KEYBYTES]; // Example bytes
    /// let master_key = crypto_kdf::Key::from_slice(&key_bytes).unwrap();
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `slice` - Byte slice of exactly `KEYBYTES` length
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new key created from the slice or an error
    ///
    /// ## Errors
    ///
    /// Returns an error if the slice is not exactly `KEYBYTES` bytes long
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {KEYBYTES} bytes"
            )));
        }
        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(slice);
        Ok(Key(key))
    }

    /// Returns a reference to the key as a byte slice
    ///
    /// This function returns a reference to the internal byte representation of the key.
    /// This is useful when you need to pass the key to other functions.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kdf;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a master key
    /// let master_key = crypto_kdf::Key::generate().unwrap();
    ///
    /// // Get the bytes of the key
    /// let key_bytes = master_key.as_bytes();
    /// assert_eq!(key_bytes.len(), crypto_kdf::KEYBYTES);
    /// ```
    ///
    /// ## Returns
    ///
    /// * `&[u8]` - Reference to the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Derives a subkey from a master key
///
/// This function derives a subkey of the specified length from a master key.
/// The subkey is derived using the BLAKE2b hash function with the master key,
/// subkey ID, and context as inputs.
///
/// ## Algorithm Details
///
/// The derivation process uses BLAKE2b-512 with the following inputs:
/// - The master key is used as the BLAKE2b key
/// - The subkey ID is encoded as a 64-bit little-endian integer
/// - The context is a fixed-size 8-byte string
/// - The output is truncated to the requested subkey length
///
/// This construction ensures that subkeys derived with different IDs or contexts
/// are independent, even if derived from the same master key.
///
/// The derivation process is deterministic - the same inputs will always produce
/// the same subkey. This allows applications to regenerate the same subkeys
/// as long as they have access to the master key.
///
/// ## Algorithm Details
///
/// The subkey derivation works as follows:
/// 1. Initialize a BLAKE2b hash state with the master key
/// 2. Update the hash state with the context and subkey ID
/// 3. Finalize the hash to produce the subkey
///
/// ## Security Considerations
///
/// - Each subkey ID should be unique within the application
/// - The context should be unique to the application to prevent key reuse
/// - Subkeys derived with different IDs are independent
/// - The subkey length must be between `BYTES_MIN` and `BYTES_MAX`
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_kdf;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a master key
/// let master_key = crypto_kdf::Key::generate().unwrap();
///
/// // Define a context for the key derivation
/// let context = b"MyAppV01"; // Must be exactly CONTEXTBYTES (8) bytes
///
/// // Derive different subkeys for different purposes
/// let encryption_key = crypto_kdf::derive_from_key(32, 1, context, &master_key).expect("Failed to derive encryption key");
/// let authentication_key = crypto_kdf::derive_from_key(32, 2, context, &master_key).expect("Failed to derive authentication key");
///
/// // Each subkey is unique and independent
/// assert_ne!(encryption_key, authentication_key);
/// ```
///
/// # Arguments
///
/// * `subkey_len` - Length of the subkey to derive (must be between `BYTES_MIN` and `BYTES_MAX`)
/// * `subkey_id` - Identifier for the subkey (should be unique for each purpose)
///   This is a 64-bit integer that distinguishes different subkeys derived from the same master key
/// * `context` - Application-specific context (must be exactly `CONTEXTBYTES` bytes)
///   This is an 8-byte identifier that should be unique to your application to prevent key reuse
/// * `master_key` - Master key used to derive the subkey from
///
/// ## Returns
///
/// * `Result<Vec<u8>>` - The derived subkey or an error
///
pub fn derive_from_key(
    subkey_len: usize,
    subkey_id: u64,
    context: &[u8],
    master_key: &Key,
) -> Result<Vec<u8>> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&subkey_len) {
        return Err(SodiumError::InvalidInput(format!(
            "subkey length must be between {BYTES_MIN} and {BYTES_MAX}"
        )));
    }

    if context.len() != CONTEXTBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "context must be exactly {CONTEXTBYTES} bytes"
        )));
    }

    let mut subkey = vec![0u8; subkey_len];

    let result = unsafe {
        libsodium_sys::crypto_kdf_derive_from_key(
            subkey.as_mut_ptr(),
            subkey_len as libc::size_t,
            subkey_id,
            context.as_ptr() as *const libc::c_char,
            master_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("key derivation failed".into()));
    }

    Ok(subkey)
}

/// Key derivation functions based on the BLAKE2b hash function
///
/// This submodule provides key derivation functions that explicitly use the BLAKE2b
/// hash function. The default KDF in the parent module also uses BLAKE2b, so this
/// submodule is provided for explicitness and clarity.
///
/// ## About BLAKE2b
///
/// BLAKE2b is a cryptographic hash function optimized for 64-bit platforms that offers
/// excellent security and performance. It was designed as a replacement for MD5 and SHA-1,
/// and has several advantages over SHA-2 and SHA-3:
///
/// - Faster than MD5, SHA-1, SHA-2, and SHA-3 on modern 64-bit platforms
/// - Resistant to length extension attacks
/// - Supports keyed mode (BLAKE2b can be used as a MAC)
/// - Supports personalization strings and salts
/// - Simple design with thorough security analysis
///
/// ## When to Use This Module
///
/// Use this module when you want to be explicit about which KDF algorithm you're using,
/// or when you need to document that your application specifically relies on BLAKE2b
/// properties. Functionally, it's identical to the parent module's KDF.
///
/// BLAKE2b is a cryptographically secure hash function that is designed to be
/// fast and resistant to various cryptographic attacks. It is suitable for
/// deriving keys for a wide range of applications.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_kdf::blake2b;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a master key
/// let master_key = blake2b::Key::generate().unwrap();
///
/// // Define a context for the key derivation
/// let context = b"MyAppV01"; // Must be exactly CONTEXTBYTES (8) bytes
///
/// // Derive a subkey
/// let subkey = blake2b::derive_from_key(32, 1, context, &master_key).unwrap();
/// ```
pub mod blake2b {
    use super::*;

    /// Minimum number of bytes in a derived subkey (16)
    pub const BYTES_MIN: usize = libsodium_sys::crypto_kdf_blake2b_BYTES_MIN as usize;
    /// Maximum number of bytes in a derived subkey (64)
    pub const BYTES_MAX: usize = libsodium_sys::crypto_kdf_blake2b_BYTES_MAX as usize;
    /// Number of bytes in a context (8)
    pub const CONTEXTBYTES: usize = libsodium_sys::crypto_kdf_blake2b_CONTEXTBYTES as usize;
    /// Number of bytes in a master key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_kdf_blake2b_KEYBYTES as usize;

    /// A master key for the BLAKE2b key derivation function
    ///
    /// This key is used to derive multiple subkeys using the BLAKE2b hash function.
    /// It should be generated using a secure random number generator and kept secret.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kdf::blake2b;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a master key
    /// let master_key = blake2b::Key::generate().unwrap();
    /// ```
    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Key([u8; KEYBYTES]);

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl TryFrom<&[u8]> for Key {
        type Error = crate::SodiumError;

        fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
            if slice.len() != KEYBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "key must be exactly {KEYBYTES} bytes"
                )));
            }
            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(slice);
            Ok(Key(key))
        }
    }

    impl From<[u8; KEYBYTES]> for Key {
        fn from(bytes: [u8; KEYBYTES]) -> Self {
            Key(bytes)
        }
    }

    impl From<Key> for [u8; KEYBYTES] {
        fn from(key: Key) -> Self {
            key.0
        }
    }

    impl Key {
        /// Generates a new random key
        pub fn generate() -> Result<Self> {
            let mut key = [0u8; KEYBYTES];
            unsafe {
                // Use the generic keygen function as the specific one isn't available
                libsodium_sys::crypto_kdf_keygen(key.as_mut_ptr());
            }
            Ok(Key(key))
        }

        /// Creates a key from a byte slice
        pub fn from_slice(slice: &[u8]) -> Result<Self> {
            if slice.len() != KEYBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "key must be exactly {KEYBYTES} bytes"
                )));
            }
            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(slice);
            Ok(Key(key))
        }

        /// Returns a reference to the key as a byte slice
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// Derives a subkey from a master key using BLAKE2b
    ///
    /// This function derives a subkey of the specified length from a master key
    /// using the BLAKE2b hash function. The subkey is derived using the master key,
    /// subkey ID, and context as inputs.
    ///
    /// ## Algorithm Details
    ///
    /// The subkey derivation works as follows:
    /// 1. Initialize a BLAKE2b hash state with the master key
    /// 2. Update the hash state with the context and subkey ID
    /// 3. Finalize the hash to produce the subkey
    ///
    /// ## Security Considerations
    ///
    /// - Each subkey ID should be unique within the application
    /// - The context should be unique to the application to prevent key reuse
    /// - Subkeys derived with different IDs are independent
    /// - The subkey length must be between `BYTES_MIN` and `BYTES_MAX`
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kdf::blake2b;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a master key
    /// let master_key = blake2b::Key::generate().unwrap();
    ///
    /// // Define a context for the key derivation
    /// let context = b"MyAppV01"; // Must be exactly CONTEXTBYTES (8) bytes
    ///
    /// // Derive different subkeys for different purposes
    /// let encryption_key = blake2b::derive_from_key(32, 1, context, &master_key).unwrap();
    /// let authentication_key = blake2b::derive_from_key(32, 2, context, &master_key).unwrap();
    ///
    /// // Each subkey is unique and independent
    /// assert_ne!(encryption_key, authentication_key);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `subkey_len` - Length of the subkey to derive (must be between `BYTES_MIN` and `BYTES_MAX`)
    /// * `subkey_id` - Identifier for the subkey (should be unique for each purpose)
    ///   This is a 64-bit integer that distinguishes different subkeys derived from the same master key
    /// * `context` - Application-specific context (must be exactly `CONTEXTBYTES` bytes)
    ///   This is an 8-byte identifier that should be unique to your application to prevent key reuse
    /// * `master_key` - Master key used to derive the subkey from
    ///
    /// ## Returns
    ///
    /// * `Result<Vec<u8>>` - The derived subkey or an error
    ///
    pub fn derive_from_key(
        subkey_len: usize,
        subkey_id: u64,
        context: &[u8],
        master_key: &Key,
    ) -> Result<Vec<u8>> {
        if !(BYTES_MIN..=BYTES_MAX).contains(&subkey_len) {
            return Err(SodiumError::InvalidInput(format!(
                "subkey length must be between {BYTES_MIN} and {BYTES_MAX} bytes"
            )));
        }

        if context.len() != CONTEXTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "context must be exactly {CONTEXTBYTES} bytes"
            )));
        }

        let mut subkey = vec![0u8; subkey_len];
        let result = unsafe {
            libsodium_sys::crypto_kdf_blake2b_derive_from_key(
                subkey.as_mut_ptr(),
                subkey_len as libc::size_t,
                subkey_id as libc::c_ulonglong,
                context.as_ptr() as *const libc::c_char,
                master_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError("key derivation failed".into()));
        }

        Ok(subkey)
    }
}

/// HMAC-based Key Derivation Function (HKDF)
///
/// This module provides an implementation of HKDF as defined in RFC 5869,
/// which is a key derivation function based on HMAC. It can be used to derive
/// multiple keys from a single input key material.
///
/// HKDF is a two-step process:
/// 1. Extract: Derive a pseudorandom key (PRK) from the input key material and salt
/// 2. Expand: Expand the PRK to the desired output length using the info parameter
///
/// This module provides implementations for both SHA-256 and SHA-512 variants of HKDF.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::crypto_kdf::hkdf;
///
/// // Generate a random PRK
/// let prk = hkdf::sha256::keygen();
///
/// // Input key material and salt
/// let ikm = b"input key material";
/// let salt = Some(b"salt".as_ref());
///
/// // Extract a pseudorandom key
/// let prk = hkdf::sha256::extract(salt, ikm).unwrap();
///
/// // Expand the key with a context
/// let context = Some(b"context info".as_ref());
/// let out_len = 32;
/// let output = hkdf::sha256::expand(out_len, context, &prk).unwrap();
/// ```
pub mod hkdf {
    use super::*;

    /// HMAC-based Key Derivation Function using SHA-256
    ///
    /// This submodule provides key derivation functions based on HKDF with SHA-256.
    ///
    /// HKDF-SHA256 is suitable for deriving keys from input key material with
    /// cryptographic strength. The extract function produces a pseudorandom key of
    /// 32 bytes, which can then be expanded to any desired length.
    pub mod sha256 {
        use super::*;

        /// Maximum number of bytes in a derived subkey (255 * 32 = 8160)
        pub const BYTES_MAX: usize = libsodium_sys::crypto_kdf_hkdf_sha256_BYTES_MAX as usize;
        /// Minimum number of bytes in a derived subkey (0)
        pub const BYTES_MIN: usize = libsodium_sys::crypto_kdf_hkdf_sha256_BYTES_MIN as usize;
        /// Number of bytes in the PRK (32)
        pub const KEYBYTES: usize = libsodium_sys::crypto_kdf_hkdf_sha256_KEYBYTES as usize;

        /// A pseudorandom key (PRK) for HKDF-SHA-256
        ///
        /// This structure represents the output of the extract step of HKDF-SHA-256.
        /// It can be used as input to the expand step to derive multiple keys.
        #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
        pub struct Prk([u8; KEYBYTES]);

        impl AsRef<[u8]> for Prk {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for Prk {
            type Error = crate::SodiumError;

            fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
                if slice.len() != KEYBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "PRK must be exactly {KEYBYTES} bytes"
                    )));
                }
                let mut prk = [0u8; KEYBYTES];
                prk.copy_from_slice(slice);
                Ok(Prk(prk))
            }
        }

        impl From<[u8; KEYBYTES]> for Prk {
            fn from(bytes: [u8; KEYBYTES]) -> Self {
                Prk(bytes)
            }
        }

        impl From<Prk> for [u8; KEYBYTES] {
            fn from(prk: Prk) -> Self {
                prk.0
            }
        }

        impl Prk {
            /// Returns a reference to the PRK as a byte slice
            ///
            /// # Returns
            ///
            /// * `&[u8; KEYBYTES]` - Reference to the PRK bytes
            pub fn as_bytes(&self) -> &[u8; KEYBYTES] {
                &self.0
            }

            /// Creates a PRK from a byte slice
            ///
            /// # Arguments
            ///
            /// * `slice` - Byte slice to create the PRK from
            ///
            /// # Returns
            ///
            /// * `Result<Self>` - A new PRK created from the slice or an error
            ///
            /// # Errors
            ///
            /// Returns an error if the slice is not exactly `KEYBYTES` bytes long
            pub fn from_slice(slice: &[u8]) -> Result<Self> {
                if slice.len() != KEYBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "PRK must be exactly {KEYBYTES} bytes"
                    )));
                }

                let mut prk = [0u8; KEYBYTES];
                prk.copy_from_slice(slice);
                Ok(Self(prk))
            }
        }
        /// Size of the state structure in bytes
        pub fn statebytes() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha256_statebytes() as usize }
        }

        /// Returns the number of bytes in the PRK (32)
        pub fn keybytes() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha256_keybytes() as usize }
        }

        /// Returns the minimum number of bytes in a derived subkey (0)
        pub fn bytes_min() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha256_bytes_min() as usize }
        }

        /// Returns the maximum number of bytes in a derived subkey (255 * 32 = 8160)
        pub fn bytes_max() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha256_bytes_max() as usize }
        }

        /// Extract a pseudorandom key from the input key material and salt
        ///
        /// This function performs the extract step of HKDF-SHA-256, which derives a
        /// pseudorandom key (PRK) from the input key material and salt.
        ///
        /// # Arguments
        ///
        /// * `salt` - Optional salt value (can be None)
        /// * `ikm` - Input key material
        ///
        /// # Returns
        ///
        /// * `Result<Prk>` - The pseudorandom key or an error
        ///
        /// # Errors
        ///
        /// Returns an error if the extract operation fails
        pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Prk> {
            let mut prk = [0u8; KEYBYTES];

            let salt_ptr = match salt {
                Some(s) => s.as_ptr(),
                None => std::ptr::null(),
            };
            let salt_len = salt.map_or(0, |s| s.len());

            let result = unsafe {
                libsodium_sys::crypto_kdf_hkdf_sha256_extract(
                    prk.as_mut_ptr(),
                    salt_ptr,
                    salt_len as libc::size_t,
                    ikm.as_ptr(),
                    ikm.len() as libc::size_t,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "HKDF-SHA-256 extract phase failed".into(),
                ));
            }

            Ok(Prk(prk))
        }

        /// Generate a random pseudorandom key
        ///
        /// This function generates a random pseudorandom key for use with HKDF-SHA-256.
        ///
        /// # Returns
        ///
        /// * `Prk` - A random pseudorandom key
        pub fn keygen() -> Prk {
            let mut prk = [0u8; KEYBYTES];
            unsafe {
                libsodium_sys::crypto_kdf_hkdf_sha256_keygen(prk.as_mut_ptr());
            }
            Prk(prk)
        }

        /// Expand the pseudorandom key to the desired output length using the context
        ///
        /// This function performs the expand step of HKDF-SHA-256, which expands the
        /// pseudorandom key to the desired output length using the context.
        ///
        /// # Arguments
        ///
        /// * `out_len` - Length of the output to generate (must be at most `BYTES_MAX`)
        /// * `ctx` - Optional context (can be None)
        /// * `prk` - Pseudorandom key from the extract step
        ///
        /// # Returns
        ///
        /// * `Result<Vec<u8>>` - The expanded output or an error
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// * `out_len` is greater than `BYTES_MAX`
        /// * The expand operation fails
        pub fn expand(out_len: usize, ctx: Option<&[u8]>, prk: &Prk) -> Result<Vec<u8>> {
            if out_len > BYTES_MAX {
                return Err(SodiumError::InvalidInput(format!(
                    "output length must be at most {BYTES_MAX} bytes"
                )));
            }

            let mut out = vec![0u8; out_len];

            let ctx_ptr = match ctx {
                Some(c) => c.as_ptr() as *const libc::c_char,
                None => std::ptr::null(),
            };
            let ctx_len = ctx.map_or(0, |c| c.len());

            let result = unsafe {
                libsodium_sys::crypto_kdf_hkdf_sha256_expand(
                    out.as_mut_ptr(),
                    out_len as libc::size_t,
                    ctx_ptr,
                    ctx_len as libc::size_t,
                    prk.as_bytes().as_ptr(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "HKDF-SHA-256 expand phase failed".into(),
                ));
            }

            Ok(out)
        }

        /// State structure for incremental HKDF-SHA-256 extraction
        pub struct State {
            state: Box<libsodium_sys::crypto_kdf_hkdf_sha256_state>,
        }

        impl Default for State {
            fn default() -> Self {
                Self::new()
            }
        }

        impl State {
            /// Create a new state for incremental HKDF-SHA-256 extraction
            pub fn new() -> Self {
                let state = unsafe {
                    let layout = std::alloc::Layout::from_size_align(statebytes(), 8)
                        .expect("Invalid layout for crypto_kdf_hkdf_sha256_state");
                    let ptr = std::alloc::alloc_zeroed(layout)
                        as *mut libsodium_sys::crypto_kdf_hkdf_sha256_state;
                    Box::from_raw(ptr)
                };
                Self { state }
            }

            /// Initialize the state with the salt
            ///
            /// # Arguments
            ///
            /// * `salt` - Optional salt value (can be None)
            ///
            /// # Returns
            ///
            /// * `Result<()>` - Success or an error
            pub fn extract_init(&mut self, salt: Option<&[u8]>) -> Result<()> {
                let salt_ptr = match salt {
                    Some(s) => s.as_ptr(),
                    None => std::ptr::null(),
                };
                let salt_len = salt.map_or(0, |s| s.len());

                let result = unsafe {
                    libsodium_sys::crypto_kdf_hkdf_sha256_extract_init(
                        self.state.as_mut(),
                        salt_ptr,
                        salt_len as libc::size_t,
                    )
                };

                if result != 0 {
                    return Err(SodiumError::OperationError(
                        "HKDF-SHA-256 extract init failed".into(),
                    ));
                }

                Ok(())
            }

            /// Update the state with input key material
            ///
            /// # Arguments
            ///
            /// * `ikm` - Input key material
            ///
            /// # Returns
            ///
            /// * `Result<()>` - Success or an error
            pub fn extract_update(&mut self, ikm: &[u8]) -> Result<()> {
                let result = unsafe {
                    libsodium_sys::crypto_kdf_hkdf_sha256_extract_update(
                        self.state.as_mut(),
                        ikm.as_ptr(),
                        ikm.len() as libc::size_t,
                    )
                };

                if result != 0 {
                    return Err(SodiumError::OperationError(
                        "HKDF-SHA-256 extract update failed".into(),
                    ));
                }

                Ok(())
            }

            /// Finalize the extraction and get the pseudorandom key
            ///
            /// # Returns
            ///
            /// * `Result<Prk>` - The pseudorandom key or an error
            pub fn extract_final(&mut self) -> Result<Prk> {
                let mut prk = [0u8; KEYBYTES];
                let result = unsafe {
                    libsodium_sys::crypto_kdf_hkdf_sha256_extract_final(
                        self.state.as_mut(),
                        prk.as_mut_ptr(),
                    )
                };

                if result != 0 {
                    return Err(SodiumError::OperationError(
                        "HKDF-SHA-256 extract final failed".into(),
                    ));
                }

                Ok(Prk(prk))
            }
        }

        impl Drop for State {
            fn drop(&mut self) {
                unsafe {
                    let ptr = Box::into_raw(std::mem::replace(
                        &mut self.state,
                        Box::new(std::mem::zeroed()),
                    ));
                    let layout = std::alloc::Layout::from_size_align(statebytes(), 8)
                        .expect("Invalid layout for crypto_kdf_hkdf_sha256_state");
                    std::alloc::dealloc(ptr as *mut u8, layout);
                }
            }
        }

        impl zeroize::Zeroize for State {
            fn zeroize(&mut self) {
                unsafe {
                    // Zero out the state memory
                    std::ptr::write_bytes(
                        self.state.as_mut() as *mut _ as *mut u8,
                        0,
                        statebytes(),
                    );
                }
            }
        }
    }

    /// HMAC-based Key Derivation Function using SHA-512
    ///
    /// This submodule provides key derivation functions based on HKDF with SHA-512.
    ///
    /// HKDF-SHA512 provides a higher security margin than HKDF-SHA256, producing a
    /// pseudorandom key of 64 bytes, which can then be expanded to any desired length.
    /// This variant is recommended for applications requiring the highest security level.
    pub mod sha512 {
        use super::*;

        /// Maximum number of bytes in a derived subkey (255 * 64 = 16320)
        pub const BYTES_MAX: usize = libsodium_sys::crypto_kdf_hkdf_sha512_BYTES_MAX as usize;
        /// Minimum number of bytes in a derived subkey (0)
        pub const BYTES_MIN: usize = libsodium_sys::crypto_kdf_hkdf_sha512_BYTES_MIN as usize;
        /// Number of bytes in the PRK (64)
        pub const KEYBYTES: usize = libsodium_sys::crypto_kdf_hkdf_sha512_KEYBYTES as usize;

        /// A pseudorandom key (PRK) for HKDF-SHA-512
        ///
        /// This structure represents the output of the extract step of HKDF-SHA-512.
        /// It can be used as input to the expand step to derive multiple keys.
        #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
        pub struct Prk([u8; KEYBYTES]);

        impl AsRef<[u8]> for Prk {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for Prk {
            type Error = crate::SodiumError;

            fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
                if slice.len() != KEYBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "PRK must be exactly {KEYBYTES} bytes"
                    )));
                }
                let mut prk = [0u8; KEYBYTES];
                prk.copy_from_slice(slice);
                Ok(Prk(prk))
            }
        }

        impl From<[u8; KEYBYTES]> for Prk {
            fn from(bytes: [u8; KEYBYTES]) -> Self {
                Prk(bytes)
            }
        }

        impl From<Prk> for [u8; KEYBYTES] {
            fn from(prk: Prk) -> Self {
                prk.0
            }
        }

        impl Prk {
            /// Returns a reference to the PRK as a byte slice
            ///
            /// # Returns
            ///
            /// * `&[u8; KEYBYTES]` - Reference to the PRK bytes
            pub fn as_bytes(&self) -> &[u8; KEYBYTES] {
                &self.0
            }

            /// Creates a PRK from a byte slice
            ///
            /// # Arguments
            ///
            /// * `slice` - Byte slice to create the PRK from
            ///
            /// # Returns
            ///
            /// * `Result<Self>` - A new PRK created from the slice or an error
            ///
            /// # Errors
            ///
            /// Returns an error if the slice is not exactly `KEYBYTES` bytes long
            pub fn from_slice(slice: &[u8]) -> Result<Self> {
                if slice.len() != KEYBYTES {
                    return Err(SodiumError::InvalidInput(format!(
                        "PRK must be exactly {KEYBYTES} bytes"
                    )));
                }

                let mut prk = [0u8; KEYBYTES];
                prk.copy_from_slice(slice);
                Ok(Self(prk))
            }
        }

        /// Size of the state structure in bytes
        pub fn statebytes() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha512_statebytes() as usize }
        }

        /// Returns the number of bytes in the PRK (64)
        pub fn keybytes() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha512_keybytes() as usize }
        }

        /// Returns the minimum number of bytes in a derived subkey (0)
        pub fn bytes_min() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha512_bytes_min() as usize }
        }

        /// Returns the maximum number of bytes in a derived subkey (255 * 64 = 16320)
        pub fn bytes_max() -> usize {
            unsafe { libsodium_sys::crypto_kdf_hkdf_sha512_bytes_max() as usize }
        }

        /// Extract a pseudorandom key from the input key material and salt
        ///
        /// This function performs the extract step of HKDF-SHA-512, which derives a
        /// pseudorandom key (PRK) from the input key material and salt.
        ///
        /// # Arguments
        ///
        /// * `salt` - Optional salt value (can be None)
        /// * `ikm` - Input key material
        ///
        /// # Returns
        ///
        /// * `Result<Prk>` - The pseudorandom key or an error
        ///
        /// # Errors
        ///
        /// Returns an error if the extract operation fails
        pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Prk> {
            let mut prk = [0u8; KEYBYTES];

            let salt_ptr = match salt {
                Some(s) => s.as_ptr(),
                None => std::ptr::null(),
            };
            let salt_len = salt.map_or(0, |s| s.len());

            let result = unsafe {
                libsodium_sys::crypto_kdf_hkdf_sha512_extract(
                    prk.as_mut_ptr(),
                    salt_ptr,
                    salt_len as libc::size_t,
                    ikm.as_ptr(),
                    ikm.len() as libc::size_t,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "HKDF-SHA-512 extract phase failed".into(),
                ));
            }

            Ok(Prk(prk))
        }

        /// Generate a random pseudorandom key
        ///
        /// This function generates a random pseudorandom key for use with HKDF-SHA-512.
        ///
        /// # Returns
        ///
        /// * `Prk` - A random pseudorandom key
        pub fn keygen() -> Prk {
            let mut prk = [0u8; KEYBYTES];
            unsafe {
                libsodium_sys::crypto_kdf_hkdf_sha512_keygen(prk.as_mut_ptr());
            }
            Prk(prk)
        }

        /// Expand the pseudorandom key to the desired output length using the context.
        ///
        /// # Arguments
        ///
        /// * `out_len` - Length of the output to generate (must be at most `BYTES_MAX`)
        /// * `ctx` - Optional context (can be None)
        /// * `prk` - Pseudorandom key from the extract step
        ///
        /// # Returns
        ///
        /// * `Result<Vec<u8>>` - The expanded output or an error
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// * `out_len` is greater than `BYTES_MAX`
        /// * The expand operation fails
        pub fn expand(out_len: usize, ctx: Option<&[u8]>, prk: &Prk) -> Result<Vec<u8>> {
            if out_len > BYTES_MAX {
                return Err(SodiumError::InvalidInput(format!(
                    "output length must be at most {BYTES_MAX} bytes"
                )));
            }

            let mut out = vec![0u8; out_len];

            let ctx_ptr = match ctx {
                Some(c) => c.as_ptr() as *const libc::c_char,
                None => std::ptr::null(),
            };
            let ctx_len = ctx.map_or(0, |c| c.len());

            let result = unsafe {
                libsodium_sys::crypto_kdf_hkdf_sha512_expand(
                    out.as_mut_ptr(),
                    out_len as libc::size_t,
                    ctx_ptr,
                    ctx_len as libc::size_t,
                    prk.as_bytes().as_ptr(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "HKDF-SHA-512 expand phase failed".into(),
                ));
            }

            Ok(out)
        }

        /// State structure for incremental HKDF-SHA-512 extraction
        pub struct State {
            state: Box<libsodium_sys::crypto_kdf_hkdf_sha512_state>,
        }

        impl Default for State {
            fn default() -> Self {
                Self::new()
            }
        }

        impl State {
            /// Create a new state for incremental HKDF-SHA-512 extraction
            pub fn new() -> Self {
                let state = unsafe {
                    let layout = std::alloc::Layout::from_size_align(statebytes(), 8)
                        .expect("Invalid layout for crypto_kdf_hkdf_sha512_state");
                    let ptr = std::alloc::alloc_zeroed(layout)
                        as *mut libsodium_sys::crypto_kdf_hkdf_sha512_state;
                    Box::from_raw(ptr)
                };
                Self { state }
            }

            /// Initialize the state with the salt
            ///
            /// # Arguments
            ///
            /// * `salt` - Optional salt value (can be None)
            ///
            /// # Returns
            ///
            /// * `Result<()>` - Success or an error
            pub fn extract_init(&mut self, salt: Option<&[u8]>) -> Result<()> {
                let salt_ptr = match salt {
                    Some(s) => s.as_ptr(),
                    None => std::ptr::null(),
                };
                let salt_len = salt.map_or(0, |s| s.len());

                let result = unsafe {
                    libsodium_sys::crypto_kdf_hkdf_sha512_extract_init(
                        self.state.as_mut(),
                        salt_ptr,
                        salt_len as libc::size_t,
                    )
                };

                if result != 0 {
                    return Err(SodiumError::OperationError(
                        "HKDF-SHA-512 extract init failed".into(),
                    ));
                }

                Ok(())
            }

            /// Update the state with input key material
            ///
            /// # Arguments
            ///
            /// * `ikm` - Input key material
            ///
            /// # Returns
            ///
            /// * `Result<()>` - Success or an error
            pub fn extract_update(&mut self, ikm: &[u8]) -> Result<()> {
                let result = unsafe {
                    libsodium_sys::crypto_kdf_hkdf_sha512_extract_update(
                        self.state.as_mut(),
                        ikm.as_ptr(),
                        ikm.len() as libc::size_t,
                    )
                };

                if result != 0 {
                    return Err(SodiumError::OperationError(
                        "HKDF-SHA-512 extract update failed".into(),
                    ));
                }

                Ok(())
            }

            /// Finalize the extraction and get the pseudorandom key
            ///
            /// # Returns
            ///
            /// * `Result<Prk>` - The pseudorandom key or an error
            pub fn extract_final(&mut self) -> Result<Prk> {
                let mut prk = [0u8; KEYBYTES];
                let result = unsafe {
                    libsodium_sys::crypto_kdf_hkdf_sha512_extract_final(
                        self.state.as_mut(),
                        prk.as_mut_ptr(),
                    )
                };

                if result != 0 {
                    return Err(SodiumError::OperationError(
                        "HKDF-SHA-512 extract final failed".into(),
                    ));
                }

                Ok(Prk(prk))
            }
        }

        impl Drop for State {
            fn drop(&mut self) {
                unsafe {
                    let ptr = Box::into_raw(std::mem::replace(
                        &mut self.state,
                        Box::new(std::mem::zeroed()),
                    ));
                    let layout = std::alloc::Layout::from_size_align(statebytes(), 8)
                        .expect("Invalid layout for crypto_kdf_hkdf_sha512_state");
                    std::alloc::dealloc(ptr as *mut u8, layout);
                }
            }
        }

        impl zeroize::Zeroize for State {
            fn zeroize(&mut self) {
                unsafe {
                    // Zero out the state memory
                    std::ptr::write_bytes(
                        self.state.as_mut() as *mut _ as *mut u8,
                        0,
                        statebytes(),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        let master_key = Key::generate().unwrap();
        let context = b"Examples";
        let subkey = derive_from_key(32, 1, context, &master_key).unwrap();
        assert_eq!(subkey.len(), 32);

        // Derive a different subkey with a different ID
        let subkey2 = derive_from_key(32, 2, context, &master_key).unwrap();
        assert_ne!(subkey, subkey2);

        // Test with invalid subkey length
        let invalid_length_result = derive_from_key(BYTES_MAX + 1, 1, context, &master_key);
        assert!(invalid_length_result.is_err());

        // Test with invalid context length (should be exactly 8 bytes)
        let invalid_context = b"Short";
        let invalid_context_result = derive_from_key(32, 1, invalid_context, &master_key);
        assert!(invalid_context_result.is_err());
    }

    #[test]
    fn test_blake2b() {
        let master_key = blake2b::Key::generate().unwrap();
        let context = b"Examples";
        let subkey = blake2b::derive_from_key(32, 1, context, &master_key).unwrap();
        assert_eq!(subkey.len(), 32);

        // Derive a different subkey with a different ID
        let subkey2 = blake2b::derive_from_key(32, 2, context, &master_key).unwrap();
        assert_ne!(subkey, subkey2);
    }

    #[test]
    fn test_hkdf_sha256() {
        // Test the extract function
        let ikm = b"input key material";
        let salt = Some(b"salt".as_ref());
        let prk = hkdf::sha256::extract(salt, ikm).unwrap();
        assert_eq!(prk.as_bytes().len(), hkdf::sha256::KEYBYTES);

        // Test the expand function
        let ctx = Some(b"context".as_ref());
        let out_len = 32;
        let out = hkdf::sha256::expand(out_len, ctx, &prk).unwrap();
        assert_eq!(out.len(), out_len);

        // Test with different context produces different output
        let ctx2 = Some(b"different context".as_ref());
        let out2 = hkdf::sha256::expand(out_len, ctx2, &prk).unwrap();
        assert_ne!(out, out2);

        // Test keygen function
        let random_prk = hkdf::sha256::keygen();
        assert_eq!(random_prk.as_bytes().len(), hkdf::sha256::KEYBYTES);
    }

    #[test]
    fn test_hkdf_sha512() {
        // Test the extract function
        let ikm = b"input key material";
        let salt = Some(b"salt".as_ref());
        let prk = hkdf::sha512::extract(salt, ikm).unwrap();
        assert_eq!(prk.as_bytes().len(), hkdf::sha512::KEYBYTES);

        // Test the expand function
        let ctx = Some(b"context".as_ref());
        let out_len = 64;
        let out = hkdf::sha512::expand(out_len, ctx, &prk).unwrap();
        assert_eq!(out.len(), out_len);

        // Test with different context produces different output
        let ctx2 = Some(b"different context".as_ref());
        let out2 = hkdf::sha512::expand(out_len, ctx2, &prk).unwrap();
        assert_ne!(out, out2);

        // Test keygen function
        let random_prk = hkdf::sha512::keygen();
        assert_eq!(random_prk.as_bytes().len(), hkdf::sha512::KEYBYTES);
    }

    #[test]
    fn test_hkdf_sha256_state() {
        // Test the incremental extraction API
        let ikm1 = b"input key";
        let ikm2 = b" material";
        let salt = Some(b"salt".as_ref());

        // One-shot extraction
        let mut combined_ikm = Vec::new();
        combined_ikm.extend_from_slice(ikm1);
        combined_ikm.extend_from_slice(ikm2);
        let prk1 = hkdf::sha256::extract(salt, &combined_ikm).unwrap();

        // Incremental extraction
        let mut state = hkdf::sha256::State::new();
        state.extract_init(salt).unwrap();
        state.extract_update(ikm1).unwrap();
        state.extract_update(ikm2).unwrap();
        let prk2 = state.extract_final().unwrap();

        // Both methods should produce the same PRK
        assert_eq!(prk1.as_bytes(), prk2.as_bytes());
    }

    #[test]
    fn test_hkdf_sha512_state() {
        // Test the incremental extraction API
        let ikm1 = b"input key";
        let ikm2 = b" material";
        let salt = Some(b"salt".as_ref());

        // One-shot extraction
        let mut combined_ikm = Vec::new();
        combined_ikm.extend_from_slice(ikm1);
        combined_ikm.extend_from_slice(ikm2);
        let prk1 = hkdf::sha512::extract(salt, &combined_ikm).unwrap();

        // Incremental extraction
        let mut state = hkdf::sha512::State::new();
        state.extract_init(salt).unwrap();
        state.extract_update(ikm1).unwrap();
        state.extract_update(ikm2).unwrap();
        let prk2 = state.extract_final().unwrap();

        // Both methods should produce the same PRK
        assert_eq!(prk1.as_bytes(), prk2.as_bytes());
    }

    #[test]
    fn test_main_key_traits() {
        // Test AsRef
        let key = Key::generate().unwrap();
        let key_ref: &[u8] = key.as_ref();
        assert_eq!(key_ref.len(), KEYBYTES);

        // Test TryFrom<&[u8]>
        let bytes = [0x42; KEYBYTES];
        let key_from_slice = Key::try_from(&bytes[..]).unwrap();
        assert_eq!(key_from_slice.as_ref(), &bytes);

        // Test TryFrom with invalid length
        let invalid_bytes = [0x42; KEYBYTES - 1];
        assert!(Key::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let key_from_bytes = Key::from(bytes);
        assert_eq!(key_from_bytes.as_ref(), &bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let key = Key::from(bytes);
        let bytes_from_key: [u8; KEYBYTES] = key.into();
        assert_eq!(bytes_from_key, bytes);
    }

    #[test]
    fn test_blake2b_key_traits() {
        // Test AsRef
        let key = blake2b::Key::generate().unwrap();
        let key_ref: &[u8] = key.as_ref();
        assert_eq!(key_ref.len(), blake2b::KEYBYTES);

        // Test TryFrom<&[u8]>
        let bytes = [0x42; blake2b::KEYBYTES];
        let key_from_slice = blake2b::Key::try_from(&bytes[..]).unwrap();
        assert_eq!(key_from_slice.as_ref(), &bytes);

        // Test TryFrom with invalid length
        let invalid_bytes = [0x42; blake2b::KEYBYTES - 1];
        assert!(blake2b::Key::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let key_from_bytes = blake2b::Key::from(bytes);
        assert_eq!(key_from_bytes.as_ref(), &bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let key = blake2b::Key::from(bytes);
        let bytes_from_key: [u8; blake2b::KEYBYTES] = key.into();
        assert_eq!(bytes_from_key, bytes);
    }

    #[test]
    fn test_hkdf_sha256_prk_traits() {
        // Test AsRef
        let prk = hkdf::sha256::keygen();
        let prk_ref: &[u8] = prk.as_ref();
        assert_eq!(prk_ref.len(), hkdf::sha256::KEYBYTES);

        // Test TryFrom<&[u8]>
        let bytes = [0x42; hkdf::sha256::KEYBYTES];
        let prk_from_slice = hkdf::sha256::Prk::try_from(&bytes[..]).unwrap();
        assert_eq!(prk_from_slice.as_ref(), &bytes);

        // Test TryFrom with invalid length
        let invalid_bytes = [0x42; hkdf::sha256::KEYBYTES - 1];
        assert!(hkdf::sha256::Prk::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let prk_from_bytes = hkdf::sha256::Prk::from(bytes);
        assert_eq!(prk_from_bytes.as_ref(), &bytes);

        // Test From<Prk> for [u8; KEYBYTES]
        let prk = hkdf::sha256::Prk::from(bytes);
        let bytes_from_prk: [u8; hkdf::sha256::KEYBYTES] = prk.into();
        assert_eq!(bytes_from_prk, bytes);
    }

    #[test]
    fn test_hkdf_sha512_prk_traits() {
        // Test AsRef
        let prk = hkdf::sha512::keygen();
        let prk_ref: &[u8] = prk.as_ref();
        assert_eq!(prk_ref.len(), hkdf::sha512::KEYBYTES);

        // Test TryFrom<&[u8]>
        let bytes = [0x42; hkdf::sha512::KEYBYTES];
        let prk_from_slice = hkdf::sha512::Prk::try_from(&bytes[..]).unwrap();
        assert_eq!(prk_from_slice.as_ref(), &bytes);

        // Test TryFrom with invalid length
        let invalid_bytes = [0x42; hkdf::sha512::KEYBYTES - 1];
        assert!(hkdf::sha512::Prk::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let prk_from_bytes = hkdf::sha512::Prk::from(bytes);
        assert_eq!(prk_from_bytes.as_ref(), &bytes);

        // Test From<Prk> for [u8; KEYBYTES]
        let prk = hkdf::sha512::Prk::from(bytes);
        let bytes_from_prk: [u8; hkdf::sha512::KEYBYTES] = prk.into();
        assert_eq!(bytes_from_prk, bytes);
    }
}
