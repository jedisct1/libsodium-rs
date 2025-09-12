//! # AES-256-GCM Authenticated Encryption with Associated Data
//!
//! This module provides authenticated encryption and decryption using the
//! AES-256-GCM algorithm. This is a widely used AEAD cipher that combines
//! the AES-256 block cipher with the Galois/Counter Mode (GCM) of operation.
//! It is standardized by NIST and widely deployed in TLS, IPsec, and many other protocols.
//!
//! ## Algorithm Details
//!
//! AES-256-GCM is a two-part construction:
//!
//! 1. **AES-256**: A block cipher using a 256-bit key
//!    * Operates on 128-bit blocks using substitution-permutation network
//!    * Uses 14 rounds of substitution and permutation operations
//!    * Provides high security margin against known attacks
//!    * Hardware acceleration available on modern CPUs via AES-NI instructions
//!
//! 2. **Galois/Counter Mode (GCM)**: A mode of operation for block ciphers
//!    * Combines counter mode encryption with Galois field multiplication for authentication
//!    * Produces a 128-bit (16-byte) authentication tag
//!    * Authenticates both the ciphertext and the additional data
//!    * Allows for parallel encryption and authentication
//!
//! ## Features and Advantages
//!
//! - **Hardware acceleration**: Extremely fast on CPUs with AES-NI and CLMUL instructions
//! - **Standardization**: Formally standardized by NIST (SP 800-38D), providing interoperability
//! - **Wide compatibility**: Supported in hardware and software across many platforms
//! - **Strong security**: 256-bit keys provide robust protection against brute force attacks
//! - **Parallelizable**: Both encryption and authentication can be parallelized
//! - **Single-pass**: Encryption and authentication performed in a single pass over the data
//!
//! ## Hardware Support
//!
//! AES-256-GCM performance varies significantly depending on hardware support:
//!
//! - **With AES-NI and CLMUL**: Extremely fast (often 10x faster than software implementations)
//! - **Without hardware acceleration**: Significantly slower and potentially vulnerable to timing attacks
//!
//! Always check for hardware support using the `is_available()` function before using this algorithm.
//! If hardware support is not available, consider using XChaCha20-Poly1305 instead, which has
//! excellent software performance without requiring special hardware.
//!
//! ## Security Properties
//!
//! - **Confidentiality**: The encrypted message cannot be read without the secret key
//! - **Integrity**: Any modification to the ciphertext will be detected during decryption
//! - **Authenticity**: The receiver can verify that the message was created by someone with the secret key
//! - **Well-analyzed**: AES-GCM has undergone extensive cryptanalysis and is widely trusted
//!
//! ## Nonce Considerations
//!
//! AES-256-GCM uses a 96-bit (12-byte) nonce, which is **NOT** large enough for safe
//! random generation. With a 96-bit nonce, the probability of a collision becomes significant
//! after encrypting approximately 2^32 messages with the same key.
//!
//! For safe nonce handling, use one of these approaches:
//!
//! 1. **Counter-based nonces**: Maintain a strictly increasing counter for each encryption
//!    with the same key. This is the recommended approach for AES-256-GCM.
//!
//! 2. **Use XChaCha20-Poly1305 instead**: If you need to encrypt many messages with the same key
//!    and cannot reliably maintain a counter, use XChaCha20-Poly1305 which has a 192-bit nonce
//!    that is safe for random generation.
//!
//! ## Security Considerations and Best Practices
//!
//! - **Nonce management**: Never reuse a nonce with the same key. Use a counter-based approach
//!   for generating nonces with AES-256-GCM.
//!
//! - **Key management**: Protect your secret keys. Consider using key derivation functions (KDFs)
//!   to derive encryption keys from passwords or master keys.
//!
//! - **Hardware requirements**: Always check for hardware support using `is_available()` before using
//!   this algorithm. Software implementations may be vulnerable to timing attacks.
//!
//! - **Authentication failures**: If authentication fails during decryption, the entire message is
//!   rejected and no plaintext is returned. Treat this as a potential attack.
//!
//! - **Ciphertext expansion**: The ciphertext will be larger than the plaintext by `ABYTES` (16 bytes)
//!   for the authentication tag.
//!
//! - **Precomputation**: For multiple encryptions with the same key, use the precomputation interface
//!   (`State` and `*_afternm` functions) for better performance.
//!
//! ## When to Use AES-256-GCM
//!
//! - When you need a standardized AEAD algorithm (NIST SP 800-38D)
//! - When you know the target platform has AES-NI and CLMUL hardware acceleration
//! - When you need maximum performance on modern hardware
//! - When you can reliably maintain a counter for nonce generation
//! - When you need interoperability with other systems and protocols (TLS, IPsec, etc.)
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::aes256gcm;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Check if AES-256-GCM is supported on this CPU
//! if !aes256gcm::is_available() {
//!     println!("AES-256-GCM is not available on this CPU");
//!     return;
//! }
//!
//! // Generate a random key
//! let key = aes256gcm::Key::generate();
//!
//! // Create a nonce
//! let nonce = aes256gcm::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Additional authenticated data (not encrypted, but authenticated)
//! let additional_data = b"Important metadata";
//!
//! // Encrypt the message
//! let ciphertext = aes256gcm::encrypt(
//!     message,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! // Decrypt the message
//! let decrypted = aes256gcm::decrypt(
//!     &ciphertext,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! assert_eq!(message, &decrypted[..]);
//! ```

use crate::{Result, SodiumError};
use std::convert::{TryFrom, TryInto};

/// Number of bytes in a secret key (32)
///
/// The secret key is used for both encryption and decryption.
/// It must be kept secret and should be generated using a secure random number generator.
pub const KEYBYTES: usize = libsodium_sys::crypto_aead_aes256gcm_KEYBYTES as usize;
/// Number of bytes in a nonce (12)
///
/// The nonce must be unique for each encryption operation with the same key.
/// It can be public, but must never be reused with the same key.
pub const NPUBBYTES: usize = libsodium_sys::crypto_aead_aes256gcm_NPUBBYTES as usize;

/// A nonce (number used once) for AES-256-GCM operations
///
/// This struct represents a nonce for use with the AES-256-GCM encryption algorithm.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// AES-256-GCM uses a 96-bit nonce, which is smaller than other AEAD algorithms like XChaCha20-Poly1305.
/// For applications that need to encrypt many messages with the same key, consider using
/// XChaCha20-Poly1305 instead, which has a larger nonce size (192 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NPUBBYTES]);

impl Nonce {
    /// Generate a random nonce for use with AES-256-GCM functions
    ///
    /// This method generates a random nonce of the appropriate size (NPUBBYTES)
    /// for use with the encryption and decryption functions in this module.
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A random nonce
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_aead::aes256gcm;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Check if AES-256-GCM is supported on this CPU
    /// if !aes256gcm::is_available() {
    ///     println!("AES-256-GCM is not available on this CPU");
    ///     return;
    /// }
    ///
    /// // Generate a random nonce
    /// let nonce = aes256gcm::Nonce::generate();
    /// assert_eq!(nonce.as_ref().len(), aes256gcm::NPUBBYTES);
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; NPUBBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from bytes of the correct length
    ///
    /// ## Arguments
    ///
    /// * `bytes` - Bytes of length NPUBBYTES
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A nonce initialized with the provided bytes
    pub fn from_bytes(bytes: [u8; NPUBBYTES]) -> Self {
        Self(bytes)
    }

    /// Create a nonce from a slice, checking that the length is correct
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A slice of bytes
    ///
    /// ## Returns
    ///
    /// * `Result<Nonce>` - A nonce or an error if the slice has the wrong length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NPUBBYTES {
            return Err(SodiumError::InvalidNonce(format!(
                "nonce must be exactly {NPUBBYTES} bytes"
            )));
        }

        let mut nonce_bytes = [0u8; NPUBBYTES];
        nonce_bytes.copy_from_slice(bytes);
        Ok(Self(nonce_bytes))
    }

    /// Get the underlying bytes of the nonce
    ///
    /// ## Returns
    ///
    /// * `&[u8; NPUBBYTES]` - A reference to the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NPUBBYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from_slice(slice)
    }
}

impl From<[u8; NPUBBYTES]> for Nonce {
    fn from(bytes: [u8; NPUBBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Nonce> for [u8; NPUBBYTES] {
    fn from(nonce: Nonce) -> [u8; NPUBBYTES] {
        nonce.0
    }
}

/// Number of bytes in an authentication tag (16)
///
/// This is the size of the authentication tag that is added to the ciphertext.
pub const ABYTES: usize = libsodium_sys::crypto_aead_aes256gcm_ABYTES as usize;

/// Maximum number of bytes in a message
///
/// This is the maximum number of bytes that can be encrypted in a single message.
pub fn messagebytes_max() -> usize {
    unsafe { libsodium_sys::crypto_aead_aes256gcm_messagebytes_max() }
}

/// Number of bytes in a state (512)
///
/// This is the size of the precomputation state used for more efficient encryption and decryption.
pub fn statebytes() -> usize {
    unsafe { libsodium_sys::crypto_aead_aes256gcm_statebytes() }
}

/// A secret key for AES-256-GCM encryption and decryption
///
/// This struct represents a 256-bit (32-byte) secret key used for
/// AES-256-GCM authenticated encryption and decryption.
/// The key should be generated using a secure random number generator
/// and kept secret.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aes256gcm;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Check if AES-256-GCM is supported on this CPU
/// if !aes256gcm::is_available() {
///     println!("AES-256-GCM is not available on this CPU");
///     return;
/// }
///
/// // Generate a random key
/// let key = aes256gcm::Key::generate();
///
/// // Create a key from existing bytes
/// let key_bytes = [0x42; aes256gcm::KEYBYTES];
/// let key_from_bytes = aes256gcm::Key::from_bytes(&key_bytes).unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generate a new key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "key must be exactly {KEYBYTES} bytes"
            )));
        }

        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(bytes);
        Ok(Key(key))
    }

    /// Generate a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_aead_aes256gcm_keygen(key.as_mut_ptr());
        }
        Key(key)
    }

    /// Get the bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; KEYBYTES]> for Key {
    fn from(bytes: [u8; KEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Key> for [u8; KEYBYTES] {
    fn from(key: Key) -> [u8; KEYBYTES] {
        key.0
    }
}

/// Check if AES-256-GCM is supported on the current CPU
///
/// This function checks if the current CPU supports the AES-NI instructions
/// required for efficient AES-256-GCM operation. If this function returns `false`,
/// you should use an alternative algorithm like XChaCha20-Poly1305.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aes256gcm;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Check if AES-256-GCM is supported on this CPU
/// if aes256gcm::is_available() {
///     println!("AES-256-GCM is available on this CPU");
/// } else {
///     println!("AES-256-GCM is not available on this CPU");
/// }
/// ```
///
/// ## Returns
///
/// * `bool` - `true` if AES-256-GCM is supported, `false` otherwise
pub fn is_available() -> bool {
    unsafe { libsodium_sys::crypto_aead_aes256gcm_is_available() == 1 }
}

/// Encrypt a message using AES-256-GCM
///
/// This function encrypts a message using the AES-256-GCM algorithm.
/// It provides both confidentiality and authenticity for the message, and also
/// authenticates the additional data if provided.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key to use for encryption
///
/// # Returns
/// * `Result<Vec<u8>>` - The encrypted message with authentication tag appended
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
///   For random nonces, use `Nonce::generate()`
/// * The additional data is authenticated but not encrypted
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aes256gcm;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Check if AES-256-GCM is supported on this CPU
/// if !aes256gcm::is_available() {
///     println!("AES-256-GCM is not available on this CPU");
///     return;
/// }
///
/// // Generate a random key
/// let key = aes256gcm::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aes256gcm::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = aes256gcm::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
/// ```
///
/// # Errors
/// Returns an error if:
/// * AES-256-GCM is not supported on the current CPU
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(SodiumError::UnsupportedOperation(
            "AES-256-GCM is not supported on this CPU".into(),
        ));
    }

    if nonce.as_ref().len() != NPUBBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "nonce must be exactly {NPUBBYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len() + ABYTES];
    let mut ciphertext_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            std::ptr::null(),
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    ciphertext.truncate(ciphertext_len as usize);
    Ok(ciphertext)
}

/// Decrypt a message using AES-256-GCM
///
/// This function decrypts a message that was encrypted using the AES-256-GCM
/// algorithm. It verifies the authenticity of both the ciphertext and the additional data
/// (if provided) before returning the decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message with authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key used for encryption
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
///
/// # Security Considerations
/// * If authentication fails, the function returns an error and no decryption is performed
/// * The additional data must be the same as used during encryption
/// * The nonce must be the same as used during encryption
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aes256gcm;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Check if AES-256-GCM is supported on this CPU
/// if !aes256gcm::is_available() {
///     println!("AES-256-GCM is not available on this CPU");
///     return;
/// }
///
/// // Generate a random key
/// let key = aes256gcm::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aes256gcm::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = aes256gcm::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message
/// let decrypted = aes256gcm::decrypt(
///     &ciphertext,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// assert_eq!(message, &decrypted[..]);
/// ```
///
/// # Errors
/// Returns an error if:
/// * AES-256-GCM is not supported on the current CPU
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The ciphertext is too short (less than `ABYTES` bytes)
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt(
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(SodiumError::UnsupportedOperation(
            "AES-256-GCM is not supported on this CPU".into(),
        ));
    }

    if nonce.as_ref().len() != NPUBBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "nonce must be exactly {NPUBBYTES} bytes"
        )));
    }

    if ciphertext.len() < ABYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len() - ABYTES];
    let mut message_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_decrypt(
            message.as_mut_ptr(),
            &mut message_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    message.truncate(message_len as usize);
    Ok(message)
}

/// Encrypt a message using AES-256-GCM with detached authentication tag
///
/// This function encrypts a message using the AES-256-GCM algorithm and returns
/// the ciphertext and authentication tag separately. This is useful when you want
/// to store or transmit the authentication tag separately from the ciphertext.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key to use for encryption
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>)>` - A tuple containing (ciphertext, authentication_tag)
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
///   For random nonces, use `Nonce::generate()`
/// * The additional data is authenticated but not encrypted
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aes256gcm;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Check if AES-256-GCM is supported on this CPU
/// if !aes256gcm::is_available() {
///     println!("AES-256-GCM is not available on this CPU");
///     return;
/// }
///
/// // Generate a random key
/// let key = aes256gcm::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aes256gcm::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = aes256gcm::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message using the detached authentication tag
/// let decrypted = aes256gcm::decrypt_detached(
///     &ciphertext,
///     &tag,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// assert_eq!(message, &decrypted[..]);
/// ```
///
/// # Errors
/// Returns an error if:
/// * AES-256-GCM is not supported on the current CPU
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt_detached(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return Err(SodiumError::UnsupportedOperation(
            "AES-256-GCM is not supported on this CPU".into(),
        ));
    }

    if nonce.as_ref().len() != NPUBBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "nonce must be exactly {NPUBBYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len()];
    let mut tag = vec![0u8; ABYTES];
    let mut tag_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_encrypt_detached(
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
            &mut tag_len,
            message.as_ptr(),
            message.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            std::ptr::null(),
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    tag.truncate(tag_len as usize);
    Ok((ciphertext, tag))
}

/// Decrypt a message using AES-256-GCM with detached authentication tag
///
/// This function decrypts a message that was encrypted using the AES-256-GCM
/// algorithm with a detached authentication tag. It verifies the authenticity of
/// both the ciphertext and the additional data (if provided) before returning the
/// decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message
/// * `tag` - The authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be exactly `NPUBBYTES` bytes)
/// * `key` - The key used for encryption
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
///
/// # Security Considerations
/// * If authentication fails, the function returns an error and no decryption is performed
/// * The additional data must be the same as used during encryption
/// * The nonce must be the same as used during encryption
///
/// # Example
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aes256gcm;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Check if AES-256-GCM is supported on this CPU
/// if !aes256gcm::is_available() {
///     println!("AES-256-GCM is not available on this CPU");
///     return;
/// }
///
/// // Generate a random key
/// let key = aes256gcm::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aes256gcm::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = aes256gcm::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message using the detached authentication tag
/// let decrypted = aes256gcm::decrypt_detached(
///     &ciphertext,
///     &tag,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// assert_eq!(message, &decrypted[..]);
/// ```
///
/// # Errors
/// Returns an error if:
/// * AES-256-GCM is not supported on the current CPU
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The tag is not exactly `ABYTES` bytes
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt_detached(
    ciphertext: &[u8],
    tag: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    if !is_available() {
        return Err(SodiumError::UnsupportedOperation(
            "AES-256-GCM is not supported on this CPU".into(),
        ));
    }

    if nonce.as_ref().len() != NPUBBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "nonce must be exactly {NPUBBYTES} bytes"
        )));
    }

    if tag.len() != ABYTES {
        return Err(SodiumError::InvalidInput(format!(
            "tag must be exactly {ABYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_decrypt_detached(
            message.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// A precomputation state for AES-256-GCM encryption and decryption
///
/// This struct represents a precomputation state that can be used to speed up
/// multiple encryption and decryption operations with the same key. It is useful
/// when you need to encrypt or decrypt multiple messages with the same key.
#[derive(Debug)]
pub struct State {
    inner: Box<libsodium_sys::crypto_aead_aes256gcm_state>,
}

impl State {
    /// Create a new precomputation state from a key
    ///
    /// This function creates a new precomputation state from a key. The state can
    /// then be used to speed up multiple encryption and decryption operations with
    /// the same key.
    ///
    /// # Arguments
    /// * `key` - The key to use for precomputation
    ///
    /// # Returns
    /// * `Result<State>` - The precomputation state
    ///
    /// # Errors
    /// Returns an error if:
    /// * AES-256-GCM is not supported on the current CPU
    /// * The precomputation operation fails
    pub fn from_key(key: &Key) -> Result<Self> {
        if !is_available() {
            return Err(SodiumError::UnsupportedOperation(
                "AES-256-GCM is not supported on this CPU".into(),
            ));
        }

        // Create a new state
        let mut state = Box::new(unsafe { std::mem::zeroed() });

        // Perform the precomputation
        let result = unsafe {
            libsodium_sys::crypto_aead_aes256gcm_beforenm(&mut *state, key.as_bytes().as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError("precomputation failed".into()));
        }

        Ok(Self { inner: state })
    }
}

/// Encrypt a message using AES-256-GCM with a precomputation state
///
/// This function encrypts a message using the AES-256-GCM algorithm with a
/// precomputation state. It provides both confidentiality and authenticity for
/// the message, and also authenticates the additional data if provided.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be exactly `NPUBBYTES` bytes)
/// * `state` - The precomputation state to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The encrypted message with authentication tag
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
///   For random nonces, use `Nonce::generate()`
/// * The additional data is authenticated but not encrypted
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt_afternm(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    state: &State,
) -> Result<Vec<u8>> {
    if nonce.as_ref().len() != NPUBBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "nonce must be exactly {NPUBBYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len() + ABYTES];
    let mut ciphertext_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_encrypt_afternm(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            std::ptr::null(),
            nonce.as_ref().as_ptr(),
            &*state.inner,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    ciphertext.truncate(ciphertext_len as usize);
    Ok(ciphertext)
}

/// Decrypt a message using AES-256-GCM with a precomputation state
///
/// This function decrypts a message that was encrypted using the AES-256-GCM
/// algorithm with a precomputation state. It verifies the authenticity of both
/// the ciphertext and the additional data (if provided) before returning the
/// decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message with authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be exactly `NPUBBYTES` bytes)
/// * `state` - The precomputation state to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
///
/// # Security Considerations
/// * If authentication fails, the function returns an error and no decryption is performed
/// * The additional data must be the same as used during encryption
/// * The nonce must be the same as used during encryption
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The ciphertext is too short (less than `ABYTES` bytes)
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt_afternm(
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    state: &State,
) -> Result<Vec<u8>> {
    if nonce.as_ref().len() != NPUBBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "nonce must be exactly {NPUBBYTES} bytes"
        )));
    }

    if ciphertext.len() < ABYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len() - ABYTES];
    let mut message_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_decrypt_afternm(
            message.as_mut_ptr(),
            &mut message_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            nonce.as_ref().as_ptr(),
            &*state.inner,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    message.truncate(message_len as usize);
    Ok(message)
}

/// Encrypt a message using AES-256-GCM with detached authentication tag and precomputation state
///
/// This function encrypts a message using the AES-256-GCM algorithm with a
/// precomputation state and returns the ciphertext and authentication tag separately.
/// This is useful when you want to store or transmit the authentication tag
/// separately from the ciphertext.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be exactly `NPUBBYTES` bytes)
/// * `state` - The precomputation state to use
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>)>` - A tuple containing (ciphertext, authentication_tag)
///
/// # Security Considerations
/// * The nonce must be unique for each encryption with the same key
/// * The nonce can be public, but must never be reused with the same key
///   For random nonces, use `Nonce::generate()`
/// * The additional data is authenticated but not encrypted
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt_detached_afternm(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    state: &State,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len()];
    let mut tag = vec![0u8; ABYTES];
    let mut tag_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_encrypt_detached_afternm(
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
            &mut tag_len,
            message.as_ptr(),
            message.len().try_into().unwrap(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            std::ptr::null(),
            nonce.as_ref().as_ptr(),
            &*state.inner,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    tag.truncate(tag_len as usize);
    Ok((ciphertext, tag))
}

/// Decrypt a message using AES-256-GCM with detached authentication tag and precomputation state
///
/// This function decrypts a message that was encrypted using the AES-256-GCM
/// algorithm with a detached authentication tag and precomputation state. It verifies
/// the authenticity of both the ciphertext and the additional data (if provided)
/// before returning the decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message
/// * `tag` - The authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be exactly `NPUBBYTES` bytes)
/// * `state` - The precomputation state to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
///
/// # Security Considerations
/// * If authentication fails, the function returns an error and no decryption is performed
/// * The additional data must be the same as used during encryption
/// * The nonce must be the same as used during encryption
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The tag is not exactly `ABYTES` bytes
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt_detached_afternm(
    ciphertext: &[u8],
    tag: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    state: &State,
) -> Result<Vec<u8>> {
    if tag.len() != ABYTES {
        return Err(SodiumError::InvalidInput(format!(
            "tag must be exactly {ABYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_aead_aes256gcm_decrypt_detached_afternm(
            message.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len().try_into().unwrap(),
            nonce.as_ref().as_ptr(),
            &*state.inner,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ensure_init;

    #[test]
    fn test_nonce_traits() {
        ensure_init().expect("Failed to initialize libsodium");

        // Test TryFrom<&[u8]>
        let bytes = [0x42; NPUBBYTES];
        let nonce = Nonce::try_from(&bytes[..]).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; NPUBBYTES - 1];
        assert!(Nonce::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; NPUBBYTES]>
        let bytes = [0x43; NPUBBYTES];
        let nonce2 = Nonce::from(bytes);
        assert_eq!(nonce2.as_bytes(), &bytes);

        // Test From<Nonce> for [u8; NPUBBYTES]
        let extracted: [u8; NPUBBYTES] = nonce2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let nonce3 = Nonce::generate();
        let slice_ref: &[u8] = nonce3.as_ref();
        assert_eq!(slice_ref.len(), NPUBBYTES);
    }

    #[test]
    fn test_key_traits() {
        ensure_init().expect("Failed to initialize libsodium");

        // Test TryFrom<&[u8]>
        let bytes = [0x42; KEYBYTES];
        let key = Key::try_from(&bytes[..]).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; KEYBYTES - 1];
        assert!(Key::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let bytes = [0x43; KEYBYTES];
        let key2 = Key::from(bytes);
        assert_eq!(key2.as_bytes(), &bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let extracted: [u8; KEYBYTES] = key2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let key3 = Key::generate();
        let slice_ref: &[u8] = key3.as_ref();
        assert_eq!(slice_ref.len(), KEYBYTES);
    }

    #[test]
    fn test_encrypt_decrypt() {
        ensure_init().expect("Failed to initialize libsodium");

        // Skip test if AES-256-GCM is not available
        if !is_available() {
            println!("Skipping test: AES-256-GCM is not available on this CPU");
            return;
        }

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, AES-256-GCM!";
        let additional_data = b"Important metadata";

        // Encrypt the message
        let ciphertext = encrypt(message, Some(additional_data), &nonce, &key).unwrap();

        // Decrypt the message
        let decrypted = decrypt(&ciphertext, Some(additional_data), &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }
}
