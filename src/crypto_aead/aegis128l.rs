//! # AEGIS-128L Authenticated Encryption with Associated Data
//!
//! This module provides authenticated encryption and decryption using the
//! AEGIS-128L algorithm. AEGIS-128L is a high-performance AEAD cipher that
//! offers both confidentiality and authenticity. It was the winner in the CAESAR
//! (Competition for Authenticated Encryption: Security, Applicability, and Robustness)
//! competition for high-performance applications and is currently being standardized by
//! the IETF Crypto Forum Research Group (CFRG) in draft-irtf-cfrg-aegis-aead.
//!
//! ## Algorithm Details
//!
//! AEGIS-128L is an AES-based authenticated encryption algorithm:
//!
//! - **Design Philosophy**: AEGIS-128L uses multiple AES encryption rounds in a stream cipher
//!   construction to provide both encryption and authentication in a single pass.
//!
//! - **State Size**: AEGIS-128L maintains a large internal state (8 AES blocks, 1024 bits)
//!   which provides strong resistance against cryptanalysis.
//!
//! - **Key and Nonce**: Uses a 128-bit (16-byte) key and a 128-bit (16-byte) nonce.
//!
//! - **Authentication Tag**: Produces a 128-bit (16-byte) authentication tag.
//!
//! ## Features and Advantages
//!
//! - **Exceptional Performance**: One of the fastest AEAD algorithms available on modern
//!   hardware with AES-NI instructions, often outperforming AES-GCM and ChaCha20-Poly1305.
//!
//! - **Hardware Acceleration**: Optimized for CPUs with AES-NI instructions, achieving
//!   extremely high throughput (often exceeding 10 cycles per byte on modern CPUs).
//!
//! - **Strong Security Margin**: Designed with a conservative approach to security,
//!   providing a high security margin against known attacks.
//!
//! - **Parallelizable**: The algorithm can be parallelized for even better performance
//!   on multi-core systems.
//!
//! - **Constant-Time Implementation**: Resistant to timing attacks when implemented on
//!   platforms with constant-time AES instructions.
//!
//! ## Hardware Support
//!
//! AEGIS-128L performance depends on hardware support:
//!
//! - **With AES-NI**: Extremely fast, often faster than AES-GCM and ChaCha20-Poly1305
//! - **Without AES-NI**: Significantly slower and not recommended
//!
//! Always ensure your target platform has AES-NI support before choosing AEGIS-128L.
//!
//! ## Security Properties
//!
//! - **Confidentiality**: The encrypted message cannot be read without the secret key
//! - **Integrity**: Any modification to the ciphertext will be detected during decryption
//! - **Authenticity**: The receiver can verify that the message was created by someone with the secret key
//! - **Nonce Misuse Resistance**: While not fully nonce-misuse resistant, AEGIS-128L has better
//!   resistance to nonce reuse than many other AEAD algorithms
//!
//! ## Nonce Considerations
//!
//! AEGIS-128L uses a 128-bit (16-byte) nonce. While this is a large nonce space,
//! it's still important to ensure nonce uniqueness for each encryption operation
//! with the same key.
//!
//! According to the IETF draft specification (draft-irtf-cfrg-aegis-aead):
//! - With AEGIS-128L, random nonces can safely encrypt up to 2^48 messages using the same key
//!   with negligible (~2^-33) collision probability, which aligns with NIST guidelines
//! - The 128-bit nonce offers an extra 32 bits compared to the commonly used AEADs in IETF protocols
//! - Unused nonce bits can encode a key identifier, enhancing multi-user security
//!
//! For nonce handling, consider one of these approaches:
//!
//! 1. **Counter-based nonces**: Maintain a counter for each key and increment it
//!    for each encryption operation. This guarantees uniqueness.
//!
//! 2. **Random nonces**: For most applications, generating random nonces is safe with AEGIS-128L,
//!    as the 128-bit nonce space is large enough that collisions are unlikely for a reasonable
//!    number of messages (up to about 2^48 messages per key).
//!
//! ## Security Considerations
//!
//! - **Nonce Reuse**: Never reuse a nonce with the same key. Doing so would compromise
//!   the security of the encrypted messages and immediately reveal the bitwise difference between two messages.
//!
//! - **Authentication**: Always verify the authentication tag before using decrypted data.
//!   AEGIS-128L provides strong authentication, but only if the tag is properly verified.
//!   If tag verification fails, the unverified plaintext must not be released.
//!
//! - **Key Management**: Protect your secret keys. Consider using a key derivation function
//!   (KDF) to derive encryption keys from passwords or other key material. Every key must be
//!   randomly chosen from a uniform distribution.
//!
//! - **Committing Security**: With a 128-bit authentication tag, AEGIS provides 64-bit committing
//!   security, which is generally acceptable for interactive protocols. Finding distinct keys and/or
//!   nonces that successfully verify the same (associated data, ciphertext, tag) tuple is expected
//!   to require ~2^64 attempts.
//!
//! - **Implementation Security**: The security of AEGIS against timing and physical attacks is
//!   limited by the implementation of the underlying AES round function. Implementations should
//!   take care to protect against timing attacks, differential power analysis, and fault injection.
//!
//! - **Hardware requirements**: AEGIS-128L is designed for hardware with AES-NI instructions.
//!   Performance will be significantly degraded on systems without these instructions.
//!
//! - **Authentication failures**: If authentication fails during decryption, the entire message
//!   is rejected and no plaintext is returned. Treat this as a potential attack.
//!
//! - **Ciphertext expansion**: The ciphertext will be larger than the plaintext by `ABYTES` (16 bytes)
//!   for the authentication tag.
//!
//! ## When to Use AEGIS-128L
//!
//! - When you need extremely high performance on modern hardware with AES-NI
//! - When you want a well-analyzed algorithm with a strong security margin
//! - When you need a larger nonce size than AES-GCM (128-bit vs 96-bit)
//! - When you want better security properties against nonce reuse than AES-GCM
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::aegis128l;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = aegis128l::Key::generate();
//!
//! // Create a nonce
//! let nonce = aegis128l::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Additional authenticated data (not encrypted, but authenticated)
//! let additional_data = b"Important metadata";
//!
//! // Encrypt the message
//! let ciphertext = aegis128l::encrypt(
//!     message,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! // Decrypt the message
//! let decrypted = aegis128l::decrypt(
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

/// Number of bytes in a secret key (16)
///
/// The secret key is used for both encryption and decryption.
/// It must be kept secret and should be generated using a secure random number generator.
pub const KEYBYTES: usize = libsodium_sys::crypto_aead_aegis128l_KEYBYTES as usize;
/// Number of bytes in a nonce (16)
///
/// The nonce must be unique for each encryption operation with the same key.
/// It can be public, but must never be reused with the same key.
pub const NPUBBYTES: usize = libsodium_sys::crypto_aead_aegis128l_NPUBBYTES as usize;

/// A nonce (number used once) for AEGIS-128L operations
///
/// This struct represents a nonce for use with the AEGIS-128L encryption algorithm.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// AEGIS-128L uses a 128-bit nonce, which is large enough that random nonces can be
/// used with a low risk of collisions, but care should still be taken in high-volume applications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NPUBBYTES]);

impl Nonce {
    /// Generate a random nonce for use with AEGIS-128L functions
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
    /// use sodium::crypto_aead::aegis128l;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = aegis128l::Nonce::generate();
    /// assert_eq!(nonce.as_ref().len(), aegis128l::NPUBBYTES);
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
pub const ABYTES: usize = libsodium_sys::crypto_aead_aegis128l_ABYTES as usize;

/// Maximum number of bytes in a message
///
/// This is the maximum number of bytes that can be encrypted in a single message.
pub fn messagebytes_max() -> usize {
    unsafe { libsodium_sys::crypto_aead_aegis128l_messagebytes_max() }
}

/// A secret key for AEGIS-128L encryption and decryption
///
/// This struct represents a 128-bit (16-byte) secret key used for
/// AEGIS-128L authenticated encryption and decryption.
/// The key should be generated using a secure random number generator
/// and kept secret.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_aead::aegis128l;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = aegis128l::Key::generate();
///
/// // Create a key from existing bytes
/// let key_bytes = [0x42; aegis128l::KEYBYTES];
/// let key_from_bytes = aegis128l::Key::from_bytes(&key_bytes).unwrap();
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
            libsodium_sys::crypto_aead_aegis128l_keygen(key.as_mut_ptr());
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

/// Encrypt a message using AEGIS-128L
///
/// This function encrypts a message using the AEGIS-128L algorithm.
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
/// use sodium::crypto_aead::aegis128l;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = aegis128l::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aegis128l::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = aegis128l::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
/// ```
///
/// # Errors
/// Returns an error if:
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len() + ABYTES];
    let mut ciphertext_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aegis128l_encrypt(
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

/// Decrypt a message using AEGIS-128L
///
/// This function decrypts a message that was encrypted using the AEGIS-128L
/// algorithm. It verifies the authenticity of both the ciphertext and the additional data
/// (if provided) before returning the decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message with authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be unique for each encryption with the same key)
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
/// use sodium::crypto_aead::aegis128l;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = aegis128l::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aegis128l::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message
/// let ciphertext = aegis128l::encrypt(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message
/// let decrypted = aegis128l::decrypt(
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
    if ciphertext.len() < ABYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len() - ABYTES];
    let mut message_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aegis128l_decrypt(
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

/// Encrypt a message using AEGIS-128L with detached authentication tag
///
/// This function encrypts a message using the AEGIS-128L algorithm and returns
/// the ciphertext and authentication tag separately. This is useful when you want
/// to store or transmit the authentication tag separately from the ciphertext.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be unique for each encryption with the same key)
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
/// use sodium::crypto_aead::aegis128l;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = aegis128l::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aegis128l::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = aegis128l::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message using the detached authentication tag
/// let decrypted = aegis128l::decrypt_detached(
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
/// * The nonce is not exactly `NPUBBYTES` bytes
/// * The encryption operation fails
pub fn encrypt_detached(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let ad = additional_data.unwrap_or(&[]);
    let mut ciphertext = vec![0u8; message.len()];
    let mut tag = vec![0u8; ABYTES];
    let mut tag_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_aead_aegis128l_encrypt_detached(
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

/// Decrypt a message using AEGIS-128L with detached authentication tag
///
/// This function decrypts a message that was encrypted using the AEGIS-128L
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
/// use sodium::crypto_aead::aegis128l;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = aegis128l::Key::generate();
///
/// // Generate a random nonce
/// let nonce = aegis128l::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"Hello, world!";
///
/// // Additional authenticated data (not encrypted, but authenticated)
/// let additional_data = b"Important metadata";
///
/// // Encrypt the message with detached authentication tag
/// let (ciphertext, tag) = aegis128l::encrypt_detached(
///     message,
///     Some(additional_data),
///     &nonce,
///     &key,
/// ).unwrap();
///
/// // Decrypt the message using the detached authentication tag
/// let decrypted = aegis128l::decrypt_detached(
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
    if tag.len() != ABYTES {
        return Err(SodiumError::InvalidInput(format!(
            "tag must be exactly {ABYTES} bytes"
        )));
    }

    let ad = additional_data.unwrap_or(&[]);
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_aead_aegis128l_decrypt_detached(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ensure_init;

    #[test]
    fn test_nonce_generation() {
        ensure_init().expect("Failed to initialize libsodium");

        let nonce = Nonce::generate();
        assert_eq!(nonce.as_ref().len(), NPUBBYTES);
    }

    #[test]
    fn test_nonce_from_bytes() {
        ensure_init().expect("Failed to initialize libsodium");

        let bytes = [0x42; NPUBBYTES];
        let nonce = Nonce::from_bytes(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_try_from_slice() {
        ensure_init().expect("Failed to initialize libsodium");

        let bytes = [0x42; NPUBBYTES];
        let nonce = Nonce::try_from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Test with invalid length
        let invalid_bytes = [0x42; NPUBBYTES - 1];
        assert!(Nonce::try_from_slice(&invalid_bytes).is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        ensure_init().expect("Failed to initialize libsodium");

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, AEGIS-128L!";
        let additional_data = b"Important metadata";

        // Encrypt the message
        let ciphertext = encrypt(message, Some(additional_data), &nonce, &key).unwrap();

        // Decrypt the message
        let decrypted = decrypt(&ciphertext, Some(additional_data), &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_decrypt_detached() {
        ensure_init().expect("Failed to initialize libsodium");

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, AEGIS-128L with detached MAC!";
        let additional_data = b"Important metadata";

        // Encrypt the message with detached MAC
        let (ciphertext, tag) =
            encrypt_detached(message, Some(additional_data), &nonce, &key).unwrap();

        // Decrypt the message with detached MAC
        let decrypted =
            decrypt_detached(&ciphertext, &tag, Some(additional_data), &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decrypt_failure() {
        ensure_init().expect("Failed to initialize libsodium");

        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, AEGIS-128L!";
        let additional_data = b"Important metadata";

        // Encrypt the message
        let mut ciphertext = encrypt(message, Some(additional_data), &nonce, &key).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        // Decryption should fail
        assert!(decrypt(&ciphertext, Some(additional_data), &nonce, &key).is_err());
    }

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
}
