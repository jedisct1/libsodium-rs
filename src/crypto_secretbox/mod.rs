//! # Secret-key Authenticated Encryption
//!
//! This module provides functions for authenticated encryption using a secret key.
//! It combines encryption and authentication to provide confidentiality, integrity,
//! and authenticity of data.
//!
//! ## Overview
//!
//! Secret-key authenticated encryption (also known as symmetric authenticated encryption)
//! allows you to encrypt data such that:
//!
//! 1. The data remains confidential (encryption)
//! 2. The data cannot be modified without detection (authentication)
//! 3. The data can only be decrypted by someone with the same secret key
//!
//! This module uses XSalsa20 for encryption and Poly1305 for authentication by default,
//! combined in an encrypt-then-MAC construction. The `xchacha20poly1305` submodule
//! provides an alternative implementation using XChaCha20 and Poly1305.
//!
//! ## Features
//!
//! - **High security**: Uses modern, secure cryptographic primitives
//! - **Authenticated encryption**: Protects against tampering and forgery
//! - **Ease of use**: Simple API with sensible defaults
//! - **Nonce-based**: Requires a unique nonce for each encryption
//! - **Zero-copy**: Minimizes memory allocations where possible
//!
//! ## Basic Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretbox;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random secret key
//! let key = crypto_secretbox::Key::generate();
//!
//! // Generate a random nonce (must be unique for each message with the same key)
//! let nonce = crypto_secretbox::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Encrypt the message
//! let ciphertext = crypto_secretbox::seal(message, &nonce, &key);
//!
//! // Decrypt the message
//! let decrypted = crypto_secretbox::open(&ciphertext, &nonce, &key).unwrap();
//! assert_eq!(decrypted, message);
//! ```
//!
//! ## Nonce Management
//!
//! Proper nonce management is critical for security. A nonce must NEVER be reused with the same key.
//! Options for generating nonces include:
//!
//! 1. **Random nonces**: Use `random::bytes(NONCEBYTES)` for each message
//! 2. **Counter-based nonces**: Start with a random nonce and increment for each message
//! 3. **Timestamp-based nonces**: Combine a timestamp with a random value
//!
//! For long-term security, consider using the XChaCha20-Poly1305 variant which has a larger
//! nonce space (192 bits) and is more suitable for random nonce generation:
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretbox::xchacha20poly1305;
//! use sodium::ensure_init;
//! use sodium::random;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random secret key
//! let key = xchacha20poly1305::Key::generate();
//!
//! // Generate a random nonce
//! let nonce = xchacha20poly1305::Nonce::generate();
//!
//! // Encrypt and decrypt
//! let message = b"Hello, world!";
//! let ciphertext = xchacha20poly1305::encrypt(message, &nonce, &key);
//! let decrypted = xchacha20poly1305::decrypt(&ciphertext, &nonce, &key).unwrap();
//! assert_eq!(decrypted, message);
//! ```
//!
//! ## Security Considerations
//!
//! - **Never reuse a nonce with the same key**: This would completely compromise security
//! - **Store keys securely**: The secret key must be kept confidential
//! - **Verify decryption**: Always check for errors when decrypting
//! - **Consider key derivation**: For user-supplied passwords, use `crypto_pwhash` to derive keys
//! - **Prefer XChaCha20-Poly1305** for most new applications due to its larger nonce space

use crate::{Result, SodiumError};
use libsodium_sys;
use std::convert::{TryFrom, TryInto};

/// Number of bytes in a secret key (32)
///
/// This is the size of the secret key used for XSalsa20-Poly1305 encryption.
/// The key should be randomly generated using `Key::generate()` or derived
/// from a password using the `crypto_pwhash` module.
pub const KEYBYTES: usize = libsodium_sys::crypto_secretbox_KEYBYTES as usize;

/// Number of bytes in a nonce (24)
///
/// This is the size of the nonce (number used once) for XSalsa20-Poly1305 encryption.
/// The nonce must be unique for each message encrypted with the same key.
/// With a 24-byte nonce, random nonces can be safely used, but care must still
/// be taken to avoid nonce reuse in distributed systems.
///
/// Use the `Nonce::generate()` method to create a secure random nonce.
pub const NONCEBYTES: usize = libsodium_sys::crypto_secretbox_NONCEBYTES as usize;

/// A nonce (number used once) for secretbox operations
///
/// This struct represents a nonce for use with the XSalsa20-Poly1305 encryption algorithm.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    /// Generate a random nonce for use with crypto_secretbox functions
    ///
    /// This method generates a random nonce of the appropriate size (NONCEBYTES)
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
    /// use sodium::crypto_secretbox;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = crypto_secretbox::Nonce::generate();
    /// assert_eq!(nonce.as_ref().len(), crypto_secretbox::NONCEBYTES);
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCEBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from a byte array of the correct length
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A byte array of length NONCEBYTES
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A nonce initialized with the provided bytes
    pub fn from_bytes(bytes: [u8; NONCEBYTES]) -> Self {
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
        if bytes.len() != NONCEBYTES {
            return Err(SodiumError::InvalidNonce(format!(
                "nonce must be exactly {NONCEBYTES} bytes"
            )));
        }

        let mut nonce_bytes = [0u8; NONCEBYTES];
        nonce_bytes.copy_from_slice(bytes);
        Ok(Self(nonce_bytes))
    }

    /// Get the underlying bytes of the nonce
    ///
    /// ## Returns
    ///
    /// * `&[u8; NONCEBYTES]` - A reference to the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NONCEBYTES] {
        &self.0
    }
}

/// Number of bytes in a MAC (message authentication code) (16)
///
/// This is the size of the authentication tag added to each encrypted message.
/// The MAC ensures the integrity and authenticity of the ciphertext.
/// It is automatically handled by the `seal` and `open` functions.
pub const MACBYTES: usize = libsodium_sys::crypto_secretbox_MACBYTES as usize;

/// A secret key for authenticated symmetric encryption
///
/// This struct represents a secret key used for XSalsa20-Poly1305 authenticated encryption.
/// The key should be kept confidential and should be randomly generated or derived
/// from a strong password.
///
/// ## Size
///
/// A secret key is always exactly `KEYBYTES` (32) bytes.
///
/// ## Security Considerations
///
/// - The key should be kept confidential at all times
/// - Each key should be used with unique nonces
/// - For long-term storage, consider encrypting the key itself
/// - If derived from a password, use the `crypto_pwhash` module with appropriate parameters
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_secretbox;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = crypto_secretbox::Key::generate();
///
/// // Create a key from existing bytes (e.g., from secure storage)
/// let key_bytes = [0x42; crypto_secretbox::KEYBYTES]; // Example bytes
/// let key_from_bytes = crypto_secretbox::Key::from_bytes(&key_bytes).unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

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

impl From<[u8; NONCEBYTES]> for Nonce {
    fn from(bytes: [u8; NONCEBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Nonce> for [u8; NONCEBYTES] {
    fn from(nonce: Nonce) -> [u8; NONCEBYTES] {
        nonce.0
    }
}

impl Key {
    /// Create a key from existing bytes
    ///
    /// This function creates a key from an existing byte array.
    /// It's useful when you need to deserialize a key that was
    /// previously serialized or derived from another source.
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A byte slice of exactly `KEYBYTES` (32) length
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new key or an error if the input is invalid
    ///
    /// ## Errors
    ///
    /// Returns an error if the input is not exactly `KEYBYTES` bytes long.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretbox;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a key from bytes (e.g., from secure storage)
    /// let key_bytes = [0x42; crypto_secretbox::KEYBYTES]; // 32 bytes of data
    /// let key = crypto_secretbox::Key::from_bytes(&key_bytes).unwrap();
    /// ```
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
    ///
    /// This function generates a new random key suitable for use with
    /// the `seal` and `open` functions. The key is generated using
    /// libsodium's secure random number generator.
    ///
    /// ## Returns
    ///
    /// * `Self` - A new randomly generated key
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretbox;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = crypto_secretbox::Key::generate();
    ///
    /// // Use the key for encryption
    /// let message = b"Hello, world!";
    /// let nonce = crypto_secretbox::Nonce::generate(); // Generate a random nonce
    /// let ciphertext = crypto_secretbox::seal(message, &nonce, &key);
    /// ```
    pub fn generate() -> Self {
        let bytes = crate::random::bytes(KEYBYTES);
        Key::from_bytes(&bytes).unwrap()
    }

    /// Get the raw bytes of the key
    ///
    /// This function returns a reference to the internal byte array of the key.
    /// It's useful when you need to serialize the key for secure storage.
    ///
    /// ## Security Considerations
    ///
    /// Be extremely careful when handling the raw bytes of a secret key.
    /// They should never be logged, transmitted over an insecure network,
    /// or stored in plaintext.
    ///
    /// ## Returns
    ///
    /// * `&[u8]` - A reference to the key bytes
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretbox;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = crypto_secretbox::Key::generate();
    ///
    /// // Get the raw bytes of the key (handle with care!)
    /// let key_bytes = key.as_bytes();
    /// assert_eq!(key_bytes.len(), crypto_secretbox::KEYBYTES);
    /// ```
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

/// Encrypt a message using authenticated symmetric encryption (XSalsa20-Poly1305)
///
/// This function encrypts a message using the XSalsa20 stream cipher and authenticates
/// it using the Poly1305 message authentication code. The resulting ciphertext includes
/// both the encrypted message and the authentication tag.
///
/// ## Algorithm Details
///
/// The encryption process works as follows:
/// 1. The message is encrypted using XSalsa20 with the provided key and nonce
/// 2. A Poly1305 authentication tag is computed over the ciphertext
/// 3. The authentication tag is prepended to the ciphertext
///
/// ## Security Considerations
///
/// - The nonce must NEVER be reused with the same key
/// - For maximum security, generate a new random nonce for each message
/// - The ciphertext will be `MACBYTES` (16) bytes longer than the original message
///
/// ## Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `nonce` - A unique nonce
/// * `key` - The secret key to encrypt with
///
/// ## Returns
///
/// * `Vec<u8>` - The authenticated ciphertext
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_secretbox;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key and nonce
/// let key = crypto_secretbox::Key::generate();
/// let nonce = crypto_secretbox::Nonce::generate(); // A secure random nonce
///
/// // Encrypt a message
/// let message = b"Hello, world!";
/// let ciphertext = crypto_secretbox::seal(message, &nonce, &key);
///
/// // The ciphertext is longer than the message due to the authentication tag
/// assert_eq!(ciphertext.len(), message.len() + crypto_secretbox::MACBYTES);
/// ```
pub fn seal(message: &[u8], nonce: &Nonce, key: &Key) -> Vec<u8> {
    let mut ciphertext = vec![0u8; message.len() + MACBYTES];

    unsafe {
        // This operation cannot fail with valid inputs, which are guaranteed by our Rust types
        libsodium_sys::crypto_secretbox_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len().try_into().unwrap(),
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        );
    }

    ciphertext
}

/// Decrypt and verify a message using authenticated symmetric encryption (XSalsa20-Poly1305)
///
/// This function verifies the authentication tag and decrypts the ciphertext
/// that was created using the `seal` function. It ensures that the message
/// has not been tampered with and was encrypted with the correct key.
///
/// ## Algorithm Details
///
/// The decryption process works as follows:
/// 1. The Poly1305 authentication tag is verified
/// 2. If verification succeeds, the message is decrypted using XSalsa20
/// 3. If verification fails, an error is returned and no decryption is performed
///
/// ## Security Considerations
///
/// - Always check the return value for errors, which indicate authentication failure
/// - Use the same nonce that was used for encryption
/// - The ciphertext must be at least `MACBYTES` (16) bytes long
///
/// ## Arguments
///
/// * `ciphertext` - The authenticated ciphertext to decrypt
/// * `nonce` - The same nonce used for encryption
/// * `key` - The secret key to decrypt with
///
/// ## Returns
///
/// * `Result<Vec<u8>>` - The decrypted message or an error
///
/// ## Errors
///
/// Returns an error if:
/// - The nonce is not exactly `NONCEBYTES` bytes long
/// - The ciphertext is too short (less than `MACBYTES` bytes)
/// - Authentication fails (wrong key, tampered ciphertext, or wrong nonce)
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_secretbox;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key and nonce
/// let key = crypto_secretbox::Key::generate();
/// let nonce = crypto_secretbox::Nonce::generate();
///
/// // Encrypt a message
/// let message = b"Hello, world!";
/// let ciphertext = crypto_secretbox::seal(message, &nonce, &key);
///
/// // Decrypt the message
/// let decrypted = crypto_secretbox::open(&ciphertext, &nonce, &key).unwrap();
/// assert_eq!(decrypted, message);
///
/// // Attempting to decrypt with the wrong key will fail
/// let wrong_key = crypto_secretbox::Key::generate();
/// assert!(crypto_secretbox::open(&ciphertext, &nonce, &wrong_key).is_err());
///
/// // Tampering with the ciphertext will cause authentication to fail
/// let mut tampered = ciphertext.clone();
/// tampered[0] ^= 1; // Flip a bit
/// assert!(crypto_secretbox::open(&tampered, &nonce, &key).is_err());
/// ```
pub fn open(ciphertext: &[u8], nonce: &Nonce, key: &Key) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_secretbox_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len().try_into().unwrap(),
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

// Export submodules

/// XChaCha20-Poly1305 authenticated encryption
///
/// This submodule provides an alternative implementation of authenticated encryption
/// using XChaCha20 for encryption and Poly1305 for authentication. It is similar to
/// the functions in the parent module but uses XChaCha20 instead of XSalsa20.
///
/// The main advantage of XChaCha20-Poly1305 is its larger nonce size (192 bits vs 192 bits),
/// which makes it more suitable for applications where random nonces are preferred.
///
/// See the submodule documentation for more details.
pub mod xchacha20poly1305;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate();
        assert_eq!(key.as_bytes().len(), KEYBYTES);
    }

    #[test]
    fn test_encryption_decryption() {
        let key = Key::generate();
        let message = b"Hello, World!";
        let nonce = &Nonce::from_bytes([0u8; NONCEBYTES]);

        let ciphertext = seal(message, nonce, &key);
        let decrypted = open(&ciphertext, nonce, &key).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_decryption_failure() {
        let key = Key::generate();
        let wrong_key = Key::generate();
        let message = b"Hello, World!";
        let nonce = &Nonce::from_bytes([0u8; NONCEBYTES]);

        let ciphertext = seal(message, nonce, &key);
        assert!(open(&ciphertext, nonce, &wrong_key).is_err());
    }

    #[test]
    fn test_nonce_traits() {
        // Test TryFrom<&[u8]>
        let bytes = [0x42; NONCEBYTES];
        let nonce = Nonce::try_from(&bytes[..]).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Test invalid length
        let invalid_bytes = [0x42; NONCEBYTES - 1];
        assert!(Nonce::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; NONCEBYTES]>
        let bytes = [0x43; NONCEBYTES];
        let nonce2 = Nonce::from(bytes);
        assert_eq!(nonce2.as_bytes(), &bytes);

        // Test From<Nonce> for [u8; NONCEBYTES]
        let extracted: [u8; NONCEBYTES] = nonce2.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let nonce3 = Nonce::generate();
        let slice_ref: &[u8] = nonce3.as_ref();
        assert_eq!(slice_ref.len(), NONCEBYTES);
    }

    #[test]
    fn test_key_traits() {
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
