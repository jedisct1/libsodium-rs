//! # XChaCha20-Poly1305 Secret-key Authenticated Encryption
//!
//! This module provides authenticated encryption using XChaCha20 for encryption
//! and Poly1305 for authentication. It offers an alternative to the default
//! XSalsa20-Poly1305 implementation in the parent module with a larger nonce size.
//!
//! ## Overview
//!
//! XChaCha20-Poly1305 is a state-of-the-art authenticated encryption algorithm that:
//!
//! 1. Uses XChaCha20 stream cipher for encryption (an extended-nonce variant of ChaCha20)
//! 2. Uses Poly1305 for message authentication
//! 3. Provides 256-bit security for encryption
//! 4. Features a 192-bit (24-byte) nonce, which is large enough for random generation
//!
//! ## Advantages over XSalsa20-Poly1305
//!
//! - **Larger nonce space**: 192 bits vs 192 bits (both are large enough for random nonces)
//! - **Modern design**: Based on the widely-reviewed ChaCha20 algorithm
//! - **Performance**: Often faster on modern CPUs without dedicated AES instructions
//! - **Constant-time implementation**: Resistant to timing attacks
//!
//! ## Basic Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretbox::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = xchacha20poly1305::Key::generate();
//!
//! // Generate a random nonce (must be unique for each message with the same key)
//! let nonce = xchacha20poly1305::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Encrypt the message
//! let ciphertext = xchacha20poly1305::encrypt(message, &nonce, &key);
//!
//! // Decrypt the message
//! let decrypted = xchacha20poly1305::decrypt(&ciphertext, &nonce, &key).unwrap();
//! assert_eq!(decrypted, message);
//! ```
//!
//! ## Detached Mode
//!
//! This module also supports "detached" mode where the authentication tag is
//! separate from the ciphertext:
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretbox::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a key and nonce
//! let key = xchacha20poly1305::Key::generate();
//! let nonce = xchacha20poly1305::Nonce::generate(); // Generate a random nonce
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Encrypt with detached MAC
//! let (ciphertext, mac) = xchacha20poly1305::encrypt_detached(message, &nonce, &key);
//!
//! // Decrypt with detached MAC
//! let decrypted = xchacha20poly1305::decrypt_detached(&ciphertext, &mac, &nonce, &key).unwrap();
//! assert_eq!(decrypted, message);
//! ```
//!
//! ## Security Considerations
//!
//! - **Never reuse a nonce with the same key**: This would completely compromise security
//! - **Store keys securely**: The secret key must be kept confidential
//! - **Verify decryption**: Always check for errors when decrypting
//! - **Consider key derivation**: For user-supplied passwords, use `crypto_pwhash` to derive keys
//! - **Random nonces are safe**: With a 192-bit nonce space, randomly generated nonces
//!   have a negligible chance of collision

use crate::{Result, SodiumError};
use libc;

/// Number of bytes in a key (32)
///
/// This is the size of the secret key used for XChaCha20-Poly1305 encryption.
/// The key should be randomly generated using `Key::generate()` or derived
/// from a password using the `crypto_pwhash` module.
///
/// XChaCha20-Poly1305 uses 256-bit keys (32 bytes) for maximum security.
pub const KEYBYTES: usize = libsodium_sys::crypto_secretbox_xchacha20poly1305_KEYBYTES as usize;

/// Number of bytes in a nonce (24)
///
/// This is the size of the nonce (number used once) for XChaCha20-Poly1305 encryption.
/// The nonce must be unique for each message encrypted with the same key.
///
/// XChaCha20-Poly1305 uses a 192-bit nonce (24 bytes), which is large enough that
/// randomly generated nonces have a negligible probability of collision, even for
/// a very large number of messages with the same key.
pub const NONCEBYTES: usize = libsodium_sys::crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize;

/// A nonce (number used once) for XChaCha20-Poly1305 operations
///
/// This struct represents a nonce for use with the XChaCha20-Poly1305 encryption algorithm.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// XChaCha20-Poly1305 uses a 192-bit nonce, which is large enough that random nonces can be
/// safely used without worrying about collisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    /// Generate a random nonce for use with XChaCha20-Poly1305 functions
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
    /// use sodium::crypto_secretbox::xchacha20poly1305;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = xchacha20poly1305::Nonce::generate();
    /// assert_eq!(nonce.as_ref().len(), xchacha20poly1305::NONCEBYTES);
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
    pub fn try_from_slice(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != NONCEBYTES {
            return Err(crate::SodiumError::InvalidNonce(format!(
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

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = crate::SodiumError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl From<[u8; NONCEBYTES]> for Nonce {
    fn from(bytes: [u8; NONCEBYTES]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Nonce> for [u8; NONCEBYTES] {
    fn from(nonce: Nonce) -> Self {
        nonce.0
    }
}

/// Number of bytes in a MAC (message authentication code) (16)
///
/// This is the size of the authentication tag added to each encrypted message.
/// The MAC ensures the integrity and authenticity of the ciphertext.
/// It is automatically handled by the `encrypt` and `decrypt` functions, or
/// can be managed separately using the `encrypt_detached` and `decrypt_detached` functions.
///
/// XChaCha20-Poly1305 uses a 128-bit Poly1305 MAC (16 bytes), which provides
/// strong protection against forgery attempts.
pub const MACBYTES: usize = libsodium_sys::crypto_secretbox_xchacha20poly1305_MACBYTES as usize;

/// A secret key for XChaCha20-Poly1305 authenticated encryption
///
/// This struct represents a secret key used for XChaCha20-Poly1305 authenticated encryption.
/// The key should be kept confidential and should be randomly generated or derived
/// from a strong password.
///
/// ## Size
///
/// A secret key is always exactly `KEYBYTES` (32) bytes, providing 256-bit security.
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
/// use sodium::crypto_secretbox::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = xchacha20poly1305::Key::generate();
///
/// // Create a key from existing bytes (e.g., from secure storage)
/// let key_bytes = [0x42; xchacha20poly1305::KEYBYTES]; // Example bytes
/// let key_from_bytes = xchacha20poly1305::Key::from_bytes(&key_bytes).unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

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
    /// use sodium::crypto_secretbox::xchacha20poly1305;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a key from bytes (e.g., from secure storage)
    /// let key_bytes = [0x42; xchacha20poly1305::KEYBYTES]; // 32 bytes of data
    /// let key = xchacha20poly1305::Key::from_bytes(&key_bytes).unwrap();
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
    /// the `encrypt` and `decrypt` functions. The key is generated using
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
    /// use sodium::crypto_secretbox::xchacha20poly1305;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = xchacha20poly1305::Key::generate();
    ///
    /// // Use the key for encryption
    /// let message = b"Hello, world!";
    /// let nonce = xchacha20poly1305::Nonce::generate();
    /// let ciphertext = xchacha20poly1305::encrypt(message, &nonce, &key);
    /// ```
    pub fn generate() -> Self {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            // Use randombytes to generate a random key since the specific keygen function isn't available
            libsodium_sys::randombytes_buf(key.as_mut_ptr() as *mut libc::c_void, KEYBYTES);
        }
        Key(key)
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
    /// use sodium::crypto_secretbox::xchacha20poly1305;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = xchacha20poly1305::Key::generate();
    ///
    /// // Get the raw bytes of the key (handle with care!)
    /// let key_bytes = key.as_bytes();
    /// assert_eq!(key_bytes.len(), xchacha20poly1305::KEYBYTES);
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
    type Error = crate::SodiumError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(value)
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

/// Encrypt a message using XChaCha20-Poly1305 authenticated encryption
///
/// This function encrypts a message using the XChaCha20 stream cipher and authenticates
/// it using the Poly1305 message authentication code. The resulting ciphertext includes
/// both the encrypted message and the authentication tag.
///
/// ## Algorithm Details
///
/// The encryption process works as follows:
/// 1. The message is encrypted using XChaCha20 with the provided key and nonce
/// 2. A Poly1305 authentication tag is computed over the ciphertext
/// 3. The authentication tag is prepended to the ciphertext
///
/// ## Security Considerations
///
/// - The nonce must NEVER be reused with the same key
/// - With XChaCha20-Poly1305's 192-bit nonce, random nonces can be safely used
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
/// use sodium::crypto_secretbox::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key and nonce
/// let key = xchacha20poly1305::Key::generate();
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Encrypt a message
/// let message = b"Hello, world!";
/// let ciphertext = xchacha20poly1305::encrypt(message, &nonce, &key);
///
/// // The ciphertext is longer than the message due to the authentication tag
/// assert_eq!(ciphertext.len(), message.len() + xchacha20poly1305::MACBYTES);
/// ```
pub fn encrypt(message: &[u8], nonce: &Nonce, key: &Key) -> Vec<u8> {
    let mut ciphertext = vec![0u8; message.len() + MACBYTES];

    unsafe {
        // This operation cannot fail with valid inputs, which are guaranteed by our Rust types
        libsodium_sys::crypto_secretbox_xchacha20poly1305_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        );
    }

    ciphertext
}

/// Decrypt and verify a message using XChaCha20-Poly1305 authenticated encryption
///
/// This function verifies the authentication tag and decrypts the ciphertext
/// that was created using the `encrypt` function. It ensures that the message
/// has not been tampered with and was encrypted with the correct key.
///
/// ## Algorithm Details
///
/// The decryption process works as follows:
/// 1. The Poly1305 authentication tag is verified
/// 2. If verification succeeds, the message is decrypted using XChaCha20
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
/// use sodium::crypto_secretbox::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key and nonce
/// let key = xchacha20poly1305::Key::generate();
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Encrypt a message
/// let message = b"Hello, world!";
/// let ciphertext = xchacha20poly1305::encrypt(message, &nonce, &key);
///
/// // Decrypt the message
/// let decrypted = xchacha20poly1305::decrypt(&ciphertext, &nonce, &key).unwrap();
/// assert_eq!(decrypted, message);
///
/// // Attempting to decrypt with the wrong key will fail
/// let wrong_key = xchacha20poly1305::Key::generate();
/// assert!(xchacha20poly1305::decrypt(&ciphertext, &nonce, &wrong_key).is_err());
///
/// // Tampering with the ciphertext will cause authentication to fail
/// let mut tampered = ciphertext.clone();
/// tampered[0] ^= 1; // Flip a bit
/// assert!(xchacha20poly1305::decrypt(&tampered, &nonce, &key).is_err());
/// ```
pub fn decrypt(ciphertext: &[u8], nonce: &Nonce, key: &Key) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_secretbox_xchacha20poly1305_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// Encrypt a message using XChaCha20-Poly1305 with detached MAC
///
/// This function encrypts a message using XChaCha20-Poly1305 but returns the
/// authentication tag separately from the ciphertext. This is useful in scenarios
/// where you want to store or transmit the tag and ciphertext separately.
///
/// ## Algorithm Details
///
/// The encryption process works as follows:
/// 1. The message is encrypted using XChaCha20 with the provided key and nonce
/// 2. A Poly1305 authentication tag is computed over the ciphertext
/// 3. The ciphertext and authentication tag are returned separately
///
/// ## Use Cases
///
/// Detached mode is useful when:
/// - You need to store the MAC separately from the ciphertext
/// - You want to implement custom authenticated encryption protocols
/// - You need to add additional authenticated data (not directly supported in this API)
///
/// ## Security Considerations
///
/// - The nonce must NEVER be reused with the same key
/// - Both the ciphertext and MAC must be stored/transmitted securely
/// - The MAC must be verified before decryption to ensure authenticity
///
/// ## Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `nonce` - A unique nonce
/// * `key` - The secret key to encrypt with
///
/// ## Returns
///
/// * `(Vec<u8>, [u8; MACBYTES])` - A tuple containing:
///   - The ciphertext (same length as the original message)
///   - The authentication tag (`MACBYTES` bytes)
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_secretbox::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key and nonce
/// let key = xchacha20poly1305::Key::generate();
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Encrypt a message with detached MAC
/// let message = b"Hello, world!";
/// let (ciphertext, mac) = xchacha20poly1305::encrypt_detached(message, &nonce, &key);
///
/// // The ciphertext is the same length as the original message
/// assert_eq!(ciphertext.len(), message.len());
/// // The MAC is MACBYTES long
/// assert_eq!(mac.len(), xchacha20poly1305::MACBYTES);
/// ```
pub fn encrypt_detached(message: &[u8], nonce: &Nonce, key: &Key) -> (Vec<u8>, [u8; MACBYTES]) {
    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = [0u8; MACBYTES];

    unsafe {
        // This operation cannot fail with valid inputs, which are guaranteed by our Rust types
        libsodium_sys::crypto_secretbox_xchacha20poly1305_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        );
    }

    (ciphertext, mac)
}

/// Decrypt and verify a message using XChaCha20-Poly1305 with detached MAC
///
/// This function verifies the detached authentication tag and decrypts the ciphertext
/// that was created using the `encrypt_detached` function. It ensures that the message
/// has not been tampered with and was encrypted with the correct key.
///
/// ## Algorithm Details
///
/// The decryption process works as follows:
/// 1. The Poly1305 authentication tag is verified against the ciphertext
/// 2. If verification succeeds, the message is decrypted using XChaCha20
/// 3. If verification fails, an error is returned and no decryption is performed
///
/// ## Security Considerations
///
/// - Always check the return value for errors, which indicate authentication failure
/// - Use the same nonce that was used for encryption
/// - Both the ciphertext and MAC must be verified to ensure authenticity
///
/// ## Arguments
///
/// * `ciphertext` - The ciphertext to decrypt
/// * `mac` - The authentication tag (`MACBYTES` bytes) to verify
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
/// - The MAC is not exactly `MACBYTES` bytes long
/// - Authentication fails (wrong key, tampered ciphertext, wrong nonce, or wrong MAC)
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_secretbox::xchacha20poly1305;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key and nonce
/// let key = xchacha20poly1305::Key::generate();
/// let nonce = xchacha20poly1305::Nonce::generate();
///
/// // Encrypt a message with detached MAC
/// let message = b"Hello, world!";
/// let (ciphertext, mac) = xchacha20poly1305::encrypt_detached(message, &nonce, &key);
///
/// // Decrypt the message with detached MAC
/// let decrypted = xchacha20poly1305::decrypt_detached(&ciphertext, &mac, &nonce, &key).unwrap();
/// assert_eq!(decrypted, message);
///
/// // Tampering with the ciphertext will cause authentication to fail
/// let mut tampered_ciphertext = ciphertext.clone();
/// if !tampered_ciphertext.is_empty() {
///     tampered_ciphertext[0] ^= 1; // Flip a bit
/// }
/// assert!(xchacha20poly1305::decrypt_detached(&tampered_ciphertext, &mac, &nonce, &key).is_err());
///
/// // Tampering with the MAC will also cause authentication to fail
/// let mut tampered_mac = mac;
/// tampered_mac[0] ^= 1; // Flip a bit
/// assert!(xchacha20poly1305::decrypt_detached(&ciphertext, &tampered_mac, &nonce, &key).is_err());
/// ```
pub fn decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8; MACBYTES],
    nonce: &Nonce,
    key: &Key,
) -> Result<Vec<u8>> {
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_secretbox_xchacha20poly1305_open_detached(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
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

    #[test]
    fn test_key_generation() {
        let key = Key::generate();
        assert_eq!(key.as_bytes().len(), KEYBYTES);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, XChaCha20-Poly1305!";

        // Encrypt the message
        let ciphertext = encrypt(message, &nonce, &key);

        // Decrypt the message
        let decrypted = decrypt(&ciphertext, &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_decrypt_detached() {
        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, XChaCha20-Poly1305 with detached MAC!";

        // Encrypt the message with detached MAC
        let (ciphertext, mac) = encrypt_detached(message, &nonce, &key);

        // Decrypt the message with detached MAC
        let decrypted = decrypt_detached(&ciphertext, &mac, &nonce, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decrypt_failure() {
        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"Hello, XChaCha20-Poly1305!";

        // Encrypt the message
        let mut ciphertext = encrypt(message, &nonce, &key);

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        // Decryption should fail
        assert!(decrypt(&ciphertext, &nonce, &key).is_err());
    }

    #[test]
    fn test_nonce_trait_implementations() {
        // Test TryFrom<&[u8]>
        let nonce_bytes = [0x42; NONCEBYTES];
        let nonce = Nonce::try_from(&nonce_bytes[..]).unwrap();
        assert_eq!(nonce.as_ref(), &nonce_bytes);

        // Test with wrong size
        let wrong_size = [0x42; NONCEBYTES - 1];
        assert!(Nonce::try_from(&wrong_size[..]).is_err());

        // Test From<[u8; NONCEBYTES]>
        let nonce2 = Nonce::from(nonce_bytes);
        assert_eq!(nonce2.as_ref(), &nonce_bytes);

        // Test From<Nonce> for [u8; NONCEBYTES]
        let bytes: [u8; NONCEBYTES] = nonce2.into();
        assert_eq!(bytes, nonce_bytes);
    }

    #[test]
    fn test_key_trait_implementations() {
        // Test AsRef<[u8]>
        let key = Key::generate();
        let key_ref: &[u8] = key.as_ref();
        assert_eq!(key_ref.len(), KEYBYTES);

        // Test TryFrom<&[u8]>
        let key_bytes = [0x42; KEYBYTES];
        let key2 = Key::try_from(&key_bytes[..]).unwrap();
        assert_eq!(key2.as_ref(), &key_bytes);

        // Test with wrong size
        let wrong_size = [0x42; KEYBYTES - 1];
        assert!(Key::try_from(&wrong_size[..]).is_err());

        // Test From<[u8; KEYBYTES]>
        let key3 = Key::from(key_bytes);
        assert_eq!(key3.as_ref(), &key_bytes);

        // Test From<Key> for [u8; KEYBYTES]
        let bytes: [u8; KEYBYTES] = key3.into();
        assert_eq!(bytes, key_bytes);
    }
}
