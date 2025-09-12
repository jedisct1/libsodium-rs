//! ChaCha20 stream cipher operations
//!
//! ChaCha20 is a stream cipher developed by Daniel J. Bernstein. It's designed to be
//! secure and efficient, with better diffusion properties than its predecessor Salsa20.
//!
//! ## Security Considerations
//!
//! - ChaCha20 uses an 8-byte nonce, which is relatively small. This means there's a
//!   higher risk of nonce reuse if you're encrypting many messages with the same key.
//! - For most applications, consider using XChaCha20 instead, which has a larger nonce.
//! - This is a raw stream cipher without authentication. For authenticated encryption,
//!   use `crypto_secretbox` instead.

use super::Key;
use crate::{Result, SodiumError};

/// Number of bytes in a ChaCha20 key (32 bytes)
pub const KEYBYTES: usize = libsodium_sys::crypto_stream_chacha20_KEYBYTES as usize;
/// Number of bytes in a ChaCha20 nonce (8 bytes)
pub const NONCEBYTES: usize = libsodium_sys::crypto_stream_chacha20_NONCEBYTES as usize;

/// A nonce (number used once) for ChaCha20 operations
///
/// This struct represents a nonce for use with the ChaCha20 stream cipher.
/// A nonce must be unique for each message encrypted with the same key to maintain security.
/// ChaCha20 uses a 64-bit (8-byte) nonce, which is relatively small. For applications
/// that need to encrypt many messages with the same key, consider using XChaCha20 instead,
/// which has a larger nonce size (192 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    /// Generate a random nonce for use with ChaCha20 functions
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
    /// use sodium::crypto_stream::chacha20;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = chacha20::Nonce::generate();
    /// assert_eq!(nonce.as_ref().len(), chacha20::NONCEBYTES);
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCEBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from bytes of the correct length
    ///
    /// ## Arguments
    ///
    /// * `bytes` - Bytes of length NONCEBYTES
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

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::convert::TryFrom<&[u8]> for Nonce {
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

/// Generate a stream of random bytes using ChaCha20
///
/// This function generates a deterministic stream of pseudo-random bytes using the
/// ChaCha20 algorithm. The same (key, nonce) combination will always produce the
/// same stream of bytes.
///
/// # Arguments
/// * `len` - The number of bytes to generate
/// * `nonce` - The nonce to use
/// * `key` - The key to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The generated stream of bytes
///
/// # Errors
/// Returns an error if the nonce is not exactly `NONCEBYTES` bytes
///
/// # Security Considerations
/// - The nonce must be unique for each stream generated with the same key.
/// - If you need to generate multiple streams with the same key, make sure to use
///   different nonces for each one.
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_stream;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = crypto_stream::Key::generate().unwrap();
///
/// // Create a nonce (in a real application, this should be unique for each stream)
/// let nonce = crypto_stream::chacha20::Nonce::from_bytes([0u8; crypto_stream::chacha20::NONCEBYTES]);
///
/// // Generate 32 bytes of pseudo-random data
/// let random_data = crypto_stream::chacha20::stream(32, &nonce, &key).unwrap();
/// assert_eq!(random_data.len(), 32);
/// ```
pub fn stream(len: usize, nonce: &Nonce, key: &Key) -> Result<Vec<u8>> {
    let mut output = vec![0u8; len];
    unsafe {
        libsodium_sys::crypto_stream_chacha20(
            output.as_mut_ptr(),
            len as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        );
    }

    Ok(output)
}

/// Encrypt or decrypt a message using ChaCha20
///
/// This function can be used for both encryption and decryption.
/// ChaCha20 is a stream cipher, so encryption and decryption are the same operation.
///
/// # Arguments
/// * `message` - The message to encrypt or decrypt
/// * `nonce` - The nonce to use
/// * `key` - The key to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The encrypted or decrypted message
///
/// # Errors
/// Returns an error if the nonce is not exactly `NONCEBYTES` bytes
///
/// # Security Considerations
/// - The nonce must be unique for each message encrypted with the same key.
/// - If you encrypt multiple messages with the same key, make sure to use
///   different nonces for each one.
/// - This function does not provide authentication. An attacker could modify
///   the ciphertext, and the changes would be reflected in the decrypted message.
///   For authenticated encryption, use `crypto_secretbox` instead.
///
/// # Example
/// ```
/// use libsodium_rs as sodium;
/// use sodium::crypto_stream;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random key
/// let key = crypto_stream::Key::generate().unwrap();
///
/// // Create a nonce (in a real application, this should be unique for each message)
/// let nonce = crypto_stream::chacha20::Nonce::generate();
///
/// // Message to encrypt
/// let message = b"This is a secret message";
///
/// // Encrypt the message
/// let encrypted = crypto_stream::chacha20::stream_xor(message, &nonce, &key).unwrap();
///
/// // Decrypt the message
/// let decrypted = crypto_stream::chacha20::stream_xor(&encrypted, &nonce, &key).unwrap();
///
/// assert_eq!(&decrypted, message);
/// ```
pub fn stream_xor(message: &[u8], nonce: &Nonce, key: &Key) -> Result<Vec<u8>> {
    let mut output = vec![0u8; message.len()];
    unsafe {
        libsodium_sys::crypto_stream_chacha20_xor(
            output.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            key.as_bytes().as_ptr(),
        );
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
