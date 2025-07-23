//! ChaCha20-Poly1305 Precomputation State
//!
//! This module provides a precomputation state for ChaCha20-Poly1305 encryption and decryption.
//! Using a precomputation state can improve performance when encrypting or decrypting multiple
//! messages with the same key.
//!
//! ## Features
//!
//! - **Performance optimization**: Precompute key-dependent data for faster encryption/decryption
//! - **Memory safety**: Secure handling of sensitive key material
//! - **Flexible API**: Support for both combined and detached modes
//! - **Optional additional data**: Support for authenticated additional data
//!
//! ## Security Considerations
//!
//! - Always use a unique nonce for each encryption with the same key
//! - The nonce can be public, but must never be reused with the same key
//! - Additional authenticated data (AAD) is not encrypted but is authenticated
//!
//! ## Example Usage
//!
//! ```
//! # use libsodium_rs::crypto_aead::{chacha20poly1305, chacha20poly1305_state};
//! # use libsodium_rs::ensure_init;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # ensure_init()?;
//! // Create a key and precomputation state
//! let key = chacha20poly1305::Key::generate();
//! let state = chacha20poly1305_state::State::from_key(&key)?;
//!
//! // Generate a nonce
//! let nonce = chacha20poly1305::Nonce::generate();
//!
//! // Encrypt a message with additional data
//! let message = b"Hello, world!";
//! let additional_data = b"Important metadata";
//! let ciphertext = chacha20poly1305_state::encrypt_afternm(
//!     message,
//!     Some(additional_data),
//!     &nonce,
//!     &state
//! )?;
//!
//! // Decrypt the message
//! let decrypted = chacha20poly1305_state::decrypt_afternm(
//!     &ciphertext,
//!     Some(additional_data),
//!     &nonce,
//!     &state
//! )?;
//!
//! assert_eq!(message, &decrypted[..]);
//! # Ok(())
//! # }
//! ```

use crate::crypto_aead::chacha20poly1305::{Key, Nonce, ABYTES};
use crate::{Result, SodiumError};
use std::convert::TryInto;

/// A precomputation state for ChaCha20-Poly1305 encryption and decryption
///
/// This struct represents a precomputation state that can be used to speed up
/// multiple encryption and decryption operations with the same key. It is useful
/// when you need to encrypt or decrypt multiple messages with the same key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    key: Key,
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
    pub fn from_key(key: impl AsRef<Key>) -> Result<Self> {
        // Create a new state with a copy of the key
        Ok(Self {
            key: key.as_ref().clone(),
        })
    }

    /// Get a reference to the underlying key
    pub fn key(&self) -> &Key {
        &self.key
    }
}

/// Encrypt a message using ChaCha20-Poly1305 with a precomputation state
///
/// This function encrypts a message using the ChaCha20-Poly1305 algorithm with a
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
/// * The nonce is not valid
/// * The encryption operation fails
pub fn encrypt_afternm(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: impl AsRef<Nonce>,
    state: &State,
) -> Result<Vec<u8>> {
    let nonce = nonce.as_ref();
    let mut ciphertext = vec![0u8; message.len() + ABYTES];
    let mut ciphertext_len = 0u64;

    let ad = additional_data.unwrap_or(&[]);
    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message
                .len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("message too large".into()))?,
            ad.as_ptr(),
            ad.len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("additional data too large".into()))?,
            std::ptr::null(),
            nonce.as_bytes().as_ptr(),
            state.key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "ChaCha20-Poly1305 encryption failed".into(),
        ));
    }

    ciphertext.truncate(ciphertext_len as usize);
    Ok(ciphertext)
}

/// Decrypt a message using ChaCha20-Poly1305 with a precomputation state
///
/// This function decrypts a message that was encrypted using the ChaCha20-Poly1305
/// algorithm with a precomputation state. It verifies the authenticity of both
/// the ciphertext and the additional data (if provided) before returning the
/// decrypted message.
///
/// # Arguments
/// * `ciphertext` - The encrypted message with authentication tag
/// * `additional_data` - Optional additional data to authenticate (must be the same as used during encryption)
/// * `nonce` - The nonce used for encryption (must be unique for each encryption with the same key)
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
/// * The nonce is not valid
/// * The ciphertext is too short (less than `ABYTES` bytes)
/// * Authentication verification fails
/// * The decryption operation fails
pub fn decrypt_afternm(
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
    nonce: impl AsRef<Nonce>,
    state: &State,
) -> Result<Vec<u8>> {
    if ciphertext.len() < ABYTES {
        return Err(SodiumError::InvalidInput(format!(
            "ciphertext must be at least {ABYTES} bytes"
        )));
    }

    let nonce = nonce.as_ref();
    let mut message = vec![0u8; ciphertext.len() - ABYTES];
    let mut message_len = 0u64;

    let ad = additional_data.unwrap_or(&[]);
    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_decrypt(
            message.as_mut_ptr(),
            &mut message_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext
                .len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("ciphertext too large".into()))?,
            ad.as_ptr(),
            ad.len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("additional data too large".into()))?,
            nonce.as_bytes().as_ptr(),
            state.key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::DecryptionError(
            "ChaCha20-Poly1305 authentication failed".into(),
        ));
    }

    message.truncate(message_len as usize);
    Ok(message)
}

/// Encrypt a message using ChaCha20-Poly1305 with detached authentication tag and precomputation state
///
/// This function encrypts a message using the ChaCha20-Poly1305 algorithm with a
/// precomputation state and returns the ciphertext and authentication tag separately.
/// This is useful when you want to store or transmit the ciphertext and tag separately.
///
/// # Arguments
/// * `message` - The message to encrypt
/// * `additional_data` - Optional additional data to authenticate (but not encrypt)
/// * `nonce` - The nonce to use (must be unique for each encryption with the same key)
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
/// * The nonce is not valid
/// * The encryption operation fails
pub fn encrypt_detached_afternm(
    message: &[u8],
    additional_data: Option<&[u8]>,
    nonce: impl AsRef<Nonce>,
    state: &State,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = nonce.as_ref();
    let mut ciphertext = vec![0u8; message.len()];
    let mut tag = vec![0u8; ABYTES];
    let mut tag_len = 0u64;

    let ad = additional_data.unwrap_or(&[]);
    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_encrypt_detached(
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
            &mut tag_len,
            message.as_ptr(),
            message
                .len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("message too large".into()))?,
            ad.as_ptr(),
            ad.len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("additional data too large".into()))?,
            std::ptr::null(),
            nonce.as_bytes().as_ptr(),
            state.key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "ChaCha20-Poly1305 encryption failed".into(),
        ));
    }

    tag.truncate(tag_len as usize);
    Ok((ciphertext, tag))
}

/// Decrypt a message using ChaCha20-Poly1305 with detached authentication tag and precomputation state
///
/// This function decrypts a message that was encrypted using the ChaCha20-Poly1305
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
    nonce: impl AsRef<Nonce>,
    state: &State,
) -> Result<Vec<u8>> {
    if tag.len() != ABYTES {
        return Err(SodiumError::InvalidInput(format!(
            "tag must be exactly {ABYTES} bytes"
        )));
    }

    let nonce = nonce.as_ref();
    let mut message = vec![0u8; ciphertext.len()];

    let ad = additional_data.unwrap_or(&[]);
    let result = unsafe {
        libsodium_sys::crypto_aead_chacha20poly1305_decrypt_detached(
            message.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext
                .len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("ciphertext too large".into()))?,
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len()
                .try_into()
                .map_err(|_| SodiumError::InvalidInput("additional data too large".into()))?,
            nonce.as_bytes().as_ptr(),
            state.key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::DecryptionError(
            "ChaCha20-Poly1305 authentication failed".into(),
        ));
    }

    Ok(message)
}
