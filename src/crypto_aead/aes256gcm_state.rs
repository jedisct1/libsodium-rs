use crate::crypto_aead::aes256gcm::{Key, Nonce, ABYTES, NPUBBYTES};
use crate::{Result, SodiumError};
use std::convert::TryInto;

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
            libsodium_sys::crypto_aead_aes256gcm_beforenm(
                &mut *state,
                key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "precomputation failed".into(),
            ));
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
/// * For random nonces, use `Nonce::generate()`
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
/// * For random nonces, use `Nonce::generate()`
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
            "tag must be exactly {} bytes",
            ABYTES
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
