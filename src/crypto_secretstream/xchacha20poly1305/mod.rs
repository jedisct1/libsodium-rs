//! # XChaCha20-Poly1305 Secret Stream Encryption
//!
//! This module provides a high-level API for encrypting and decrypting streams of data
//! using the XChaCha20-Poly1305 authenticated encryption algorithm.
//!
//! ## Features
//!
//! - Messages cannot be truncated, removed, reordered, duplicated or modified without detection
//! - The same sequence encrypted twice will produce different ciphertexts
//! - Authentication tags are added to each encrypted message for early corruption detection
//! - Each message can include additional authenticated data (AAD)
//! - Messages can have different sizes
//! - No practical limits to the total length of the stream or number of messages
//! - Rekeying: at any point, it's possible to "forget" the key used to encrypt previous messages
//!
//! ## Usage
//!
//! ```
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretstream::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a key
//! let key = xchacha20poly1305::Key::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, secret world!";
//! let additional_data = b"message metadata";
//!
//! // Initialize encryption
//! let (mut push_state, header) = xchacha20poly1305::PushState::init_push(&key).unwrap();
//!
//! // Encrypt a message
//! let ciphertext = push_state.push(
//!     message,
//!     Some(additional_data),
//!     xchacha20poly1305::TAG_MESSAGE
//! ).unwrap();
//!
//! // Initialize decryption
//! let mut pull_state = xchacha20poly1305::PullState::init_pull(&header, &key).unwrap();
//!
//! // Decrypt the message
//! let (decrypted, tag) = pull_state.pull(&ciphertext, Some(additional_data)).unwrap();
//!
//! assert_eq!(&decrypted, message);
//! assert_eq!(tag, xchacha20poly1305::TAG_MESSAGE);
//! ```

use crate::{Result, SodiumError};
use libc;
use std::convert::TryFrom;

/// Number of bytes in a key (32 bytes)
pub const KEYBYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;

/// Number of bytes in a header (24 bytes)
///
/// The header must be sent/stored before the encrypted messages, as it is required for decryption.
/// The header content doesn't have to be secret, but decryption with a different header will fail.
pub const HEADERBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;

/// Number of additional bytes for authentication (17 bytes)
///
/// This is the number of bytes added to each encrypted message for authentication.
pub const ABYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

/// Tag for a standard message (0)
///
/// This is the most common tag that doesn't add any information about the nature of the message.
pub const TAG_MESSAGE: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8;

/// Tag for the final message (3)
///
/// Indicates that the message marks the end of the stream and erases the secret key
/// used to encrypt the previous sequence.
pub const TAG_FINAL: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8;

/// Tag for a message that completes a logical chunk (1)
///
/// Indicates that the message marks the end of a set of messages, but not the end of the stream.
/// For example, a large JSON string sent as multiple chunks can use this tag to indicate
/// that the string is complete and can be processed, but the stream itself is not closed.
pub const TAG_PUSH: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8;

/// Tag for a message that triggers rekeying (2)
///
/// Using this tag will "forget" the key used to encrypt this message and the previous ones,
/// and derive a new secret key for subsequent messages.
pub const TAG_REKEY: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8;

fn validate_message_len(message_len: usize) -> Result<()> {
    let max = unsafe { libsodium_sys::crypto_secretstream_xchacha20poly1305_messagebytes_max() };
    if message_len > max {
        return Err(SodiumError::InvalidInput("message too large".into()));
    }
    Ok(())
}

fn message_len_from_ciphertext_len(ciphertext_len: usize) -> Result<usize> {
    let message_len = ciphertext_len
        .checked_sub(ABYTES)
        .ok_or_else(|| SodiumError::InvalidInput("ciphertext too short".into()))?;
    validate_message_len(message_len)?;
    Ok(message_len)
}

/// A secret key for XChaCha20-Poly1305 secretstream
///
/// This key is used to initialize the encryption and decryption states.
/// It should be kept secret and can be generated randomly or derived from a password.
///
/// The key size is 32 bytes (256 bits).
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generate a new key from existing bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte slice of exactly KEYBYTES length (32 bytes)
    ///
    /// # Returns
    /// * `Result<Self>` - A new key or an error if the input is invalid
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::Key;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a key from existing bytes
    /// let key_bytes = [0x42; 32]; // 32 bytes of data
    /// let key = Key::from_bytes(&key_bytes).unwrap();
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
    /// This is the recommended way to create a new key for encryption.
    /// The key is generated using libsodium's secure random number generator.
    ///
    /// # Returns
    /// * `Self` - A new randomly generated key
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::Key;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random key
    /// let key = Key::generate();
    /// ```
    pub fn generate() -> Self {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_keygen(key.as_mut_ptr());
        }
        Key(key)
    }

    /// Get the bytes of the key
    ///
    /// # Returns
    /// * `&[u8]` - Reference to the key bytes
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

/// State for XChaCha20-Poly1305 secretstream encryption/decryption
pub struct State {
    state: Box<libsodium_sys::crypto_secretstream_xchacha20poly1305_state>,
    finalized: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        // Securely clear the state when dropped
        unsafe {
            // Use sodium_memzero to clear the state
            libsodium_sys::sodium_memzero(
                self.state.as_mut() as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libsodium_sys::crypto_secretstream_xchacha20poly1305_state>(),
            );
        }
    }
}

impl State {
    fn new() -> Self {
        State {
            state: Box::new(unsafe { std::mem::zeroed() }),
            finalized: false,
        }
    }
}

impl AsMut<libsodium_sys::crypto_secretstream_xchacha20poly1305_state> for State {
    fn as_mut(&mut self) -> &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state {
        self.state.as_mut()
    }
}

/// Push state for XChaCha20-Poly1305 secretstream encryption
///
/// This state is used to encrypt messages in a stream. It maintains the internal
/// state required for the encryption process, including nonces and authentication data.
///
/// ## Overview
///
/// The `PushState` is responsible for:
/// - Initializing the encryption state with a secret key
/// - Generating a header that must be transmitted to the recipient
/// - Encrypting messages with authentication tags
/// - Handling additional authenticated data (optional)
/// - Supporting different message tags (regular, push, rekey, final)
/// - Providing forward secrecy through rekeying
///
/// ## Workflow
///
/// 1. Initialize the encryption state with `PushState::init_push()`
/// 2. Store/transmit the returned header (required for decryption)
/// 3. Encrypt messages with `push()`, specifying a tag for each message
/// 4. Optionally rekey the state with `rekey()` for long-running streams
/// 5. Mark the end of the stream with `TAG_FINAL` when encrypting the last message
///
/// ## Security Considerations
///
/// - The header is not secret but must be transmitted intact
/// - Each message can have different sizes
/// - Messages cannot be reordered, removed, or modified without detection
/// - Using `TAG_FINAL` for the last message provides the strongest security guarantees
/// - Rekeying provides forward secrecy (compromise of current key doesn't expose previous messages)
///
/// The state should be initialized with `PushState::init_push()` and then used to encrypt
/// messages with the `push()` method.
pub struct PushState(State);

impl PushState {
    /// Initialize a new encryption state
    ///
    /// This function initializes a state for encrypting a stream of messages.
    /// It generates a header that must be stored/transmitted before the encrypted messages,
    /// as it will be required for decryption.
    ///
    /// ## Algorithm Details
    ///
    /// The initialization process:
    /// 1. Derives an initial state from the provided key
    /// 2. Generates a unique header containing the information needed for decryption
    /// 3. Sets up internal counters and authentication state
    ///
    /// The XChaCha20-Poly1305 construction uses:
    /// - XChaCha20 stream cipher for encryption (256-bit security, 192-bit nonce)
    /// - Poly1305 for message authentication
    /// - A key derivation mechanism to generate unique subkeys for each message
    ///
    /// ## Security Considerations
    ///
    /// - The header is not secret but must be transmitted intact
    /// - Each encryption with the same key will produce a different header
    /// - The header uniquely identifies the stream and prevents replay attacks
    /// - Loss or corruption of the header makes decryption impossible
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::{self, Key, PushState};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = Key::generate();
    ///
    /// // Initialize encryption
    /// let (push_state, header) = PushState::init_push(&key).unwrap();
    ///
    /// // The header (24 bytes) must be stored/transmitted before any encrypted messages
    /// // Store or transmit the header securely to the recipient
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `key` - The secret key used for encryption (32 bytes)
    ///
    /// ## Returns
    ///
    /// * `Result<(PushState, [u8; HEADERBYTES])>` - A tuple containing:
    ///   - The encryption state for subsequent operations
    ///   - The header (24 bytes) that must be transmitted to the recipient
    ///
    /// ## Errors
    ///
    /// Returns an error if the initialization fails (extremely rare with proper libsodium initialization)
    pub fn init_push(key: &Key) -> Result<(PushState, [u8; HEADERBYTES])> {
        let mut state = State::new();
        let mut header = [0u8; HEADERBYTES];

        unsafe {
            let result = libsodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
                state.as_mut(),
                header.as_mut_ptr(),
                key.as_bytes().as_ptr(),
            );

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "failed to initialize push state".into(),
                ));
            }
        }

        Ok((PushState(state), header))
    }

    /// Encrypt a message
    ///
    /// This function encrypts a message and authenticates it with the given tag.
    /// The tag can be one of `TAG_MESSAGE`, `TAG_PUSH`, `TAG_REKEY`, or `TAG_FINAL`.
    ///
    /// ## Tag Behavior
    ///
    /// - `TAG_MESSAGE` (0): Standard message with no special behavior
    /// - `TAG_PUSH` (1): Marks the end of a logical chunk (but not the stream)
    /// - `TAG_REKEY` (2): Automatically rekeys the state after encryption
    /// - `TAG_FINAL` (3): Marks the end of the stream, rekeys and finalizes the state
    ///
    /// ## Additional Data
    ///
    /// The optional additional data (AD) parameter allows you to authenticate
    /// data that is not encrypted but is bound to the ciphertext. This could include
    /// metadata, headers, or any other information that should be authenticated
    /// but not encrypted. The same AD must be provided during decryption.
    ///
    /// ## Algorithm Details
    ///
    /// Each encryption operation:
    /// 1. Generates a unique subkey for this message
    /// 2. Encrypts the message using XChaCha20
    /// 3. Computes an authentication tag using Poly1305
    /// 4. Includes the message tag in the authenticated data
    /// 5. Updates the internal state for the next message
    ///
    /// ## Security Considerations
    ///
    /// - Each message can have a different size
    /// - The ciphertext will be `message.len() + ABYTES` bytes long
    /// - Using `TAG_FINAL` for the last message is strongly recommended
    /// - After using `TAG_FINAL`, the state should not be used anymore
    /// - For very long streams, consider using `TAG_REKEY` periodically
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::{self, Key, PushState, TAG_MESSAGE, TAG_FINAL};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = Key::generate();
    ///
    /// // Initialize encryption
    /// let (mut push_state, header) = PushState::init_push(&key).unwrap();
    ///
    /// // Encrypt a regular message
    /// let message1 = b"Hello, world!";
    /// let ciphertext1 = push_state.push(message1, None, TAG_MESSAGE).unwrap();
    ///
    /// // Encrypt with additional data
    /// let message2 = b"Secret message";
    /// let metadata = b"message-id:12345";
    /// let ciphertext2 = push_state.push(message2, Some(metadata), TAG_MESSAGE).unwrap();
    ///
    /// // Encrypt with final tag to mark the end of the stream
    /// let message3 = b"Goodbye!";
    /// let ciphertext3 = push_state.push(message3, None, TAG_FINAL).unwrap();
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `m` - The message to encrypt
    /// * `ad` - Optional additional data to authenticate (not encrypted)
    /// * `tag` - The tag to attach to the message (`TAG_MESSAGE`, `TAG_PUSH`, `TAG_REKEY`, or `TAG_FINAL`)
    ///
    /// ## Returns
    ///
    /// * `Result<Vec<u8>>` - The encrypted message (ciphertext) or an error
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The message exceeds libsodium's maximum message length
    /// - The encryption operation fails
    /// - An invalid tag is provided
    /// - The state has already been finalized with `TAG_FINAL`
    pub fn push(&mut self, m: &[u8], ad: Option<&[u8]>, tag: u8) -> Result<Vec<u8>> {
        if self.0.finalized {
            return Err(SodiumError::InvalidInput("stream already finalized".into()));
        }
        if !matches!(tag, TAG_MESSAGE | TAG_PUSH | TAG_REKEY | TAG_FINAL) {
            return Err(SodiumError::InvalidInput("invalid message tag".into()));
        }
        validate_message_len(m.len())?;
        let c_len = m.len() + ABYTES;
        let mut c = vec![0u8; c_len];
        let mut c_len: u64 = 0;

        unsafe {
            let result = libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
                self.0.state.as_mut(),
                c.as_mut_ptr(),
                &mut c_len,
                m.as_ptr(),
                m.len() as u64,
                ad.map_or(std::ptr::null(), |ad| ad.as_ptr()),
                ad.map_or(0, |ad| ad.len()) as u64,
                tag,
            );

            if result != 0 {
                return Err(SodiumError::OperationError("encryption failed".into()));
            }
        }

        if tag == TAG_FINAL {
            self.0.finalized = true;
        }
        c.truncate(c_len as usize);
        Ok(c)
    }

    /// Explicitly rekey the state
    ///
    /// This function derives a new key for the encryption state, effectively
    /// "forgetting" the key used for previous messages. This provides forward secrecy.
    ///
    /// ## Rekeying Process
    ///
    /// When rekeying occurs, the following happens:
    ///
    /// 1. A new key is derived from the current state
    /// 2. The internal state is updated with this new key
    /// 3. The previous key material is overwritten and "forgotten"
    /// 4. All subsequent messages will be encrypted using the new key
    /// 5. The stream continues without interruption
    ///
    /// ## Security Benefits
    ///
    /// Rekeying provides several important security benefits:
    ///
    /// - **Forward secrecy**: If the current key is compromised, previously encrypted messages remain secure
    /// - **Key rotation**: Limits the amount of data processed with a single key
    /// - **Damage containment**: Limits the impact of partial key compromise
    /// - **Memory protection**: Reduces the lifetime of sensitive key material in memory
    ///
    /// ## Usage Considerations
    ///
    /// - For manual rekeying, this method must be called explicitly
    /// - Alternatively, use the `TAG_REKEY` tag when pushing a message to automatically rekey
    /// - For long-running streams, consider using periodic rekeying (every N messages or bytes)
    /// - Rekeying is automatically performed when a message with `TAG_FINAL` is pushed
    /// - Explicit rekeying does not reopen a finalized stream
    ///
    /// ## Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::{Key, PushState, PullState, TAG_MESSAGE};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = Key::generate();
    ///
    /// // Initialize encryption
    /// let (mut push_state, header) = PushState::init_push(&key).unwrap();
    ///
    /// // Encrypt a message
    /// let message = b"Secret message";
    /// let ciphertext = push_state.push(message, None, TAG_MESSAGE).unwrap();
    ///
    /// // Rekey the encryption state
    /// push_state.rekey().unwrap();
    ///
    /// // Initialize decryption
    /// let mut pull_state = PullState::init_pull(&header, &key).unwrap();
    ///
    /// // Decrypt the message
    /// let (decrypted, _) = pull_state.pull(&ciphertext, None).unwrap();
    ///
    /// // Rekey the decryption state at the same position
    /// pull_state.rekey().unwrap();
    /// ```
    pub fn rekey(&mut self) -> Result<()> {
        unsafe {
            // Call the function without trying to capture its return value
            libsodium_sys::crypto_secretstream_xchacha20poly1305_rekey(self.0.state.as_mut());
            // Since we can't check the return value, we'll assume it succeeded
        }

        Ok(())
    }
}

/// Pull state for XChaCha20-Poly1305 secretstream decryption
///
/// This state is used to decrypt messages in a stream. It maintains the internal
/// state required for the decryption process, including nonces and authentication data.
///
/// ## Overview
///
/// The `PullState` is responsible for:
/// - Initializing the decryption state with a secret key and header
/// - Decrypting messages and verifying their authenticity
/// - Handling additional authenticated data (optional)
/// - Detecting and reporting message tags (regular, push, rekey, final)
/// - Providing forward secrecy through rekeying
/// - Detecting tampering, forgery, or out-of-order messages
///
/// ## Workflow
///
/// 1. Initialize the decryption state with `PullState::init_pull()` using the header from the sender
/// 2. Decrypt messages with `pull()`, providing the same additional data used during encryption
/// 3. Check the returned tag to determine message type (regular, push, rekey, final)
/// 4. Optionally rekey the state with `rekey()` at the same points the sender did
/// 5. Stop decryption when a message with `TAG_FINAL` is received
///
/// ## Security Considerations
///
/// - Messages must be decrypted in the exact order they were encrypted
/// - Any tampering with the ciphertext or header will cause decryption to fail
/// - The additional data must match exactly what was used during encryption
/// - When a message with `TAG_FINAL` is received, the stream is considered complete
/// - Rekeying must be performed at exactly the same points in the stream as during encryption
///
/// The state should be initialized with `PullState::init_pull()` and then used to decrypt
/// messages with the `pull()` method.
pub struct PullState(State);

impl PullState {
    /// Initialize a decryption state with the sender's header and secret key.
    ///
    /// Store or transmit the header alongside the encrypted messages.
    /// It is not secret, but it must reach the receiver unchanged.
    ///
    /// Initialization does not authenticate the header or key.
    /// A corrupted header or wrong key is detected when [`Self::pull`]
    /// authenticates the first ciphertext.
    /// Decrypt messages in the same order they were encrypted.
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::{Key, PushState, PullState};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = Key::generate();
    ///
    /// // Initialize encryption
    /// let (push_state, header) = PushState::init_push(&key).unwrap();
    ///
    /// // Receive the header from the sender
    /// // (In a real application, this would come from the network or storage)
    ///
    /// // Initialize decryption with the header
    /// let pull_state = PullState::init_pull(&header, &key).unwrap();
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `header` - The header generated during encryption initialization (24 bytes)
    /// * `key` - The secret key used for encryption (32 bytes)
    ///
    /// ## Returns
    ///
    /// * `Result<PullState>` - The decryption state for subsequent operations, or an error
    ///
    /// ## Errors
    ///
    /// Returns an error if libsodium cannot initialize the state.
    pub fn init_pull(header: &[u8; HEADERBYTES], key: &Key) -> Result<PullState> {
        let mut state = State::new();

        let result = unsafe {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
                state.as_mut(),
                header.as_ptr(),
                key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to initialize pull state".into(),
            ));
        }

        Ok(PullState(state))
    }

    /// Decrypt a message
    ///
    /// This function decrypts a message and verifies its authentication tag.
    /// If the ciphertext has been tampered with or the additional data doesn't match
    /// what was used during encryption, the function will return an error.
    ///
    /// ## Tag Handling
    ///
    /// The function returns both the decrypted message and the tag that was attached to it.
    /// The tag can be one of:
    /// - `TAG_MESSAGE` (0): Standard message with no special behavior
    /// - `TAG_PUSH` (1): Marks the end of a logical chunk (but not the stream)
    /// - `TAG_REKEY` (2): The encryption state was rekeyed after this message
    /// - `TAG_FINAL` (3): Marks the end of the stream
    ///
    /// ## Automatic Tag Actions
    ///
    /// Certain tags trigger automatic actions in the decryption state:
    ///
    /// - **TAG_MESSAGE**: No special action, just regular decryption
    /// - **TAG_PUSH**: Indicates a logical boundary in the data stream
    /// - **TAG_REKEY**: The decryption state is automatically rekeyed after processing this message
    /// - **TAG_FINAL**: The state is automatically rekeyed and marked as finalized
    ///
    /// ## Additional Data
    ///
    /// If additional data was provided during encryption, the exact same data must be
    /// provided during decryption. If the additional data doesn't match, the function
    /// will return an error.
    ///
    /// Additional data (sometimes called Associated Data or AAD) has these properties:
    /// - It is authenticated but not encrypted
    /// - It can be different for each message in the stream
    /// - It can be used for metadata, headers, or context information
    /// - It must match exactly between encryption and decryption
    /// - It is optional (can be None)
    ///
    /// ## Algorithm Details
    ///
    /// Each decryption operation:
    /// 1. Verifies the authentication tag using Poly1305
    /// 2. Decrypts the message using XChaCha20
    /// 3. Extracts the message tag
    /// 4. Updates the internal state for the next message
    /// 5. Performs automatic rekeying if the tag is `TAG_REKEY` or `TAG_FINAL`
    ///
    /// ## Error Handling
    ///
    /// The function will return an error in these cases:
    /// - The ciphertext is too short (less than ABYTES)
    /// - The authentication tag verification fails (tampering detected)
    /// - The additional data doesn't match what was used during encryption
    /// - Messages are not decrypted in the same order they were encrypted
    /// - The state has already been finalized with a message tagged with `TAG_FINAL`
    ///
    /// ## Security Considerations
    ///
    /// - Messages must be decrypted in the exact order they were encrypted
    /// - Any tampering with the ciphertext will cause decryption to fail
    /// - After receiving a message with `TAG_FINAL`, the stream is considered complete
    /// - The state should not be used after receiving a message with `TAG_FINAL`
    /// - If additional data was used during encryption, it must be provided during decryption
    /// - Decryption errors should be treated as potential security breaches
    ///
    /// ## Example
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::{self, Key, PushState, PullState, TAG_MESSAGE, TAG_FINAL};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = Key::generate();
    ///
    /// // Initialize encryption
    /// let (mut push_state, header) = PushState::init_push(&key).unwrap();
    ///
    /// // Encrypt messages
    /// let message1 = b"First message";
    /// let metadata = b"message-id:12345";
    /// let ciphertext1 = push_state.push(message1, Some(metadata), TAG_MESSAGE).unwrap();
    ///
    /// let message2 = b"Last message";
    /// let ciphertext2 = push_state.push(message2, None, TAG_FINAL).unwrap();
    ///
    /// // Initialize decryption
    /// let mut pull_state = PullState::init_pull(&header, &key).unwrap();
    ///
    /// // Decrypt messages (with the same additional data used during encryption)
    /// let (decrypted1, tag1) = pull_state.pull(&ciphertext1, Some(metadata)).unwrap();
    /// assert_eq!(&decrypted1, message1);
    /// assert_eq!(tag1, TAG_MESSAGE);
    ///
    /// // Decrypt the final message
    /// let (decrypted2, tag2) = pull_state.pull(&ciphertext2, None).unwrap();
    /// assert_eq!(&decrypted2, message2);
    /// assert_eq!(tag2, TAG_FINAL); // End of stream
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `c` - The ciphertext to decrypt
    /// * `ad` - Optional additional data that was authenticated during encryption
    ///
    /// ## Returns
    ///
    /// * `Result<(Vec<u8>, u8)>` - A tuple containing:
    ///   - The decrypted message
    ///   - The tag that was attached to the message
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is shorter than `ABYTES`
    /// - The message exceeds libsodium's maximum message length
    /// - The ciphertext has been tampered with
    /// - The additional data doesn't match what was used during encryption
    /// - The messages are not decrypted in the same order they were encrypted
    /// - The state has already been finalized with a message tagged with `TAG_FINAL`
    pub fn pull(&mut self, c: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, u8)> {
        if self.0.finalized {
            return Err(SodiumError::InvalidInput("stream already finalized".into()));
        }
        let m_len = message_len_from_ciphertext_len(c.len())?;
        let mut m = vec![0u8; m_len];
        let mut m_len_out: u64 = 0;
        let mut tag: u8 = 0;

        unsafe {
            let result = libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
                self.0.state.as_mut(),
                m.as_mut_ptr(),
                &mut m_len_out,
                &mut tag,
                c.as_ptr(),
                c.len() as u64,
                ad.map_or(std::ptr::null(), |ad| ad.as_ptr()),
                ad.map_or(0, |ad| ad.len()) as u64,
            );

            if result != 0 {
                return Err(SodiumError::OperationError("decryption failed".into()));
            }
        }

        if tag == TAG_FINAL {
            self.0.finalized = true;
        }
        m.truncate(m_len_out as usize);
        Ok((m, tag))
    }

    /// Explicitly rekey the state
    ///
    /// This function derives a new key for the decryption state, effectively
    /// "forgetting" the key used for previous messages. This provides forward secrecy.
    ///
    /// ## Rekeying Process
    ///
    /// When rekeying occurs, the following happens:
    ///
    /// 1. A new key is derived from the current state
    /// 2. The internal state is updated with this new key
    /// 3. The previous key material is overwritten and "forgotten"
    /// 4. All subsequent messages will be decrypted using the new key
    /// 5. The stream continues without interruption
    ///
    /// ## Security Benefits
    ///
    /// Rekeying provides several important security benefits:
    ///
    /// - **Forward secrecy**: If the current key is compromised, previously decrypted messages remain secure
    /// - **Key rotation**: Limits the amount of data processed with a single key
    /// - **Damage containment**: Limits the impact of partial key compromise
    /// - **Memory protection**: Reduces the lifetime of sensitive key material in memory
    ///
    /// ## Usage Considerations
    ///
    /// - This must be called at the exact same position in the stream as the corresponding
    ///   rekey operation was performed during encryption
    /// - It's usually better to rely on the `TAG_REKEY` tag, which is automatically handled by the `pull()` function
    /// - For long-running streams, consider using periodic rekeying (every N messages or bytes)
    /// - Rekeying is automatically performed when a message with `TAG_FINAL` is received
    /// - Explicit rekeying does not reopen a finalized stream
    ///
    /// # Example
    /// ```
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_secretstream::xchacha20poly1305::{Key, PushState, PullState, TAG_MESSAGE};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key
    /// let key = Key::generate();
    ///
    /// // Initialize encryption
    /// let (mut push_state, header) = PushState::init_push(&key).unwrap();
    ///
    /// // Encrypt a message
    /// let message = b"Secret message";
    /// let ciphertext = push_state.push(message, None, TAG_MESSAGE).unwrap();
    ///
    /// // Rekey the encryption state
    /// push_state.rekey().unwrap();
    ///
    /// // Initialize decryption
    /// let mut pull_state = PullState::init_pull(&header, &key).unwrap();
    ///
    /// // Decrypt the message
    /// let (decrypted, _) = pull_state.pull(&ciphertext, None).unwrap();
    ///
    /// // Rekey the decryption state at the same position
    /// pull_state.rekey().unwrap();
    /// ```
    pub fn rekey(&mut self) -> Result<()> {
        unsafe {
            // Call the function without trying to capture its return value
            libsodium_sys::crypto_secretstream_xchacha20poly1305_rekey(self.0.state.as_mut());
            // Since we can't check the return value, we'll assume it succeeded
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_length_boundaries() {
        let max =
            unsafe { libsodium_sys::crypto_secretstream_xchacha20poly1305_messagebytes_max() };
        for len in [0, 1, max - 1, max] {
            assert!(validate_message_len(len).is_ok());
        }
        for len in [max.checked_add(1).unwrap(), usize::MAX] {
            assert!(matches!(
                validate_message_len(len),
                Err(SodiumError::InvalidInput(_))
            ));
        }

        for len in [0, ABYTES - 1] {
            assert!(matches!(
                message_len_from_ciphertext_len(len),
                Err(SodiumError::InvalidInput(_))
            ));
        }
        assert_eq!(message_len_from_ciphertext_len(ABYTES).unwrap(), 0);
        assert_eq!(message_len_from_ciphertext_len(ABYTES + 1).unwrap(), 1);
        let max_ciphertext = max.checked_add(ABYTES).unwrap();
        assert_eq!(
            message_len_from_ciphertext_len(max_ciphertext - 1).unwrap(),
            max - 1
        );
        assert_eq!(
            message_len_from_ciphertext_len(max_ciphertext).unwrap(),
            max
        );
        if let Some(oversized) = max_ciphertext.checked_add(1) {
            for len in [oversized, usize::MAX] {
                assert!(matches!(
                    message_len_from_ciphertext_len(len),
                    Err(SodiumError::InvalidInput(_))
                ));
            }
        }
    }

    fn stream_pair() -> (PushState, PullState) {
        let key = Key::generate();
        let (push, header) = PushState::init_push(&key).unwrap();
        let pull = PullState::init_pull(&header, &key).unwrap();
        (push, pull)
    }

    #[test]
    fn test_finalization_survives_rekey() {
        let (mut push, mut pull) = stream_pair();
        let ciphertext = push.push(b"last", None, TAG_FINAL).unwrap();
        let (message, tag) = pull.pull(&ciphertext, None).unwrap();
        assert_eq!(message, b"last");
        assert_eq!(tag, TAG_FINAL);

        for rekey in [false, true] {
            if rekey {
                push.rekey().unwrap();
                pull.rekey().unwrap();
            }
            for tag in [TAG_MESSAGE, TAG_PUSH, TAG_REKEY, TAG_FINAL] {
                assert!(matches!(
                    push.push(b"after final", None, tag),
                    Err(SodiumError::InvalidInput(_))
                ));
            }
            assert!(matches!(
                pull.pull(&ciphertext, None),
                Err(SodiumError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn test_invalid_tags_do_not_advance_state() {
        let (mut push, mut pull) = stream_pair();
        for tag in 0..=u8::MAX {
            if matches!(tag, TAG_MESSAGE | TAG_PUSH | TAG_REKEY | TAG_FINAL) {
                continue;
            }
            assert!(matches!(
                push.push(b"invalid", None, tag),
                Err(SodiumError::InvalidInput(_))
            ));
        }
        let ciphertext = push.push(b"valid", None, TAG_MESSAGE).unwrap();
        let (message, tag) = pull.pull(&ciphertext, None).unwrap();
        assert_eq!(message, b"valid");
        assert_eq!(tag, TAG_MESSAGE);
    }

    #[test]
    fn test_failed_final_authentication_does_not_finalize() {
        let (mut push, mut pull) = stream_pair();
        let ciphertext = push.push(b"last", Some(b"context"), TAG_FINAL).unwrap();
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            pull.pull(&tampered, Some(b"context")),
            Err(SodiumError::OperationError(_))
        ));
        assert!(matches!(
            pull.pull(&ciphertext, Some(b"wrong context")),
            Err(SodiumError::OperationError(_))
        ));
        assert!(matches!(
            pull.pull(&ciphertext[..ABYTES - 1], Some(b"context")),
            Err(SodiumError::InvalidInput(_))
        ));

        let (message, tag) = pull.pull(&ciphertext, Some(b"context")).unwrap();
        assert_eq!(message, b"last");
        assert_eq!(tag, TAG_FINAL);
        assert!(matches!(
            pull.pull(&ciphertext, Some(b"context")),
            Err(SodiumError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_header_and_key_authenticated_by_pull() {
        let key = Key::from([0x42; KEYBYTES]);
        let (mut push, header) = PushState::init_push(&key).unwrap();
        let ciphertext = push.push(b"message", None, TAG_MESSAGE).unwrap();
        for index in 0..HEADERBYTES {
            let mut corrupted = header;
            corrupted[index] ^= 1;
            let mut pull = PullState::init_pull(&corrupted, &key).unwrap();
            assert!(matches!(
                pull.pull(&ciphertext, None),
                Err(SodiumError::OperationError(_))
            ));
        }
        let wrong_key = Key::from([0x43; KEYBYTES]);
        let mut pull = PullState::init_pull(&header, &wrong_key).unwrap();
        assert!(matches!(
            pull.pull(&ciphertext, None),
            Err(SodiumError::OperationError(_))
        ));
        let mut pull = PullState::init_pull(&header, &key).unwrap();
        let (message, tag) = pull.pull(&ciphertext, None).unwrap();
        assert_eq!(message, b"message");
        assert_eq!(tag, TAG_MESSAGE);
    }

    #[test]
    fn test_secretstream() {
        let key = Key::generate();
        let message1 = b"Hello, ";
        let message2 = b"World!";
        let message3 = b"This is the final message.";
        let ad = b"Additional data";

        // Initialize the encryption
        let (mut push_state, header) = PushState::init_push(&key).unwrap();

        // Encrypt the messages
        let ciphertext1 = push_state.push(message1, Some(ad), TAG_MESSAGE).unwrap();
        let ciphertext2 = push_state.push(message2, Some(ad), TAG_MESSAGE).unwrap();
        let ciphertext_rekey = push_state.push(b"", Some(b""), TAG_REKEY).unwrap();
        assert_eq!(ciphertext_rekey.len(), ABYTES);
        let ciphertext3 = push_state.push(message3, Some(ad), TAG_FINAL).unwrap();

        // Initialize the decryption
        let mut pull_state = PullState::init_pull(&header, &key).unwrap();

        // Decrypt the messages
        let (decrypted1, tag1) = pull_state.pull(&ciphertext1, Some(ad)).unwrap();
        let (decrypted2, tag2) = pull_state.pull(&ciphertext2, Some(ad)).unwrap();
        let (empty_message, rekey_tag) = pull_state.pull(&ciphertext_rekey, Some(b"")).unwrap();
        let (decrypted3, tag3) = pull_state.pull(&ciphertext3, Some(ad)).unwrap();

        // Verify the decrypted messages
        assert_eq!(&decrypted1, message1);
        assert_eq!(&decrypted2, message2);
        assert!(empty_message.is_empty());
        assert_eq!(&decrypted3, message3);

        // Verify the tags
        assert_eq!(tag1, TAG_MESSAGE);
        assert_eq!(tag2, TAG_MESSAGE);
        assert_eq!(rekey_tag, TAG_REKEY);
        assert_eq!(tag3, TAG_FINAL);
    }

    #[test]
    fn test_secretstream_rekey() {
        let key = Key::generate();
        let message1 = b"Message before rekey";
        let message2 = b"Message after rekey";

        // Initialize the encryption
        let (mut push_state, header) = PushState::init_push(&key).unwrap();

        // Encrypt the first message
        let ciphertext1 = push_state.push(message1, None, TAG_MESSAGE).unwrap();

        // Rekey
        push_state.rekey().unwrap();

        // Encrypt the second message
        let ciphertext2 = push_state.push(message2, None, TAG_MESSAGE).unwrap();

        // Initialize the decryption
        let mut pull_state = PullState::init_pull(&header, &key).unwrap();

        // Decrypt the first message
        let (decrypted1, _) = pull_state.pull(&ciphertext1, None).unwrap();

        // Rekey
        pull_state.rekey().unwrap();

        // Decrypt the second message
        let (decrypted2, _) = pull_state.pull(&ciphertext2, None).unwrap();

        // Verify the decrypted messages
        assert_eq!(&decrypted1, message1);
        assert_eq!(&decrypted2, message2);
    }

    #[test]
    fn test_secretstream_tag_push() {
        let key = Key::generate();
        let message = b"Message with key material";

        // Initialize the encryption
        let (mut push_state, header) = PushState::init_push(&key).unwrap();

        // Encrypt the message with TAG_PUSH
        let ciphertext = push_state.push(message, None, TAG_PUSH).unwrap();

        // Initialize the decryption
        let mut pull_state = PullState::init_pull(&header, &key).unwrap();

        // Decrypt the message
        let (decrypted, tag) = pull_state.pull(&ciphertext, None).unwrap();

        // Verify the decrypted message and tag
        assert_eq!(&decrypted, message);
        assert_eq!(tag, TAG_PUSH);
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
