//! # Secret Stream Encryption
//!
//! This module provides APIs for secure streaming encryption of data. Secret stream encryption
//! is designed for scenarios where you need to encrypt an ordered sequence of messages (a stream)
//! with strong security guarantees.
//!
//! ## Use Cases
//!
//! Secret stream encryption is ideal for:
//!
//! - **File encryption**: Securely encrypt files that may be processed in chunks
//! - **Secure communications**: Protect ongoing communication sessions
//! - **Data streaming**: Encrypt data streams where messages arrive sequentially
//! - **Secure logging**: Protect log entries while maintaining their order
//! - **Secure backup**: Encrypt backup data with the ability to verify integrity
//!
//! ## Features
//!
//! - **Authenticated encryption**: Ensures confidentiality, integrity, and authenticity of all messages
//! - **Secure ordering**: Protection against reordering, truncation, and message forgery
//! - **Additional data**: Support for additional authenticated data (AAD) with each message
//! - **Message tagging**: Ability to tag messages with different purposes (regular, final, etc.)
//! - **Rekeying**: Capability to limit the impact of key compromise by changing keys mid-stream
//! - **Streaming operation**: Process messages of arbitrary size without loading everything into memory
//! - **Chunk completion markers**: Signal logical boundaries within the encrypted stream
//!
//! ## Security Properties
//!
//! Secret stream encryption provides:
//!
//! - **Confidentiality**: Messages cannot be read without the key
//! - **Integrity**: Any modification to encrypted messages will be detected
//! - **Authenticity**: Messages are guaranteed to come from the legitimate sender
//! - **Forward secrecy** (with rekeying): Compromise of current state doesn't expose previously sent messages
//! - **Replay protection**: Previously sent messages cannot be replayed in a different context
//! - **Unique ciphertexts**: The same message encrypted twice will produce different ciphertexts
//!
//! ## Available Implementations
//!
//! Currently, this module provides:
//!
//! - `xchacha20poly1305`: A streaming encryption API based on the XChaCha20 stream cipher and
//!   Poly1305 MAC, offering 256-bit security and 192-bit nonces. This implementation is
//!   highly secure, efficient, and suitable for most applications.
//!
//! ## Usage
//!
//! For most use cases, you should use the re-exported types from the `xchacha20poly1305` module:
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretstream::{Key, PullState, PushState};
//! use sodium::crypto_secretstream::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a key
//! let key = Key::generate();
//!
//! // Initialize encryption
//! let (mut push_state, header) = PushState::init_push(&key).unwrap();
//!
//! // Encrypt a message
//! let message = b"Hello, secret stream!";
//! let ciphertext = push_state.push(
//!     message,
//!     None, // No additional data
//!     xchacha20poly1305::TAG_MESSAGE
//! ).unwrap();
//!
//! // Initialize decryption
//! let mut pull_state = PullState::init_pull(&header, &key).unwrap();
//!
//! // Decrypt the message
//! let (decrypted, tag) = pull_state.pull(&ciphertext, None).unwrap();
//!
//! assert_eq!(&decrypted, message);
//! assert_eq!(tag, xchacha20poly1305::TAG_MESSAGE);
//! ```
//!
//! ## Advanced Usage: Multiple Messages with Final Tag
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_secretstream::{Key, PullState, PushState};
//! use sodium::crypto_secretstream::xchacha20poly1305::{TAG_MESSAGE, TAG_FINAL};
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a key
//! let key = Key::generate();
//!
//! // Initialize encryption
//! let (mut push_state, header) = PushState::init_push(&key).unwrap();
//!
//! // Encrypt multiple messages
//! let message1 = b"Part 1 of the stream";
//! let message2 = b"Part 2 of the stream";
//! let message3 = b"Final part of the stream";
//!
//! let ciphertext1 = push_state.push(message1, None, TAG_MESSAGE).unwrap();
//! let ciphertext2 = push_state.push(message2, None, TAG_MESSAGE).unwrap();
//! // Mark the last message with TAG_FINAL
//! let ciphertext3 = push_state.push(message3, None, TAG_FINAL).unwrap();
//!
//! // Initialize decryption
//! let mut pull_state = PullState::init_pull(&header, &key).unwrap();
//!
//! // Decrypt the messages in the same order
//! let (decrypted1, tag1) = pull_state.pull(&ciphertext1, None).unwrap();
//! let (decrypted2, tag2) = pull_state.pull(&ciphertext2, None).unwrap();
//! let (decrypted3, tag3) = pull_state.pull(&ciphertext3, None).unwrap();
//!
//! // Verify the decrypted messages and tags
//! assert_eq!(&decrypted1, message1);
//! assert_eq!(&decrypted2, message2);
//! assert_eq!(&decrypted3, message3);
//! assert_eq!(tag1, TAG_MESSAGE);
//! assert_eq!(tag2, TAG_MESSAGE);
//! assert_eq!(tag3, TAG_FINAL);
//! ```
//!
//! ## Security Considerations
//!
//! - **Key Management**: Keep the `Key` secret - it's the basis of all security guarantees
//! - **Header Handling**: The `header` must be transmitted/stored alongside the ciphertext, but it doesn't need to be secret
//! - **Message Ordering**: Messages MUST be processed in the exact same order they were encrypted
//! - **Stream Finalization**: For maximum security, use the `TAG_FINAL` tag for the last message in a stream
//! - **Long-running Streams**: Consider using `rekey()` for very long streams or when forward secrecy is needed
//! - **Additional Data**: If you use additional authenticated data (AAD), the same data must be provided during decryption
//! - **Error Handling**: Any decryption error should be treated as a potential attack - do not retry with modified parameters
//! - **Memory Management**: The state objects contain sensitive cryptographic material and will be automatically zeroized when dropped
//! - **Nonce Reuse**: The library automatically handles nonces, preventing dangerous reuse

// Export submodules
pub mod xchacha20poly1305;

// Re-export common types and functions
pub use self::xchacha20poly1305::{Key, PullState, PushState};
