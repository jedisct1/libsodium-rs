//! # Rust bindings for libsodium
//!
//! This crate provides safe, ergonomic Rust bindings for the libsodium cryptographic library.
//! It offers a comprehensive set of cryptographic primitives with a focus on usability, security,
//! and performance.
//!
//! ## Features
//!
//! - **Complete Coverage**: Implements the entire libsodium API in Rust
//! - **Memory Safety**: Ensures secure memory handling with automatic clearing of sensitive data
//! - **Type Safety**: Leverages Rust's type system to prevent misuse of cryptographic primitives
//! - **Flexible APIs**: Uses `AsRef` trait for parameters, allowing for more ergonomic function calls
//! - **Extensive Testing**: Comprehensive test suite covering all functionality
//! - **Minimal Dependencies**: Uses only a small set of carefully selected dependencies beyond libsodium itself
//!
//! ## Getting Started
//!
//! Before using any cryptographic functions, you must initialize the library:
//!
//! ```
//! use libsodium_rs::ensure_init;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize libsodium
//!     ensure_init()?;
//!
//!     // Now you can use the cryptographic functions
//!     Ok(())
//! }
//! ```
//!
//! ## Available Modules
//!
//! - **[`crypto_aead`]**: Authenticated Encryption with Associated Data (AEAD)
//! - **[`crypto_auth`]**: Secret-key message authentication
//! - **[`crypto_box`]**: Public-key authenticated encryption
//! - **[`crypto_core`]**: Core cryptographic operations
//! - **[`crypto_generichash`]**: Cryptographic hash functions (BLAKE2b)
//! - **[`crypto_hash`]**: Traditional cryptographic hash functions (SHA-256, SHA-512)
//! - **[`crypto_kdf`]**: Key derivation functions
//! - **[`crypto_kx`]**: Key exchange
//! - **[`crypto_pwhash`]**: Password hashing and key derivation
//! - **[`crypto_scalarmult`]**: Elliptic curve operations
//! - **[`crypto_secretbox`]**: Secret-key authenticated encryption
//! - **[`crypto_secretstream`]**: Secret-key authenticated encryption for streams
//! - **[`crypto_shorthash`]**: Short-input hash functions (SipHash)
//! - **[`crypto_sign`]**: Public-key signatures
//! - **[`crypto_stream`]**: Stream ciphers
//! - **[`random`]**: Secure random number generation
//! - **[`utils`]**: Utility functions
//! - **[`version`]**: Library version information

use thiserror::Error;

/// Error type for libsodium operations
#[derive(Error, Debug)]
pub enum SodiumError {
    /// Hex decoding failed
    #[error("Invalid hexadecimal string")]
    HexDecodingFailed,
    /// Base64 decoding failed
    #[error("Invalid Base64 string")]
    Base64DecodingFailed,
    /// Initialization of libsodium failed
    #[error("libsodium initialization failed")]
    InitializationError,

    /// Invalid key provided (wrong size or format)
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid nonce provided (wrong size or format)
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Invalid input data provided
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Authentication failed during decryption
    #[error("authentication failed")]
    AuthenticationError,

    /// Encryption operation failed
    #[error("encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption operation failed
    #[error("decryption failed: {0}")]
    DecryptionError(String),

    /// Generic operation error
    #[error("operation failed: {0}")]
    OperationError(String),

    /// Operation not supported on this platform or configuration
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
}

/// Result type for sodium operations
pub type Result<T> = std::result::Result<T, SodiumError>;

/// Ensures libsodium is initialized
pub fn ensure_init() -> Result<()> {
    unsafe {
        if libsodium_sys::sodium_init() < 0 {
            return Err(SodiumError::InitializationError);
        }
    }
    Ok(())
}

pub mod crypto_aead;
pub mod crypto_auth;
pub mod crypto_box;
pub mod crypto_core;
pub mod crypto_generichash;
pub mod crypto_hash;
pub mod crypto_kdf;
pub mod crypto_kx;
pub mod crypto_onetimeauth;
pub mod crypto_pwhash;
pub mod crypto_scalarmult;
pub mod crypto_secretbox;
pub mod crypto_secretstream;
pub mod crypto_shorthash;
pub mod crypto_sign;
pub mod crypto_stream;
pub mod crypto_verify;
pub mod random;
pub mod utils;
pub mod version;

// No re-exports at the top level - users should import from specific modules

// Initialize libsodium when the library is loaded
#[ctor::ctor]
fn initialize() {
    if let Err(e) = ensure_init() {
        panic!("Failed to initialize libsodium: {e}");
    }
}
