//! # Key Exchange
//!
//! This module provides a secure key exchange mechanism based on the X25519 function.
//! It allows two parties to establish a shared secret over an insecure channel.
//! The implementation follows the key exchange protocol defined in libsodium.
//!
//! ## Overview
//!
//! The key exchange mechanism in this module uses the X25519 function, which is an
//! elliptic curve Diffie-Hellman key exchange using Curve25519. This allows two parties
//! to establish a shared secret that can be used for symmetric encryption. The shared
//! secret is automatically hashed using BLAKE2b before being used as session keys.
//!
//! ## Features
//!
//! - **High security**: Based on the X25519 function (Curve25519)
//! - **Forward secrecy**: New session keys can be generated for each session
//! - **Authenticated**: Both parties can verify the identity of the other party
//! - **Bidirectional**: Generates separate keys for sending and receiving
//!
//! ## Usage
//!
//! The typical workflow is as follows:
//!
//! 1. Both the client and server generate their own keypairs
//! 2. They exchange their public keys over any channel (doesn't need to be secure)
//! 3. The client computes session keys using `client_session_keys()`
//! 4. The server computes session keys using `server_session_keys()`
//! 5. Both parties now have matching session keys for bidirectional communication
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_kx;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Client and server each generate their keypairs
//! let client_keypair = crypto_kx::KeyPair::generate().unwrap();
//! let (client_pk, client_sk) = (client_keypair.public_key, client_keypair.secret_key);
//! let server_keypair = crypto_kx::KeyPair::generate().unwrap();
//! let (server_pk, server_sk) = (server_keypair.public_key, server_keypair.secret_key);
//!
//! // Exchange public keys (this would happen over a network in practice)
//!
//! // Client computes session keys
//! let client_keys = crypto_kx::client_session_keys(
//!     &client_pk,
//!     &client_sk,
//!     &server_pk,
//! ).unwrap();
//!
//! // Server computes session keys
//! let server_keys = crypto_kx::server_session_keys(
//!     &server_pk,
//!     &server_sk,
//!     &client_pk,
//! ).unwrap();
//!
//! // Now client_keys.tx matches server_keys.rx
//! // and client_keys.rx matches server_keys.tx
//! assert_eq!(client_keys.tx, server_keys.rx);
//! assert_eq!(client_keys.rx, server_keys.tx);
//!
//! // These keys can now be used for symmetric encryption
//! ```
//!
//! ## Security Considerations
//!
//! - Keep secret keys private at all times
//! - Public keys can be freely shared
//! - Generate new keypairs for each communication session for forward secrecy
//! - The session keys should be used with appropriate symmetric encryption algorithms
//! - For maximum security, authenticate the public keys through a trusted channel
//! - The shared secret established through X25519 is automatically hashed before being used as session keys
//! - Be aware that X25519 is based on Curve25519, which has a cofactor of 8
//! - The key exchange protocol provides protection against man-in-the-middle attacks
//!   when public keys are properly authenticated
//! - The session keys are derived using BLAKE2b, which is resistant to length extension attacks
//! - Different keys are used for each direction to prevent reflection attacks

use crate::{Result, SodiumError};
use libsodium_sys;

/// Number of bytes in a public key (32)
///
/// This is the size of a Curve25519 public key used in the X25519 key exchange.
pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_kx_PUBLICKEYBYTES as usize;

/// Number of bytes in a secret key (32)
///
/// This is the size of a Curve25519 secret key used in the X25519 key exchange.
pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_kx_SECRETKEYBYTES as usize;

/// Number of bytes in a session key (32)
///
/// This is the size of the symmetric keys generated through the key exchange.
/// These keys can be used for symmetric encryption algorithms like XChaCha20-Poly1305.
pub const SESSIONKEYBYTES: usize = libsodium_sys::crypto_kx_SESSIONKEYBYTES as usize;

/// A public key for key exchange
///
/// This represents a Curve25519 public key used in the X25519 key exchange.
/// Public keys can be freely shared with other parties.
///
/// ## Size
///
/// A public key is always exactly `PUBLICKEYBYTES` (32) bytes.
///
/// ## Security Considerations
///
/// While public keys can be freely shared, it's important to authenticate
/// them through a trusted channel to prevent man-in-the-middle attacks.
///
/// ## Usage
///
/// Public keys are typically generated with the `KeyPair::generate()` function
/// and then shared with the other party to establish a secure communication channel.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

/// A secret key for key exchange
///
/// This represents a Curve25519 secret key used in the X25519 key exchange.
/// Secret keys must be kept private and never shared.
///
/// ## Size
///
/// A secret key is always exactly `SECRETKEYBYTES` (32) bytes.
///
/// ## Security Considerations
///
/// Secret keys should be generated using a secure random number generator
/// and should never be exposed. When a secret key is no longer needed,
/// it should be securely erased from memory.
///
/// ## Security
///
/// Secret keys should be protected with the same care as passwords or encryption keys.
/// They should never be transmitted over a network or stored in plaintext.
///
/// ## Usage
///
/// Secret keys are typically generated with the `KeyPair::generate()` function
/// and used locally to compute shared session keys.
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

/// A key pair for key exchange
///
/// Contains both a public key and a secret key for use with crypto_kx functions.
/// The key pair is used to establish a secure communication channel between
/// two parties using the X25519 key exchange protocol.
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

/// A pair of session keys for bidirectional communication
///
/// This struct contains two symmetric keys for secure bidirectional communication:
/// - `tx`: Used for encrypting outgoing messages (and decrypting by the other party)
/// - `rx`: Used for decrypting incoming messages (and encrypting by the other party)
///
/// Using separate keys for each direction provides additional security by preventing
/// reflection attacks and ensuring that encryption and decryption operations use
/// different keys.
///
/// ## Size
///
/// Each session key is exactly `SESSIONKEYBYTES` (32) bytes.
///
/// ## Usage
///
/// Session keys are computed using either `client_session_keys()` or `server_session_keys()`
/// and then used with symmetric encryption algorithms like XChaCha20-Poly1305.
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_kx;
/// use sodium::crypto_secretbox;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keypairs and compute session keys (abbreviated)
/// let client_keypair = crypto_kx::KeyPair::generate().unwrap();
/// let client_pk = client_keypair.public_key;
/// let client_sk = client_keypair.secret_key;
/// let server_keypair = crypto_kx::KeyPair::generate().unwrap();
/// let server_pk = server_keypair.public_key;
/// let server_sk = server_keypair.secret_key;
/// let client_keys = crypto_kx::client_session_keys(&client_pk, &client_sk, &server_pk).unwrap();
///
/// // Use the tx key for encryption
/// let nonce = crypto_secretbox::Nonce::generate();
/// let message = b"Hello, server!";
///
/// // Create a key from the session key bytes
/// let tx_key = crypto_secretbox::Key::from_bytes(&client_keys.tx).unwrap();
///
/// // Encrypt the message
/// let ciphertext = crypto_secretbox::seal(message, &nonce, &tx_key);
///
/// // The server would decrypt using its rx key (which matches client's tx key)
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for sending messages (rx for the other party)
    pub tx: [u8; SESSIONKEYBYTES],
    /// Key for receiving messages (tx for the other party)
    pub rx: [u8; SESSIONKEYBYTES],
}

impl PublicKey {
    /// Create a public key from existing bytes
    ///
    /// This function creates a public key from an existing byte array.
    /// It's useful when you need to deserialize a public key that was
    /// previously serialized or received from another party.
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A byte slice of exactly `PUBLICKEYBYTES` (32) length
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new public key or an error if the input is invalid
    ///
    /// ## Errors
    ///
    /// Returns an error if the input is not exactly `PUBLICKEYBYTES` bytes long.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kx::PublicKey;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a public key from bytes (e.g., received from a peer)
    /// let key_bytes = [0x42; 32]; // 32 bytes of data
    /// let public_key = PublicKey::from_bytes(&key_bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLICKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "public key must be exactly {PUBLICKEYBYTES} bytes"
            )));
        }

        let mut key = [0u8; PUBLICKEYBYTES];
        key.copy_from_slice(bytes);
        Ok(PublicKey(key))
    }

    /// Get the raw bytes of the public key
    ///
    /// This function returns a reference to the internal byte array of the public key.
    /// It's useful when you need to serialize the public key for transmission or storage.
    ///
    /// ## Returns
    ///
    /// * `&[u8]` - A reference to the public key bytes
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kx;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a keypair
    /// let keypair = crypto_kx::KeyPair::generate().unwrap();
    /// let public_key = keypair.public_key;
    ///
    /// // Get the raw bytes of the public key
    /// let key_bytes = public_key.as_bytes();
    /// assert_eq!(key_bytes.len(), crypto_kx::PUBLICKEYBYTES);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<[u8; PUBLICKEYBYTES]> for PublicKey {
    fn from(bytes: [u8; PUBLICKEYBYTES]) -> Self {
        PublicKey(bytes)
    }
}

impl From<PublicKey> for [u8; PUBLICKEYBYTES] {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

impl SecretKey {
    /// Create a secret key from existing bytes
    ///
    /// This function creates a secret key from an existing byte array.
    /// It's useful when you need to deserialize a secret key that was
    /// previously serialized or derived from another source.
    ///
    /// ## Security Considerations
    ///
    /// Be extremely careful when handling secret key material. Secret keys should
    /// never be transmitted over a network or stored in plaintext.
    ///
    /// ## Arguments
    ///
    /// * `bytes` - A byte slice of exactly `SECRETKEYBYTES` (32) length
    ///
    /// ## Returns
    ///
    /// * `Result<Self>` - A new secret key or an error if the input is invalid
    ///
    /// ## Errors
    ///
    /// Returns an error if the input is not exactly `SECRETKEYBYTES` bytes long.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kx::SecretKey;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a secret key from bytes (e.g., from secure storage)
    /// let key_bytes = [0x42; 32]; // 32 bytes of data
    /// let secret_key = SecretKey::from_bytes(&key_bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRETKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "secret key must be exactly {SECRETKEYBYTES} bytes"
            )));
        }

        let mut key = [0u8; SECRETKEYBYTES];
        key.copy_from_slice(bytes);
        Ok(SecretKey(key))
    }

    /// Get the raw bytes of the secret key
    ///
    /// This function returns a reference to the internal byte array of the secret key.
    /// It's useful when you need to serialize the secret key for secure storage.
    ///
    /// ## Security Considerations
    ///
    /// Be extremely careful when handling the raw bytes of a secret key.
    /// They should never be logged, transmitted over a network, or stored in plaintext.
    ///
    /// ## Returns
    ///
    /// * `&[u8]` - A reference to the secret key bytes
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kx;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a keypair
    /// let keypair = crypto_kx::KeyPair::generate().unwrap();
    /// let secret_key = keypair.secret_key;
    ///
    /// // Get the raw bytes of the secret key (handle with care!)
    /// let key_bytes = secret_key.as_bytes();
    /// assert_eq!(key_bytes.len(), crypto_kx::SECRETKEYBYTES);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<[u8; SECRETKEYBYTES]> for SecretKey {
    fn from(bytes: [u8; SECRETKEYBYTES]) -> Self {
        SecretKey(bytes)
    }
}

impl From<SecretKey> for [u8; SECRETKEYBYTES] {
    fn from(key: SecretKey) -> Self {
        key.0
    }
}

impl KeyPair {
    /// Generate a new key pair for key exchange
    ///
    /// This function generates a new random keypair for use in the X25519 key exchange.
    /// The keypair consists of a public key that can be shared with other parties,
    /// and a secret key that must be kept private.
    ///
    /// ## Algorithm Details
    ///
    /// The keypair is generated using the X25519 function, which is based on the
    /// Curve25519 elliptic curve. This provides 128 bits of security, which is
    /// considered sufficient for most applications.
    ///
    /// ## Security Considerations
    ///
    /// - The secret key should be kept private at all times
    /// - For maximum security, generate a new keypair for each session
    /// - The public key can be freely shared with other parties
    ///
    /// ## Returns
    ///
    /// * `Result<KeyPair>` - A key pair containing the public and secret keys
    ///
    /// ## Errors
    ///
    /// Returns an error if the keypair generation fails (extremely rare with proper libsodium initialization)
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_kx;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a keypair
    /// let keypair = crypto_kx::KeyPair::generate().unwrap();
    ///
    /// // The public key can be shared with other parties
    /// let public_key_bytes = keypair.public_key.as_bytes();
    ///
    /// // The secret key must be kept private
    /// let secret_key_bytes = keypair.secret_key.as_bytes();
    /// ```
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        let result = unsafe { libsodium_sys::crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to generate keypair".into(),
            ));
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Convert the KeyPair into a tuple of (PublicKey, SecretKey)
    pub fn into_tuple(self) -> (PublicKey, SecretKey) {
        (self.public_key, self.secret_key)
    }
}

/// Computes session keys for a client
///
/// This function computes a pair of session keys that can be used for secure
/// communication between a client and a server. It must be called by the client
/// using the client's keypair and the server's public key.
///
/// The client and server roles are important because they determine the order
/// of inputs to the key derivation function, ensuring that the client's tx key
/// matches the server's rx key, and vice versa.
///
/// ## Algorithm Details
///
/// The session keys are derived using the X25519 function to compute a shared secret,
/// which is then hashed using BLAKE2b to produce two separate keys for sending and receiving.
/// This ensures that different keys are used in each direction and that the raw output of
/// the X25519 function is never directly used as a cryptographic key.
///
/// ## Security Considerations
///
/// - The client must verify the authenticity of the server's public key
/// - The resulting session keys should be used with appropriate symmetric encryption
/// - The client's tx key corresponds to the server's rx key, and vice versa
/// - The session keys are derived using BLAKE2b, which is resistant to length extension attacks
/// - Different keys are used for each direction to prevent reflection attacks
/// - The key exchange provides forward secrecy if new keypairs are generated for each session
///
/// ## Arguments
///
/// * `client_pk` - The client's public key
/// * `client_sk` - The client's secret key
/// * `server_pk` - The server's public key
///
/// ## Returns
///
/// * `Result<SessionKeys>` - A pair of session keys for bidirectional communication
///
/// ## Errors
///
/// Returns an error if the key computation fails, which can happen if:
/// - The public keys are invalid
/// - The secret key is invalid
/// - The public keys represent the same identity (client_pk == server_pk)
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_kx;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keypairs for client and server
/// let client_keypair = crypto_kx::KeyPair::generate().unwrap();
/// let client_pk = client_keypair.public_key;
/// let client_sk = client_keypair.secret_key;
/// let server_keypair = crypto_kx::KeyPair::generate().unwrap();
/// let server_pk = server_keypair.public_key;
/// let server_sk = server_keypair.secret_key;
///
/// // Client computes session keys
/// let client_keys = crypto_kx::client_session_keys(
///     &client_pk,
///     &client_sk,
///     &server_pk,
/// ).unwrap();
///
/// // Now client_keys.tx can be used to encrypt messages to the server,
/// // and client_keys.rx can be used to decrypt messages from the server.
/// ```
pub fn client_session_keys(
    client_pk: &PublicKey,
    client_sk: &SecretKey,
    server_pk: &PublicKey,
) -> Result<SessionKeys> {
    let mut rx = [0u8; SESSIONKEYBYTES];
    let mut tx = [0u8; SESSIONKEYBYTES];

    let result = unsafe {
        libsodium_sys::crypto_kx_client_session_keys(
            rx.as_mut_ptr(),
            tx.as_mut_ptr(),
            client_pk.as_bytes().as_ptr(),
            client_sk.as_bytes().as_ptr(),
            server_pk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "failed to compute session keys".into(),
        ));
    }

    Ok(SessionKeys { rx, tx })
}

/// Server side: compute session keys
///
/// This function computes a pair of session keys for secure bidirectional
/// communication between a client and a server. It must be called by the server
/// using the server's keypair and the client's public key.
///
/// ## Algorithm Details
///
/// The session keys are derived using the X25519 function to compute a shared secret,
/// which is then hashed using BLAKE2b to produce two separate keys for sending and receiving.
/// This ensures that different keys are used in each direction and that the raw output of
/// the X25519 function is never directly used as a cryptographic key.
///
/// ## Security Considerations
///
/// - The server must verify the authenticity of the client's public key
/// - The resulting session keys should be used with appropriate symmetric encryption
/// - The server's tx key corresponds to the client's rx key, and vice versa
/// - The session keys are derived using BLAKE2b, which is resistant to length extension attacks
/// - Different keys are used for each direction to prevent reflection attacks
/// - The key exchange provides forward secrecy if new keypairs are generated for each session
///
/// ## Arguments
///
/// * `server_pk` - The server's public key
/// * `server_sk` - The server's secret key
/// * `client_pk` - The client's public key
///
/// ## Returns
///
/// * `Result<SessionKeys>` - A pair of session keys for bidirectional communication
///
/// ## Errors
///
/// Returns an error if the key computation fails, which can happen if:
/// - The public keys are invalid
/// - The secret key is invalid
/// - The public keys represent the same identity (server_pk == client_pk)
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_kx;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate keypairs for client and server
/// let client_keypair = crypto_kx::KeyPair::generate().unwrap();
/// let client_pk = client_keypair.public_key;
/// let client_sk = client_keypair.secret_key;
/// let server_keypair = crypto_kx::KeyPair::generate().unwrap();
/// let server_pk = server_keypair.public_key;
/// let server_sk = server_keypair.secret_key;
///
/// // Server computes session keys
/// let server_keys = crypto_kx::server_session_keys(
///     &server_pk,
///     &server_sk,
///     &client_pk,
/// ).unwrap();
///
/// // Now server_keys.tx can be used to encrypt messages to the client,
/// // and server_keys.rx can be used to decrypt messages from the client.
/// ```
pub fn server_session_keys(
    server_pk: &PublicKey,
    server_sk: &SecretKey,
    client_pk: &PublicKey,
) -> Result<SessionKeys> {
    let mut rx = [0u8; SESSIONKEYBYTES];
    let mut tx = [0u8; SESSIONKEYBYTES];

    let result = unsafe {
        libsodium_sys::crypto_kx_server_session_keys(
            rx.as_mut_ptr(),
            tx.as_mut_ptr(),
            server_pk.as_bytes().as_ptr(),
            server_sk.as_bytes().as_ptr(),
            client_pk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "failed to compute session keys".into(),
        ));
    }

    Ok(SessionKeys { rx, tx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let sk = keypair.secret_key;
        assert_eq!(pk.as_bytes().len(), PUBLICKEYBYTES);
        assert_eq!(sk.as_bytes().len(), SECRETKEYBYTES);
    }

    #[test]
    fn test_key_exchange() {
        // Generate keypairs for client and server
        let client_keypair = KeyPair::generate().unwrap();
        let client_pk = client_keypair.public_key;
        let client_sk = client_keypair.secret_key;
        let server_keypair = KeyPair::generate().unwrap();
        let server_pk = server_keypair.public_key;
        let server_sk = server_keypair.secret_key;

        // Compute session keys
        let client_keys = client_session_keys(&client_pk, &client_sk, &server_pk).unwrap();
        let server_keys = server_session_keys(&server_pk, &server_sk, &client_pk).unwrap();

        // Verify that the session keys match (client_tx = server_rx and client_rx = server_tx)
        assert_eq!(client_keys.tx, server_keys.rx);
        assert_eq!(client_keys.rx, server_keys.tx);
    }

    #[test]
    fn test_public_key_asref() {
        let keypair = KeyPair::generate().unwrap();
        let public_key = keypair.public_key;
        let bytes_ref: &[u8] = public_key.as_ref();
        assert_eq!(bytes_ref.len(), PUBLICKEYBYTES);
        assert_eq!(bytes_ref, public_key.as_bytes());
    }

    #[test]
    fn test_public_key_try_from_slice() {
        // Valid case
        let bytes = [42u8; PUBLICKEYBYTES];
        let public_key = PublicKey::try_from(&bytes[..]).unwrap();
        assert_eq!(public_key.as_bytes(), &bytes);

        // Invalid case - wrong length
        let short_bytes = [42u8; PUBLICKEYBYTES - 1];
        assert!(PublicKey::try_from(&short_bytes[..]).is_err());

        let long_bytes = [42u8; PUBLICKEYBYTES + 1];
        assert!(PublicKey::try_from(&long_bytes[..]).is_err());
    }

    #[test]
    fn test_public_key_from_bytes() {
        let bytes = [42u8; PUBLICKEYBYTES];
        let public_key = PublicKey::from(bytes);
        assert_eq!(public_key.as_bytes(), &bytes);
    }

    #[test]
    fn test_public_key_into_bytes() {
        let bytes = [42u8; PUBLICKEYBYTES];
        let public_key = PublicKey::from(bytes);
        let array: [u8; PUBLICKEYBYTES] = public_key.into();
        assert_eq!(array, bytes);
    }

    #[test]
    fn test_secret_key_asref() {
        let keypair = KeyPair::generate().unwrap();
        let secret_key = keypair.secret_key;
        let bytes_ref: &[u8] = secret_key.as_ref();
        assert_eq!(bytes_ref.len(), SECRETKEYBYTES);
        assert_eq!(bytes_ref, secret_key.as_bytes());
    }

    #[test]
    fn test_secret_key_try_from_slice() {
        // Valid case
        let bytes = [42u8; SECRETKEYBYTES];
        let secret_key = SecretKey::try_from(&bytes[..]).unwrap();
        assert_eq!(secret_key.as_bytes(), &bytes);

        // Invalid case - wrong length
        let short_bytes = [42u8; SECRETKEYBYTES - 1];
        assert!(SecretKey::try_from(&short_bytes[..]).is_err());

        let long_bytes = [42u8; SECRETKEYBYTES + 1];
        assert!(SecretKey::try_from(&long_bytes[..]).is_err());
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = [42u8; SECRETKEYBYTES];
        let secret_key = SecretKey::from(bytes);
        assert_eq!(secret_key.as_bytes(), &bytes);
    }

    #[test]
    fn test_secret_key_into_bytes() {
        let bytes = [42u8; SECRETKEYBYTES];
        let secret_key = SecretKey::from(bytes);
        let array: [u8; SECRETKEYBYTES] = secret_key.into();
        assert_eq!(array, bytes);
    }

    #[test]
    fn test_secret_key_zeroization() {
        let bytes = [42u8; SECRETKEYBYTES];
        let secret_key = SecretKey::from(bytes);

        // Convert to array and drop the original
        let array: [u8; SECRETKEYBYTES] = secret_key.into();
        assert_eq!(array, bytes);

        // The original secret_key is now dropped and should be zeroized
        // (We can't directly test this as the memory is freed, but the
        // ZeroizeOnDrop trait ensures it happens)
    }

    #[test]
    fn test_roundtrip_conversions() {
        // Test PublicKey roundtrip
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let pk_bytes = pk.as_bytes().to_vec();

        // Via TryFrom
        let pk2 = PublicKey::try_from(&pk_bytes[..]).unwrap();
        assert_eq!(pk2.as_bytes(), pk_bytes);

        // Via From array
        let pk_array: [u8; PUBLICKEYBYTES] = pk2.into();
        let pk3 = PublicKey::from(pk_array);
        assert_eq!(pk3.as_bytes(), pk_bytes);

        // Test SecretKey roundtrip
        let sk = keypair.secret_key;
        let sk_bytes = sk.as_bytes().to_vec();

        // Via TryFrom
        let sk2 = SecretKey::try_from(&sk_bytes[..]).unwrap();
        assert_eq!(sk2.as_bytes(), sk_bytes);

        // Via From array
        let sk_array: [u8; SECRETKEYBYTES] = sk2.into();
        let sk3 = SecretKey::from(sk_array);
        assert_eq!(sk3.as_bytes(), sk_bytes);
    }
}
