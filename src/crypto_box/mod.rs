//! # Public-Key Cryptography
//!
//! This module provides functions for authenticated encryption using public-key cryptography.
//! It implements the X25519-XSalsa20-Poly1305 construction, which combines the X25519
//! key exchange with the XSalsa20 stream cipher and the Poly1305 message authentication code.
//!
//! This construction is also known as NaCl's crypto_box.
//!
//! ## Features
//!
//! - Authenticated encryption with public-key cryptography
//! - Protection against tampering and forgery
//! - Secure key exchange using X25519 elliptic curve Diffie-Hellman
//! - Strong encryption using XSalsa20 stream cipher
//! - Message authentication using Poly1305 MAC
//! - Forward secrecy when using ephemeral keys
//!
//! ## Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_box;
//! use sodium::random;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate key pairs for Alice and Bob
//! let alice_keypair = crypto_box::KeyPair::generate();
//! let alice_pk = alice_keypair.public_key;
//! let alice_sk = alice_keypair.secret_key;
//! let bob_keypair = crypto_box::KeyPair::generate();
//! let bob_pk = bob_keypair.public_key;
//! let bob_sk = bob_keypair.secret_key;
//!
//! // Generate a random nonce
//! let nonce = crypto_box::Nonce::generate();
//!
//! // Alice encrypts a message for Bob
//! let message = b"Hello, Bob! This is a secret message.";
//! let ciphertext = crypto_box::seal(message, &nonce, &bob_pk, &alice_sk).unwrap();
//!
//! // Bob decrypts the message from Alice
//! let decrypted = crypto_box::open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();
//! assert_eq!(message, &decrypted[..]);
//! ```
//!
//! ## Security Considerations
//!
//! - Always use a unique nonce for each encryption operation with the same key pair
//! - For maximum security, use ephemeral keys for each communication session
//! - The secret key should be kept confidential
//! - The public key can be shared freely
//! - This implementation uses constant-time operations to prevent timing attacks
//! - For long-term security, consider using the XChaCha20-Poly1305 variant in the
//!   `curve25519xchacha20poly1305` submodule
//! - Be aware that X25519 is based on Curve25519, which has a cofactor of 8
//! - The shared secret established through X25519 is automatically hashed before being used
//!   as an encryption key
//! - The encryption provides authenticated encryption with associated data (AEAD)
//!   which means it protects both confidentiality and integrity

use crate::{Result, SodiumError};
use ct_codecs;
use ct_codecs::Encoder;
use libsodium_sys;

/// Number of bytes in a public key (32)
///
/// The public key is used for encryption and can be shared publicly.
/// It is based on the X25519 elliptic curve cryptography.
pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_box_PUBLICKEYBYTES as usize;

/// Number of bytes in a secret key (32)
///
/// The secret key is used for decryption and should be kept private.
/// It is based on the X25519 elliptic curve cryptography.
pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_box_SECRETKEYBYTES as usize;

/// Number of bytes in a nonce (24)
///
/// The nonce is a unique value used for each encryption operation.
/// It should never be reused with the same key pair.
pub const NONCEBYTES: usize = libsodium_sys::crypto_box_NONCEBYTES as usize;

/// A nonce for use with crypto_box functions
///
/// This struct represents a nonce of the appropriate size (NONCEBYTES)
/// for use with the encryption and decryption functions in this module.
///
/// A nonce must be unique for each encryption operation with the same key pair.
#[derive(Clone, Eq, PartialEq)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    /// Generate a new random nonce
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A random nonce for use with crypto_box functions
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_box;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random nonce
    /// let nonce = crypto_box::Nonce::generate();
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCEBYTES];
        crate::random::fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from raw bytes
    ///
    /// ## Arguments
    ///
    /// * `bytes` - Byte array of exactly NONCEBYTES length
    ///
    /// ## Returns
    ///
    /// * `Nonce` - A nonce initialized with the provided bytes
    pub const fn from_bytes_exact(bytes: [u8; NONCEBYTES]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the underlying bytes
    ///
    /// ## Returns
    ///
    /// * `&[u8; NONCEBYTES]` - Reference to the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NONCEBYTES] {
        &self.0
    }

    /// Get a mutable reference to the underlying bytes
    ///
    /// ## Returns
    ///
    /// * `&mut [u8; NONCEBYTES]` - Mutable reference to the nonce bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; NONCEBYTES] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = crate::SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        if slice.len() != NONCEBYTES {
            return Err(crate::SodiumError::InvalidNonce(format!(
                "nonce must be exactly {NONCEBYTES} bytes"
            )));
        }

        let mut bytes = [0u8; NONCEBYTES];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = ct_codecs::Hex::encode_to_string(&self.0[..4]).unwrap_or_default();
        write!(f, "Nonce({hex})...")
    }
}

/// Generate a random nonce for use with crypto_box functions (legacy function)
///
/// This function generates a random nonce of the appropriate size (NONCEBYTES)
/// for use with the encryption and decryption functions in this module.
///
/// ## Returns
///
/// * `Vec<u8>` - A random nonce of length NONCEBYTES
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
/// assert_eq!(nonce.as_ref().len(), crypto_box::NONCEBYTES);
/// ```
///
/// Number of bytes in a MAC (message authentication code) (16)
///
/// The MAC is used to verify the authenticity and integrity of the message.
/// It is added to the ciphertext during encryption.
pub const MACBYTES: usize = libsodium_sys::crypto_box_MACBYTES as usize;

/// Number of bytes in a precomputed key (32)
///
/// The precomputed key is the result of the Diffie-Hellman key exchange,
/// which can be reused for multiple encryption/decryption operations.
pub const BEFORENMBYTES: usize = libsodium_sys::crypto_box_BEFORENMBYTES as usize;

/// Number of zero bytes required for NaCl compatibility (32)
///
/// This is used only with the NaCl compatibility API.
pub const ZEROBYTES: usize = libsodium_sys::crypto_box_ZEROBYTES as usize;

/// Number of zero bytes required in ciphertext for NaCl compatibility (16)
///
/// This is used only with the NaCl compatibility API.
pub const BOXZEROBYTES: usize = libsodium_sys::crypto_box_BOXZEROBYTES as usize;

/// Number of bytes in a sealed box (48)
///
/// A sealed box is used for anonymous encryption, where the sender's identity is not revealed.
pub const SEALBYTES: usize = libsodium_sys::crypto_box_SEALBYTES as usize;

/// A public key for asymmetric encryption using X25519
///
/// This key is used for encrypting messages and can be shared publicly.
/// It is derived from the corresponding secret key using the X25519 elliptic curve.
///
/// ## Properties
///
/// - Size: 32 bytes (256 bits)
/// - Based on the X25519 elliptic curve
/// - Can be safely shared with anyone
/// - Used to encrypt messages that can only be decrypted with the corresponding secret key
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

/// A secret key for asymmetric encryption using X25519
///
/// This key is used for decrypting messages and must be kept private.
/// It is randomly generated and used to derive the corresponding public key.
///
/// ## Properties
///
/// - Size: 32 bytes (256 bits)
/// - Based on the X25519 elliptic curve
/// - Must be kept confidential
/// - Used to decrypt messages that were encrypted with the corresponding public key
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

/// A key pair for public-key encryption
///
/// Contains both a public key and a secret key for use with crypto_box functions.
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl PublicKey {
    /// Generate a new public key from bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte slice of exactly PUBLICKEYBYTES length
    ///
    /// # Returns
    /// * `Result<Self>` - A new public key or an error if the input is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != libsodium_sys::crypto_box_PUBLICKEYBYTES as usize {
            return Err(SodiumError::InvalidKey(format!(
                "public key must be exactly {} bytes",
                libsodium_sys::crypto_box_PUBLICKEYBYTES
            )));
        }

        let mut key = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
        key.copy_from_slice(bytes);
        Ok(PublicKey(key))
    }

    /// Create a public key from a fixed-size bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly PUBLICKEYBYTES length
    ///
    /// # Returns
    /// * `Self` - A new public key
    pub const fn from_bytes_exact(
        bytes: [u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    ) -> Self {
        Self(bytes)
    }

    /// Get a reference to the underlying bytes
    ///
    /// # Returns
    /// * `&[u8; PUBLICKEYBYTES]` - Reference to the public key bytes
    pub fn as_bytes(&self) -> &[u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize]> for PublicKey {
    fn from(bytes: [u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; PUBLICKEYBYTES] {
    fn from(key: PublicKey) -> [u8; PUBLICKEYBYTES] {
        key.0
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = ct_codecs::Hex::encode_to_string(&self.0[..4]).unwrap_or_default();
        write!(f, "PublicKey({hex})...")
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = ct_codecs::Hex::encode_to_string(&self.0[..4]).unwrap_or_default();
        write!(f, "PublicKey({hex})...")
    }
}

impl SecretKey {
    /// Generate a new secret key from bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte slice of exactly SECRETKEYBYTES length
    ///
    /// # Returns
    /// * `Result<Self>` - A new secret key or an error if the input is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != libsodium_sys::crypto_box_SECRETKEYBYTES as usize {
            return Err(SodiumError::InvalidKey(format!(
                "secret key must be exactly {} bytes",
                libsodium_sys::crypto_box_SECRETKEYBYTES
            )));
        }

        let mut key = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];
        key.copy_from_slice(bytes);
        Ok(SecretKey(key))
    }

    /// Create a secret key from a fixed-size bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly SECRETKEYBYTES length
    ///
    /// # Returns
    /// * `Self` - A new secret key
    pub const fn from_bytes_exact(
        bytes: [u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
    ) -> Self {
        Self(bytes)
    }

    /// Get a reference to the underlying bytes
    ///
    /// # Returns
    /// * `&[u8; SECRETKEYBYTES]` - Reference to the secret key bytes
    pub fn as_bytes(&self) -> &[u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize]> for SecretKey {
    fn from(bytes: [u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize]) -> Self {
        Self(bytes)
    }
}

impl From<SecretKey> for [u8; SECRETKEYBYTES] {
    fn from(key: SecretKey) -> [u8; SECRETKEYBYTES] {
        key.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(*****)")
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(*****)")
    }
}

/// A precomputed shared key for public-key cryptography
///
/// This key is the result of the Diffie-Hellman key exchange between a public key
/// and a secret key. It can be reused for multiple encryption/decryption operations
/// with the same pair of keys, improving performance.
///
/// ## Properties
///
/// - Size: 32 bytes (256 bits)
/// - Derived from a public key and a secret key
/// - Must be kept confidential
/// - Can be used for multiple encryption/decryption operations
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PrecomputedKey([u8; BEFORENMBYTES]);

impl PrecomputedKey {
    /// Generate a new precomputed key from bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte slice of exactly BEFORENMBYTES length
    ///
    /// # Returns
    /// * `Result<Self>` - A new precomputed key or an error if the input is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BEFORENMBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "precomputed key must be exactly {BEFORENMBYTES} bytes"
            )));
        }

        let mut k = [0u8; BEFORENMBYTES];
        k.copy_from_slice(bytes);
        Ok(PrecomputedKey(k))
    }

    /// Get a reference to the underlying bytes
    ///
    /// # Returns
    /// * `&[u8; BEFORENMBYTES]` - Reference to the precomputed key bytes
    pub fn as_bytes(&self) -> &[u8; BEFORENMBYTES] {
        &self.0
    }

    /// Create a precomputed key from a fixed-size bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly BEFORENMBYTES length
    ///
    /// # Returns
    /// * `Self` - A new precomputed key
    pub const fn from_bytes_exact(bytes: [u8; BEFORENMBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PrecomputedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PrecomputedKey {
    type Error = SodiumError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_bytes(slice)
    }
}

impl From<[u8; BEFORENMBYTES]> for PrecomputedKey {
    fn from(bytes: [u8; BEFORENMBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<PrecomputedKey> for [u8; BEFORENMBYTES] {
    fn from(key: PrecomputedKey) -> [u8; BEFORENMBYTES] {
        key.0
    }
}

impl KeyPair {
    /// Generate a new key pair for public-key encryption
    ///
    /// This function generates a new random X25519 key pair suitable for public-key encryption
    /// and decryption. The key generation process uses libsodium's secure random number generator.
    ///
    /// ## Algorithm Details
    ///
    /// The key pair generation works as follows:
    /// 1. Generate 32 random bytes for the secret key
    /// 2. Derive the public key from the secret key using the X25519 elliptic curve
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_box;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key pair
    /// let keypair = crypto_box::KeyPair::generate();
    ///
    /// // The keys can now be used for encryption and decryption
    /// assert_eq!(keypair.public_key.as_bytes().len(), crypto_box::PUBLICKEYBYTES);
    /// assert_eq!(keypair.secret_key.as_bytes().len(), crypto_box::SECRETKEYBYTES);
    /// ```
    ///
    /// # Returns
    /// * `KeyPair` - A new key pair
    ///
    /// # Note
    /// This function should not fail under normal circumstances. In the extremely unlikely event
    /// of a system-level failure, this function might panic.
    pub fn generate() -> Self {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        let result = unsafe { libsodium_sys::crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

        // This should never happen in practice, but we check anyway for safety
        assert_eq!(result, 0, "Failed to generate keypair");

        Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        }
    }

    /// Generate a new key pair from a seed
    ///
    /// This function generates a deterministic X25519 key pair from a seed. Given the same seed,
    /// it will always produce the same key pair. This is useful for applications that need
    /// deterministic key generation, such as when deriving keys from a master key.
    ///
    /// ## Security Considerations
    ///
    /// - The seed must be kept as secret as the secret key itself
    /// - The seed should be high-entropy (ideally from a CSPRNG)
    /// - If you need non-deterministic key generation, use `generate()` instead
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_box;
    /// use sodium::random;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random seed
    /// let mut seed = [0u8; 32];
    /// random::fill_bytes(&mut seed);
    ///
    /// // Generate a keypair from the seed
    /// let keypair1 = crypto_box::KeyPair::from_seed(&seed).unwrap();
    ///
    /// // The same seed will always produce the same keypair
    /// let keypair2 = crypto_box::KeyPair::from_seed(&seed).unwrap();
    /// assert_eq!(keypair1.public_key, keypair2.public_key);
    /// assert_eq!(keypair1.secret_key, keypair2.secret_key);
    /// ```
    ///
    /// # Arguments
    /// * `seed` - The seed to generate the keypair from (must be exactly 32 bytes)
    ///
    /// # Returns
    /// * `Result<KeyPair>` - A deterministically generated key pair or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// * The seed has an invalid length
    /// * Key generation fails (extremely rare, typically only due to system issues)
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != SECRETKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid seed length: expected {}, got {}",
                SECRETKEYBYTES,
                seed.len()
            )));
        }

        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        let result = unsafe {
            libsodium_sys::crypto_box_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to generate keypair from seed".into(),
            ));
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Convert the KeyPair into a tuple of (PublicKey, SecretKey)
    ///
    /// This function consumes the KeyPair and returns its components as a tuple.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_box;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key pair
    /// let keypair = crypto_box::KeyPair::generate();
    ///
    /// // Convert to tuple
    /// let (public_key, secret_key) = keypair.into_tuple();
    /// ```
    pub fn into_tuple(self) -> (PublicKey, SecretKey) {
        (self.public_key, self.secret_key)
    }
}

/// ## Algorithm Details
///
/// 1. A shared secret is computed using X25519 key exchange
/// 2. The shared secret is hashed using the HSalsa20 function
/// 3. The resulting key is used with XSalsa20 for encryption
/// 4. Poly1305 is used to authenticate the ciphertext, ensuring integrity
///
/// ## Security Considerations
///
/// - Always use a unique nonce for each encryption operation with the same key pair
/// - The nonce can be public, but must never be reused with the same key pair
/// - For maximum security, use `Nonce::generate()` to create random nonces
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
///
/// // Alice encrypts a message for Bob
/// let message = b"Hello, Bob! This is a secret message.";
/// let ciphertext = crypto_box::seal(message, &nonce, &bob_pk, &alice_sk).unwrap();
///
/// // The ciphertext is longer than the message due to the added MAC
/// assert_eq!(ciphertext.len(), message.len() + crypto_box::MACBYTES);
/// ```
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption
/// * `recipient_pk` - Recipient's public key
/// * `sender_sk` - Sender's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message (ciphertext) or an error
///
/// # Errors
/// Returns an error if the encryption operation fails (extremely rare)
pub fn seal(
    message: &[u8],
    nonce: &Nonce,
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
) -> Result<Vec<u8>> {
    let mut ciphertext = vec![0u8; message.len() + MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            recipient_pk.as_bytes().as_ptr(),
            sender_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "crypto_box encryption failed".into(),
        ));
    }

    Ok(ciphertext)
}

/// Encrypts a message using public-key cryptography with a precomputed shared key
///
/// This function is similar to `seal`, but it uses a precomputed shared key
/// instead of computing it from the public and secret keys. This can improve
/// performance when encrypting multiple messages with the same key pair.
///
/// ## Algorithm Details
///
/// 1. The precomputed shared key (already derived from X25519 and hashed with HSalsa20)
///    is used directly for XSalsa20 encryption
/// 2. Poly1305 is used to authenticate the ciphertext, ensuring integrity
///
/// ## Security Considerations
///
/// - Always use a unique nonce for each encryption operation with the same key pair
/// - The nonce can be public, but must never be reused with the same key pair
/// - For maximum security, use `Nonce::generate()` to create random nonces
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Alice precomputes a shared key with Bob
/// let alice_precomputed = crypto_box::beforenm(&bob_pk, &alice_sk).unwrap();
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
///
/// // Alice encrypts a message for Bob using the precomputed key
/// let message = b"Hello, Bob! This is a secret message.";
/// let ciphertext = crypto_box::seal_afternm(message, &nonce, &alice_precomputed).unwrap();
/// ```
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message or an error
///
/// # Errors
/// Returns an error if the encryption operation fails (extremely rare)
pub fn seal_afternm(
    message: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    let ciphertext_len = message.len() + MACBYTES;
    let mut ciphertext = vec![0u8; ciphertext_len];

    let result = unsafe {
        libsodium_sys::crypto_box_easy_afternm(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok(ciphertext)
}

/// Decrypts a message using public-key cryptography
///
/// This function decrypts a message using the X25519-XSalsa20-Poly1305 construction.
/// The recipient uses their secret key and the sender's public key to decrypt
/// the message.
///
/// ## Algorithm Details
///
/// 1. A shared secret is computed using X25519 key exchange
/// 2. The shared secret is hashed using the HSalsa20 function
/// 3. The resulting key is used with XSalsa20 for decryption
/// 4. Poly1305 is used to authenticate the ciphertext, ensuring integrity
///
/// ## Security Considerations
///
/// - If decryption fails, it could be due to tampering, using the wrong keys, or using the wrong nonce
/// - The decryption operation is performed in constant time to prevent timing attacks
/// - If verification fails, no part of the message is considered authentic
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
///
/// // Alice encrypts a message for Bob
/// let message = b"Hello, Bob! This is a secret message.";
/// let ciphertext = crypto_box::seal(message, &nonce, &bob_pk, &alice_sk).unwrap();
///
/// // Bob decrypts the message from Alice
/// let decrypted = crypto_box::open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();
/// assert_eq!(message, &decrypted[..]);
///
/// // Tamper with the ciphertext - decryption should fail
/// let mut tampered = ciphertext.clone();
/// tampered[0] ^= 1; // Flip a bit in the ciphertext
/// assert!(crypto_box::open(&tampered, &nonce, &alice_pk, &bob_sk).is_err());
/// ```
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt
/// * `nonce` - Nonce used for encryption
/// * `sender_pk` - Sender's public key
/// * `recipient_sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
///
/// # Errors
/// Returns an error if:
/// - The ciphertext is too short (less than MACBYTES)
/// - The MAC verification fails (indicating tampering or incorrect keys/nonce)
/// - The decryption operation fails
pub fn open(ciphertext: &[u8], nonce: &Nonce, pk: &PublicKey, sk: &SecretKey) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            pk.as_bytes().as_ptr(),
            sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::AuthenticationError);
    }

    Ok(message)
}

/// Decrypts a message using public-key cryptography with a precomputed shared key
///
/// This function is similar to `open`, but it uses a precomputed shared key
/// instead of computing it from the public and secret keys. This can improve
/// performance when decrypting multiple messages with the same key pair.
///
/// ## Algorithm Details
///
/// 1. The precomputed shared key (already derived from X25519 and hashed with HSalsa20)
///    is used directly for XSalsa20 decryption
/// 2. Poly1305 is used to authenticate the ciphertext, ensuring integrity
///
/// ## Security Considerations
///
/// - If decryption fails, it could be due to tampering, using the wrong keys, or using the wrong nonce
/// - The decryption operation is performed in constant time to prevent timing attacks
/// - If verification fails, no part of the message is considered authentic
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Bob precomputes a shared key with Alice
/// let bob_precomputed = crypto_box::beforenm(&alice_pk, &bob_sk).unwrap();
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
///
/// // Alice encrypts a message for Bob using the precomputed key
/// let message = b"Hello, Bob! This is a secret message.";
/// let alice_precomputed = crypto_box::beforenm(&bob_pk, &alice_sk).unwrap();
/// let ciphertext = crypto_box::seal_afternm(message, &nonce, &alice_precomputed).unwrap();
///
/// // Bob decrypts the message from Alice using the precomputed key
/// let decrypted = crypto_box::open_afternm(&ciphertext, &nonce, &bob_precomputed).unwrap();
/// assert_eq!(message, &decrypted[..]);
/// ```
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt
/// * `nonce` - Nonce used for encryption
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
///
/// # Errors
/// Returns an error if:
/// - The ciphertext is too short (less than MACBYTES)
/// - The MAC verification fails (indicating tampering or incorrect keys/nonce)
/// - The decryption operation fails
pub fn open_afternm(
    ciphertext: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    if ciphertext.len() < MACBYTES {
        return Err(SodiumError::InvalidInput("ciphertext too short".into()));
    }

    let mut message = vec![0u8; ciphertext.len() - MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_open_easy_afternm(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// Computes a shared secret key from a public key and a secret key
///
/// This function performs the X25519 key exchange to compute a shared secret
/// that can be used for symmetric encryption. It's useful when you need to
/// perform multiple encryption operations with the same key pair.
///
/// ## Algorithm Details
///
/// The shared secret is computed using the X25519 function, which is an
/// implementation of the elliptic curve Diffie-Hellman key exchange using
/// Curve25519. The raw output of X25519 is then hashed using the HSalsa20
/// function to derive the final symmetric key.
///
/// ## Security Considerations
///
/// - The shared secret should be kept confidential
/// - The shared secret should be used with a secure symmetric encryption algorithm
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Alice precomputes a shared key with Bob
/// let alice_precomputed = crypto_box::beforenm(&bob_pk, &alice_sk).unwrap();
///
/// // Bob precomputes a shared key with Alice
/// let bob_precomputed = crypto_box::beforenm(&alice_pk, &bob_sk).unwrap();
///
/// // These precomputed keys can now be used for faster encryption/decryption
/// ```
///
/// # Arguments
/// * `public_key` - The public key of the other party
/// * `secret_key` - Your secret key
///
/// # Returns
/// * `Result<PrecomputedKey>` - The precomputed shared key or an error
///
/// # Example
/// ```rust
///   use libsodium_rs as sodium;
///   use sodium::crypto_box;
///   use sodium::random;
///   use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Alice precomputes a shared key with Bob
/// let alice_precomputed = crypto_box::beforenm(&bob_pk, &alice_sk).unwrap();
///
/// // Bob precomputes a shared key with Alice
/// let bob_precomputed = crypto_box::beforenm(&alice_pk, &bob_sk).unwrap();
///
/// // These precomputed keys can now be used for faster encryption/decryption
/// ```
pub fn beforenm(public_key: &PublicKey, secret_key: &SecretKey) -> Result<PrecomputedKey> {
    let mut k = [0u8; BEFORENMBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_beforenm(
            k.as_mut_ptr(),
            public_key.as_bytes().as_ptr(),
            secret_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "precomputed key generation failed".into(),
        ));
    }

    Ok(PrecomputedKey(k))
}

/// Encrypt a message using a precomputed key
///
/// This function is more efficient when encrypting multiple messages for the same recipient.
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption (must be NONCEBYTES bytes)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message or an error
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Alice precomputes a shared key with Bob
/// let alice_precomputed = crypto_box::beforenm(&bob_pk, &alice_sk).unwrap();
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
///
/// // Alice encrypts a message for Bob using the precomputed key
/// let message = b"Hello, Bob! This is a secret message.";
/// let ciphertext = crypto_box::seal_afternm(message, &nonce, &alice_precomputed).unwrap();
/// ```
/// Decrypt a message using a precomputed key
///
/// This function is more efficient when decrypting multiple messages from the same sender.
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt
/// * `nonce` - Nonce used for encryption (must be NONCEBYTES bytes)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_box;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate key pairs for Alice and Bob
/// let alice_keypair = crypto_box::KeyPair::generate();
/// let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
/// let bob_keypair = crypto_box::KeyPair::generate();
/// let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
///
/// // Bob precomputes a shared key with Alice
/// let bob_precomputed = crypto_box::beforenm(&alice_pk, &bob_sk).unwrap();
///
/// // Generate a random nonce
/// let nonce = crypto_box::Nonce::generate();
///
/// // Alice encrypts a message for Bob using the precomputed key
/// let message = b"Hello, Bob! This is a secret message.";
/// let alice_precomputed = crypto_box::beforenm(&bob_pk, &alice_sk).unwrap();
/// let ciphertext = crypto_box::seal_afternm(message, &nonce, &alice_precomputed).unwrap();
///
/// // Bob decrypts the message from Alice using the precomputed key
/// let decrypted = crypto_box::open_afternm(&ciphertext, &nonce, &bob_precomputed).unwrap();
/// assert_eq!(message, &decrypted[..]);
/// ```
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption
/// * `recipient_pk` - Recipient's public key
/// * `sender_sk` - Sender's secret key
///
/// # Returns
/// * `Result<(Vec<u8>, [u8; MACBYTES])>` - Tuple of (ciphertext, authentication tag) or an error
pub fn seal_detached(
    message: &[u8],
    nonce: &Nonce,
    recipient_pk: &PublicKey,
    sender_sk: &SecretKey,
) -> Result<(Vec<u8>, [u8; MACBYTES])> {
    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = [0u8; MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            recipient_pk.as_bytes().as_ptr(),
            sender_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "crypto_box detached encryption failed".into(),
        ));
    }

    Ok((ciphertext, mac))
}

/// Encrypt a message with detached authentication tag (legacy version)
///
/// This function is a legacy version that accepts a raw byte slice for the nonce.
/// It's recommended to use the version that accepts a `Nonce` type instead.
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption (must be NONCEBYTES bytes)
/// * `recipient_pk` - Recipient's public key
/// * `sender_sk` - Sender's secret key
///
/// # Returns
/// * `Result<(Vec<u8>, [u8; MACBYTES])>` - Tuple of (ciphertext, authentication tag) or an error
///
/// Decrypt a message with detached authentication tag
///
/// This function decrypts a message using a separately provided authentication tag.
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt
/// * `mac` - Authentication tag (must be MACBYTES bytes)
/// * `nonce` - Nonce used for encryption
/// * `sender_pk` - Sender's public key
/// * `recipient_sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
pub fn open_detached(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &Nonce,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<Vec<u8>> {
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_open_detached(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            pk.as_bytes().as_ptr(),
            sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::AuthenticationError);
    }

    Ok(message)
}

/// Decrypt a message with detached authentication tag (legacy version)
///
/// This function is a legacy version that accepts a raw byte slice for the nonce.
/// It's recommended to use the version that accepts a `Nonce` type instead.
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt
/// * `mac` - Authentication tag (must be MACBYTES bytes)
/// * `nonce` - Nonce used for encryption (must be NONCEBYTES bytes)
/// * `sender_pk` - Sender's public key
/// * `recipient_sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
///
/// Encrypt a message with detached authentication tag using a precomputed key
///
/// This function encrypts a message and returns the ciphertext and authentication tag separately.
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `nonce` - Nonce for encryption (must be NONCEBYTES bytes)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>)>` - Tuple of (ciphertext, authentication tag) or an error
pub fn seal_detached_afternm(
    message: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; MACBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_detached_afternm(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok((ciphertext, mac))
}

/// Decrypt a message with detached authentication tag using a precomputed key
///
/// This function decrypts a message using a separately provided authentication tag.
///
/// # Arguments
/// * `ciphertext` - Ciphertext to decrypt
/// * `mac` - Authentication tag
/// * `nonce` - Nonce used for encryption
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
pub fn open_detached_afternm(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    let mut message = vec![0u8; ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_open_detached_afternm(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// Encrypt a message for a recipient without revealing the sender's identity
///
/// This function generates an ephemeral key pair, performs a key exchange with the recipient's
/// public key, and then encrypts the message. The ephemeral public key is included in the output.
///
/// ## Algorithm Details
///
/// The sealed box construction works as follows:
/// 1. Generate an ephemeral key pair
/// 2. Perform a key exchange with the recipient's public key to create a shared secret
/// 3. Use the shared secret to encrypt the message
/// 4. Combine the ephemeral public key with the ciphertext
///
/// This provides anonymity for the sender while ensuring only the intended recipient can decrypt
/// the message.
///
/// ## Security Considerations
///
/// - The recipient cannot authenticate the sender's identity
/// - Each message uses a unique ephemeral key pair, providing forward secrecy
/// - The output is deterministic for the same input message and recipient key
///
/// # Arguments
/// * `message` - Message to encrypt
/// * `recipient_pk` - Recipient's public key
///
/// # Returns
/// * `Result<Vec<u8>>` - Sealed box (ephemeral public key + ciphertext) or an error
pub fn seal_box(message: &[u8], recipient_pk: &PublicKey) -> Result<Vec<u8>> {
    let mut sealed_box = vec![0u8; message.len() + SEALBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_seal(
            sealed_box.as_mut_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            recipient_pk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::EncryptionError(
            "sealed box encryption failed".into(),
        ));
    }

    Ok(sealed_box)
}

/// Decrypt a message from an anonymous sender
///
/// This function decrypts a message that was encrypted using seal_box().
/// It extracts the ephemeral public key from the sealed box and performs the key exchange.
///
/// # Arguments
/// * `sealed_box` - Sealed box (ephemeral public key + ciphertext)
/// * `recipient_pk` - Recipient's public key
/// * `recipient_sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message or an error
pub fn open_sealed_box(
    sealed_box: &[u8],
    recipient_pk: &PublicKey,
    recipient_sk: &SecretKey,
) -> Result<Vec<u8>> {
    if sealed_box.len() < SEALBYTES {
        return Err(SodiumError::InvalidInput("sealed box too short".into()));
    }

    let mut message = vec![0u8; sealed_box.len() - SEALBYTES];

    let result = unsafe {
        libsodium_sys::crypto_box_seal_open(
            message.as_mut_ptr(),
            sealed_box.as_ptr(),
            sealed_box.len() as libc::c_ulonglong,
            recipient_pk.as_bytes().as_ptr(),
            recipient_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "sealed box decryption failed".into(),
        ));
    }

    Ok(message)
}

/// NaCl compatibility: Encrypt a message using XSalsa20-Poly1305 with zero padding
///
/// This function is provided for compatibility with the NaCl API.
/// It requires the message to be padded with ZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_message` - Message to encrypt, with ZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce for encryption (must be NONCEBYTES bytes)
/// * `recipient_pk` - Recipient's public key
/// * `sender_sk` - Sender's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message (with BOXZEROBYTES zero bytes at the beginning) or an error
pub fn seal_nacl(
    padded_message: &[u8],
    nonce: &Nonce,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<Vec<u8>> {
    if padded_message.len() < ZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded message must be at least {ZEROBYTES} bytes"
        )));
    }

    // Verify that the first ZEROBYTES bytes of the message are all 0
    if padded_message.iter().take(ZEROBYTES).any(|&byte| byte != 0) {
        return Err(SodiumError::InvalidInput(format!(
            "first {ZEROBYTES} bytes of padded message must be zero"
        )));
    }

    let mut ciphertext = vec![0u8; padded_message.len()];

    let result = unsafe {
        libsodium_sys::crypto_box(
            ciphertext.as_mut_ptr(),
            padded_message.as_ptr(),
            padded_message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            pk.as_bytes().as_ptr(),
            sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok(ciphertext)
}

/// NaCl compatibility: Decrypt a message using XSalsa20-Poly1305 with zero padding
///
/// This function is provided for compatibility with the NaCl API.
/// The ciphertext must have BOXZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_ciphertext` - Ciphertext to decrypt, with BOXZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce used for encryption
/// * `pk` - Sender's public key
/// * `sk` - Recipient's secret key
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message (with ZEROBYTES zero bytes at the beginning) or an error
pub fn open_nacl(
    padded_ciphertext: &[u8],
    nonce: &Nonce,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Result<Vec<u8>> {
    if padded_ciphertext.len() < BOXZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded ciphertext must be at least {BOXZEROBYTES} bytes"
        )));
    }

    // Verify that the first BOXZEROBYTES bytes of the ciphertext are all 0
    if padded_ciphertext
        .iter()
        .take(BOXZEROBYTES)
        .any(|&byte| byte != 0)
    {
        return Err(SodiumError::InvalidInput(format!(
            "first {BOXZEROBYTES} bytes of padded ciphertext must be zero"
        )));
    }

    let mut message = vec![0u8; padded_ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_open(
            message.as_mut_ptr(),
            padded_ciphertext.as_ptr(),
            padded_ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            pk.as_bytes().as_ptr(),
            sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

/// NaCl compatibility: Encrypt a message using XSalsa20-Poly1305 with zero padding and a precomputed key
///
/// This function is provided for compatibility with the NaCl API.
/// It requires the message to be padded with ZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_message` - Message to encrypt, with ZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce for encryption (must be NONCEBYTES bytes)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted message (with BOXZEROBYTES zero bytes at the beginning) or an error
pub fn seal_nacl_afternm(
    padded_message: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    if padded_message.len() < ZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded message must be at least {ZEROBYTES} bytes"
        )));
    }

    // Verify that the first ZEROBYTES bytes of the message are all 0
    if padded_message.iter().take(ZEROBYTES).any(|&byte| byte != 0) {
        return Err(SodiumError::InvalidInput(format!(
            "first {ZEROBYTES} bytes of padded message must be zero"
        )));
    }

    let mut ciphertext = vec![0u8; padded_message.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_afternm(
            ciphertext.as_mut_ptr(),
            padded_message.as_ptr(),
            padded_message.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("encryption failed".into()));
    }

    Ok(ciphertext)
}

/// NaCl compatibility: Decrypt a message using XSalsa20-Poly1305 with zero padding and a precomputed key
///
/// This function is provided for compatibility with the NaCl API.
/// The ciphertext must have BOXZEROBYTES zero bytes at the beginning.
///
/// # Arguments
/// * `padded_ciphertext` - Ciphertext to decrypt, with BOXZEROBYTES zero bytes at the beginning
/// * `nonce` - Nonce used for encryption (must be NONCEBYTES bytes)
/// * `precomputed_key` - Precomputed shared key from beforenm()
///
/// # Returns
/// * `Result<Vec<u8>>` - Decrypted message (with ZEROBYTES zero bytes at the beginning) or an error
pub fn open_nacl_afternm(
    padded_ciphertext: &[u8],
    nonce: &Nonce,
    precomputed_key: &PrecomputedKey,
) -> Result<Vec<u8>> {
    if padded_ciphertext.len() < BOXZEROBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "padded ciphertext must be at least {BOXZEROBYTES} bytes"
        )));
    }

    // Verify that the first BOXZEROBYTES bytes of the ciphertext are all 0
    if padded_ciphertext
        .iter()
        .take(BOXZEROBYTES)
        .any(|&byte| byte != 0)
    {
        return Err(SodiumError::InvalidInput(format!(
            "first {BOXZEROBYTES} bytes of padded ciphertext must be zero"
        )));
    }

    let mut message = vec![0u8; padded_ciphertext.len()];

    let result = unsafe {
        libsodium_sys::crypto_box_open_afternm(
            message.as_mut_ptr(),
            padded_ciphertext.as_ptr(),
            padded_ciphertext.len() as libc::c_ulonglong,
            nonce.as_ref().as_ptr(),
            precomputed_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("decryption failed".into()));
    }

    Ok(message)
}

// Export submodules

/// Original variant of crypto_box using XSalsa20-Poly1305
///
/// This submodule provides the same functionality as the parent module, but with
/// explicit naming to indicate the use of XSalsa20-Poly1305.
pub mod curve25519xsalsa20poly1305;

/// Extended variant of crypto_box using XChaCha20-Poly1305
///
/// This submodule provides the same functionality as the parent module, but uses
/// XChaCha20-Poly1305 instead of XSalsa20-Poly1305. The main advantage is the
/// extended nonce size (24 bytes), which makes it safer for random nonce generation.
pub mod curve25519xchacha20poly1305;

#[cfg(test)]
mod tests {
    use super::*;
    // Random is used in other test functions

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        let (pk, sk) = (keypair.public_key, keypair.secret_key);
        assert_eq!(pk.as_bytes().len(), PUBLICKEYBYTES);
        assert_eq!(sk.as_bytes().len(), SECRETKEYBYTES);
    }

    #[test]
    fn test_seed_keypair() {
        // Generate a random seed
        let mut seed = [0u8; SECRETKEYBYTES];
        crate::random::fill_bytes(&mut seed);

        // Use the from_seed method of KeyPair
        let keypair1 = KeyPair::from_seed(&seed).unwrap();
        let keypair2 = KeyPair::from_seed(&seed).unwrap();

        // Both keypairs should be identical
        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.secret_key, keypair2.secret_key);

        // Test with invalid seed length
        let invalid_seed = [0u8; SECRETKEYBYTES - 1];
        assert!(KeyPair::from_seed(&invalid_seed).is_err());
    }

    #[test]
    fn test_seal_open() {
        let alice_keypair = KeyPair::generate();
        let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let nonce = Nonce::generate();
        let message = b"Hello, world!";

        // Alice encrypts a message for Bob
        let ciphertext = seal(message, &nonce, &bob_pk, &alice_sk).unwrap();

        // Bob decrypts the message from Alice
        let decrypted = open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_beforenm_afternm() {
        let alice_keypair = KeyPair::generate();
        let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let nonce = Nonce::generate();
        let message = b"Hello, precomputed key!";

        // Alice precomputes a shared key with Bob
        let alice_precomputed = beforenm(&bob_pk, &alice_sk).unwrap();

        // Bob precomputes a shared key with Alice
        let bob_precomputed = beforenm(&alice_pk, &bob_sk).unwrap();

        // Alice encrypts a message for Bob using the precomputed key
        let ciphertext = seal_afternm(message, &nonce, &alice_precomputed).unwrap();

        // Bob decrypts the message from Alice using the precomputed key
        let decrypted = open_afternm(&ciphertext, &nonce, &bob_precomputed).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_seal_detached_open_detached() {
        let alice_keypair = KeyPair::generate();
        let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let nonce = Nonce::generate();
        let message = b"Hello, detached authentication!";

        // Alice encrypts a message for Bob with detached authentication
        let (ciphertext, mac) = seal_detached(message, &nonce, &bob_pk, &alice_sk).unwrap();

        // Bob decrypts the message from Alice with detached authentication
        let decrypted = open_detached(&ciphertext, &mac, &nonce, &alice_pk, &bob_sk).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_seal_detached_open_detached_afternm() {
        let alice_keypair = KeyPair::generate();
        let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let nonce = Nonce::generate();
        let message = b"Hello, detached authentication with precomputed key!";

        // Alice precomputes a shared key with Bob
        let alice_precomputed = beforenm(&bob_pk, &alice_sk).unwrap();

        // Bob precomputes a shared key with Alice
        let bob_precomputed = beforenm(&alice_pk, &bob_sk).unwrap();

        // Alice encrypts a message for Bob with detached authentication using precomputed key
        let (ciphertext, mac) = seal_detached_afternm(message, &nonce, &alice_precomputed).unwrap();

        // Bob decrypts the message from Alice with detached authentication using precomputed key
        let decrypted = open_detached_afternm(&ciphertext, &mac, &nonce, &bob_precomputed).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_seal_box_open_sealed_box() {
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let message = b"Hello, anonymous sender!";

        // Anonymous sender encrypts a message for Bob
        let sealed_box = seal_box(message, &bob_pk).unwrap();

        // Bob decrypts the message from the anonymous sender
        let decrypted = open_sealed_box(&sealed_box, &bob_pk, &bob_sk).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_nacl_compatibility() {
        let alice_keypair = KeyPair::generate();
        let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let nonce = Nonce::generate();

        // Create a message with ZEROBYTES zero bytes at the beginning
        let message = b"Hello, NaCl!";
        let mut padded_message = vec![0u8; ZEROBYTES + message.len()];
        padded_message[ZEROBYTES..].copy_from_slice(message);

        // Alice encrypts a message for Bob using NaCl compatibility mode
        let padded_ciphertext = seal_nacl(&padded_message, &nonce, &bob_pk, &alice_sk).unwrap();

        // Bob decrypts the message from Alice using NaCl compatibility mode
        let decrypted_padded = open_nacl(&padded_ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();

        assert_eq!(decrypted_padded, padded_message);
    }

    #[test]
    fn test_nacl_compatibility_afternm() {
        let alice_keypair = KeyPair::generate();
        let (alice_pk, alice_sk) = (alice_keypair.public_key, alice_keypair.secret_key);
        let bob_keypair = KeyPair::generate();
        let (bob_pk, bob_sk) = (bob_keypair.public_key, bob_keypair.secret_key);
        let nonce = Nonce::generate();

        // Create a message with ZEROBYTES zero bytes at the beginning
        let message = b"Hello, NaCl afternm!";
        let mut padded_message = vec![0u8; ZEROBYTES + message.len()];
        padded_message[ZEROBYTES..].copy_from_slice(message);

        // Alice precomputes a shared key with Bob
        let alice_precomputed = beforenm(&bob_pk, &alice_sk).unwrap();

        // Bob precomputes a shared key with Alice
        let bob_precomputed = beforenm(&alice_pk, &bob_sk).unwrap();

        // Alice encrypts a message for Bob using NaCl compatibility mode with precomputed key
        let padded_ciphertext =
            seal_nacl_afternm(&padded_message, &nonce, &alice_precomputed).unwrap();

        // Bob decrypts the message from Alice using NaCl compatibility mode with precomputed key
        let decrypted_padded =
            open_nacl_afternm(&padded_ciphertext, &nonce, &bob_precomputed).unwrap();

        assert_eq!(decrypted_padded, padded_message);
    }

    #[test]
    fn test_publickey_traits() {
        let keypair = KeyPair::generate();
        let pk = keypair.public_key;

        // Test From<[u8; N]> for PublicKey
        let bytes: [u8; PUBLICKEYBYTES] = pk.clone().into();
        let pk2 = PublicKey::from(bytes);
        assert_eq!(pk.as_bytes(), pk2.as_bytes());

        // Test From<PublicKey> for [u8; N]
        let extracted: [u8; PUBLICKEYBYTES] = pk.into();
        assert_eq!(extracted, bytes);
    }

    #[test]
    fn test_secretkey_traits() {
        let keypair = KeyPair::generate();
        let sk = keypair.secret_key;

        // Test From<[u8; N]> for SecretKey
        let bytes: [u8; SECRETKEYBYTES] = sk.clone().into();
        let sk2 = SecretKey::from(bytes);
        assert_eq!(sk.as_bytes(), sk2.as_bytes());

        // Test From<SecretKey> for [u8; N]
        let extracted: [u8; SECRETKEYBYTES] = sk.into();
        assert_eq!(extracted, bytes);
    }

    #[test]
    fn test_precomputedkey_traits() {
        let alice_keypair = KeyPair::generate();
        let bob_keypair = KeyPair::generate();

        let precomputed = beforenm(&bob_keypair.public_key, &alice_keypair.secret_key).unwrap();

        // Test TryFrom<&[u8]>
        let bytes = precomputed.as_bytes();
        let pk2 = PrecomputedKey::try_from(&bytes[..]).unwrap();
        assert_eq!(precomputed.as_bytes(), pk2.as_bytes());

        // Test invalid length
        let invalid_bytes = [0u8; BEFORENMBYTES - 1];
        assert!(PrecomputedKey::try_from(&invalid_bytes[..]).is_err());

        // Test From<[u8; N]>
        let bytes: [u8; BEFORENMBYTES] = precomputed.clone().into();
        let pk3 = PrecomputedKey::from(bytes);
        assert_eq!(precomputed.as_bytes(), pk3.as_bytes());

        // Test From<PrecomputedKey> for [u8; N]
        let extracted: [u8; BEFORENMBYTES] = precomputed.into();
        assert_eq!(extracted, bytes);

        // Test AsRef<[u8]>
        let precomputed2 = beforenm(&alice_keypair.public_key, &bob_keypair.secret_key).unwrap();
        let slice_ref: &[u8] = precomputed2.as_ref();
        assert_eq!(slice_ref.len(), BEFORENMBYTES);
    }
}
