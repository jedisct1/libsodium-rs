//! # Digital Signatures
//!
//! This module provides functions for creating and verifying digital signatures using
//! the Ed25519 signature scheme, which is based on the Edwards-curve Digital Signature
//! Algorithm (`EdDSA`) using the edwards25519 curve.
//!
//! ## Overview
//!
//! Digital signatures provide a way to verify the authenticity and integrity of messages or data.
//! They serve as the digital equivalent of handwritten signatures, but with stronger security
//! properties. When you sign a message with your secret key, anyone with your public key can
//! verify that:
//!
//! 1. The message was signed by someone who possesses the corresponding secret key
//! 2. The message has not been altered since it was signed
//!
//! The Ed25519 signature scheme is based on the Edwards-curve Digital Signature Algorithm (EdDSA)
//! using the edwards25519 curve with a SHA-512 hash function
//!
//! Ed25519 is a modern, high-security, high-performance signature algorithm that is resistant
//! to many types of attacks and side-channel leaks.
//!
//! ## Features
//!
//! - **Fast and secure signatures** with small keys and signatures
//! - **Public key size**: 32 bytes
//! - **Secret key size**: 64 bytes (includes the seed and the public key for optimization)
//! - **Signature size**: 64 bytes
//! - **Batch signature verification** for improved performance
//! - **Protection against side-channel attacks**
//! - **Deterministic signatures** (same message + same key = same signature)
//! - **Collision resistance** against hash function attacks
//! - **No random number generator needed** during signing (prevents RNG-related vulnerabilities)
//!
//! ## Use Cases
//!
//! - **Document signing**: Verify the authenticity of documents
//! - **Software distribution**: Ensure software packages haven't been tampered with
//! - **Secure messaging**: Authenticate the sender of messages
//! - **API authentication**: Verify API requests are coming from authorized clients
//! - **Blockchain transactions**: Sign transactions to prove ownership
//!
//! ## Basic Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_sign;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a key pair
//! let keypair = crypto_sign::KeyPair::generate().unwrap();
//! let public_key = keypair.public_key;
//! let secret_key = keypair.secret_key;
//!
//! // Message to sign
//! let message = b"Hello, world!";
//!
//! // Sign the message (combined mode)
//! let signed_message = crypto_sign::sign(message, &secret_key).unwrap();
//!
//! // Verify the signature and get the original message
//! let original_message = crypto_sign::verify(&signed_message, &public_key).unwrap();
//! assert_eq!(original_message, message);
//!
//! // Alternatively, use detached signatures
//! let signature = crypto_sign::sign_detached(message, &secret_key).unwrap();
//! assert!(crypto_sign::verify_detached(&signature, message, &public_key));
//! ```
//!
//! ## Combined vs. Detached Signatures
//!
//! This module supports two signature modes:
//!
//! 1. **Combined mode**: The signature is prepended to the message, creating a single byte array
//!    containing both. This is convenient when you want to transmit both together.
//!    - Use `sign()` to create combined signatures
//!    - Use `verify()` to verify combined signatures
//!
//! 2. **Detached mode**: The signature is separate from the message. This is useful when you
//!    want to keep the original message intact or transmit the signature separately.
//!    - Use `sign_detached()` to create detached signatures
//!    - Use `verify_detached()` to verify detached signatures
//!
//! ## Key Management
//!
//! Proper key management is crucial for the security of digital signatures. Here are some
//! best practices:
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_sign;
//! use sodium::ensure_init;
//! use std::fs;
//! use std::io::{self, Read, Write};
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate keys (typically done once)
//! fn generate_and_save_keys() -> io::Result<()> {
//!     let keypair = crypto_sign::KeyPair::generate().unwrap();
//!     let public_key = keypair.public_key;
//!     let secret_key = keypair.secret_key;
//!     
//!     // Save public key (can be shared)
//!     fs::write("public_key.bin", public_key.as_bytes())?;
//!     
//!     // Save secret key (must be kept secure)
//!     // In a real application, you would encrypt this or use a secure key storage solution
//!     fs::write("secret_key.bin", secret_key.as_bytes())?;
//!     
//!     Ok(())
//! }
//!
//! // Load keys for signing
//! fn load_secret_key() -> io::Result<crypto_sign::SecretKey> {
//!     let mut key_data = [0u8; crypto_sign::SECRETKEYBYTES];
//!     let mut file = fs::File::open("secret_key.bin")?;
//!     file.read_exact(&mut key_data)?;
//!     
//!     Ok(crypto_sign::SecretKey::from_bytes(&key_data).unwrap())
//! }
//!
//! // Load keys for verification
//! fn load_public_key() -> io::Result<crypto_sign::PublicKey> {
//!     let mut key_data = [0u8; crypto_sign::PUBLICKEYBYTES];
//!     let mut file = fs::File::open("public_key.bin")?;
//!     file.read_exact(&mut key_data)?;
//!     
//!     Ok(crypto_sign::PublicKey::from_bytes(&key_data).unwrap())
//! }
//!
//! // Sign a document
//! fn sign_document(document: &[u8]) -> io::Result<Vec<u8>> {
//!     let secret_key = load_secret_key()?;
//!     let signature = crypto_sign::sign_detached(document, &secret_key).unwrap();
//!     
//!     // Save or transmit both the document and signature
//!     let mut signed_data = Vec::new();
//!     signed_data.extend_from_slice(&signature);
//!     signed_data.extend_from_slice(document);
//!     
//!     Ok(signed_data)
//! }
//!
//! // Verify a signed document
//! fn verify_document(signed_data: &[u8]) -> io::Result<bool> {
//!     if signed_data.len() < crypto_sign::BYTES {
//!         return Ok(false);
//!     }
//!     
//!     let signature = <[u8; crypto_sign::BYTES]>::try_from(&signed_data[..crypto_sign::BYTES]).unwrap();
//!     let document = &signed_data[crypto_sign::BYTES..];
//!     
//!     let public_key = load_public_key()?;
//!     let result = crypto_sign::verify_detached(&signature, document, &public_key);
//!     
//!     Ok(result)
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - **Secret key protection**: The secret key should be kept confidential at all times. Consider using
//!   hardware security modules (HSMs) or secure enclaves for high-security applications.
//!
//!
//! - **Signature malleability**: Ed25519 signatures are not malleable, meaning an attacker cannot
//!   modify a valid signature to create another valid signature for the same message.
//!
//! - **Forward secrecy**: Digital signatures do not provide forward secrecy. If a secret key is
//!   compromised, all previous signatures created with that key can be attributed to the attacker.
//!
//! - **Deterministic**: Ed25519 is deterministic, meaning the same message signed with the same key
//!   will always produce the same signature. This eliminates the need for a random number generator
//!   during signing, which can be a source of vulnerabilities.
//!
//! - **Cofactor**: Ed25519 has a cofactor of 8, but the signature verification process ensures
//!   that signatures are secure despite this property.
//!
//! - **Quantum resistance**: Ed25519 is not resistant to quantum computing attacks. For long-term
//!   security against quantum computers, consider using post-quantum signature schemes.
//!
//! - **This implementation** uses constant-time operations to prevent timing attacks.

use crate::{Result, SodiumError};
use libc::c_ulonglong;
use std::convert::TryFrom;
use std::fmt;

/// Number of bytes in a public key (32)
///
/// The public key is used to verify signatures and can be shared publicly.
pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize;

/// Number of bytes in a secret key (64)
///
/// The secret key is used to create signatures and should be kept private.
/// Note that the secret key contains both the secret scalar and the public key.
pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_sign_SECRETKEYBYTES as usize;

/// Number of bytes in a signature (64)
///
/// Ed25519 signatures are 64 bytes long, consisting of an R value (32 bytes)
/// and an S value (32 bytes) concatenated together.
pub const BYTES: usize = libsodium_sys::crypto_sign_BYTES as usize;

/// Number of bytes in a seed (32)
///
/// The seed is used to deterministically generate a keypair.
pub const SEEDBYTES: usize = libsodium_sys::crypto_sign_SEEDBYTES as usize;

/// Maximum message length in bytes
///
/// This is the maximum length of a message that can be signed.
pub fn messagebytes_max() -> usize {
    unsafe { libsodium_sys::crypto_sign_messagebytes_max() }
}

/// Size of the state for multi-part signatures
pub const STATEBYTES: usize = std::mem::size_of::<libsodium_sys::crypto_sign_state>();

/// The primitive used by this module ("ed25519")
pub const PRIMITIVE: &str = "ed25519";

/// A public key for Ed25519 digital signatures
///
/// Used to verify signatures created with the corresponding `SecretKey`.
/// The public key is derived from the secret key and can be shared publicly.
///
/// ## Properties
///
/// - Size: 32 bytes (256 bits)
/// - Can be safely shared with anyone
/// - Used to verify the authenticity of signed messages
/// - Represents a point on the edwards25519 elliptic curve
///
/// ## Usage
///
/// Public keys are typically distributed to anyone who needs to verify signatures.
/// They can be safely shared over insecure channels and stored without special protection.
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
/// use std::convert::TryFrom;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a keypair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let public_key = keypair.public_key;
///
/// // Get the raw bytes of the public key (for storage or transmission)
/// let key_bytes = public_key.as_bytes();
///
/// // Later, reconstruct the public key from bytes
/// let reconstructed_key = crypto_sign::PublicKey::from_bytes(key_bytes).unwrap();
/// // Or using TryFrom with owned array
/// let reconstructed_key2 = crypto_sign::PublicKey::try_from(*key_bytes).unwrap();
///
/// assert_eq!(public_key, reconstructed_key);
/// assert_eq!(public_key, reconstructed_key2);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

/// A secret key for Ed25519 digital signatures
///
/// Used to create signatures that can be verified with the corresponding `PublicKey`.
/// The secret key must be kept private to maintain security.
///
/// ## Properties
///
/// - Size: 64 bytes (512 bits)
/// - Contains both the secret scalar (32 bytes) and the public key (32 bytes)
/// - Must be kept confidential
/// - Used to sign messages
///
/// ## Security Considerations
///
/// The secret key is the most sensitive component in the digital signature system.
/// If compromised, an attacker can create valid signatures for any message, impersonating
/// the legitimate owner of the key.
///
/// Best practices for secret key management:
///
/// - Store secret keys in secure, encrypted storage
/// - Consider using hardware security modules (HSMs) for high-security applications
/// - Implement proper access controls to limit who can use the signing key
/// - Rotate keys periodically according to your security policy
/// - Have a revocation plan in case a key is compromised
///
/// ## Usage
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key pair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let secret_key = keypair.secret_key;
///
/// // Sign a message
/// let message = b"Important document";
/// let signature = crypto_sign::sign_detached(message, &secret_key).unwrap();
///
/// // In a real application, you would securely store the secret key
/// // and implement proper key management procedures
/// ```
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

/// A key pair for digital signatures
///
/// Contains both a public key and a secret key for use with `crypto_sign` functions.
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
    /// * `bytes` - The bytes to create the public key from
    ///
    /// # Returns
    /// * `Result<Self>` - The public key or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `PUBLICKEYBYTES` bytes long
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLICKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "public key must be exactly {} bytes, got {}",
                PUBLICKEYBYTES,
                bytes.len()
            )));
        }

        let mut key = [0u8; PUBLICKEYBYTES];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Extract the public key from a secret key
    ///
    /// This function extracts the public key that is embedded in an Ed25519 secret key.
    /// In the Ed25519 implementation, the secret key (64 bytes) actually contains both
    /// the secret seed (32 bytes) and the public key (32 bytes) for optimization purposes.
    ///
    /// The public key is deterministically derived from the secret seed, but storing it
    /// as part of the secret key allows for faster signing operations by avoiding the
    /// need to recompute the public key for each signature.
    ///
    /// # Arguments
    /// * `secret_key` - The secret key to extract the public key from
    ///
    /// # Returns
    /// * `Result<PublicKey>` - The extracted public key or an error
    ///
    /// # Errors
    /// Returns an error if the extraction fails (extremely rare)
    ///
    /// # Security Considerations
    ///
    /// - This operation does not compromise the security of the secret key
    /// - The public key is safe to share publicly
    /// - The same public key will always be extracted from the same secret key
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_sign::{KeyPair, PublicKey};
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key pair
    /// let keypair = KeyPair::generate().unwrap();
    /// let secret_key = keypair.secret_key;
    ///
    /// // Extract the public key from the secret key
    /// let extracted_pk = PublicKey::from_secret_key(&secret_key).unwrap();
    ///
    /// // The extracted public key should match the original public key
    /// assert_eq!(extracted_pk, keypair.public_key);
    /// ```
    pub fn from_secret_key(secret_key: &SecretKey) -> Result<Self> {
        let mut pk = [0u8; PUBLICKEYBYTES];

        let result = unsafe {
            libsodium_sys::crypto_sign_ed25519_sk_to_pk(
                pk.as_mut_ptr(),
                secret_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "Failed to extract public key from secret key".into(),
            ));
        }

        Ok(PublicKey(pk))
    }

    /// Get the bytes of the public key
    ///
    /// # Returns
    /// * `&[u8; PUBLICKEYBYTES]` - A reference to the public key bytes
    pub fn as_bytes(&self) -> &[u8; PUBLICKEYBYTES] {
        &self.0
    }

    /// Create a public key from a fixed-size byte array
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly PUBLICKEYBYTES length
    ///
    /// # Returns
    /// * `Self` - A new public key
    pub const fn from_bytes_exact(bytes: [u8; PUBLICKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; PUBLICKEYBYTES]> for PublicKey {
    fn from(bytes: [u8; PUBLICKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; PUBLICKEYBYTES] {
    fn from(key: PublicKey) -> [u8; PUBLICKEYBYTES] {
        key.0
    }
}

impl SecretKey {
    /// Generate a new secret key from bytes
    ///
    /// # Arguments
    /// * `bytes` - The bytes to create the secret key from
    ///
    /// # Returns
    /// * `Result<Self>` - The secret key or an error if the input is invalid
    ///
    /// # Errors
    /// Returns an error if the input is not exactly `SECRETKEYBYTES` bytes long
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRETKEYBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "secret key must be exactly {} bytes, got {}",
                SECRETKEYBYTES,
                bytes.len()
            )));
        }

        let mut key = [0u8; SECRETKEYBYTES];
        key.copy_from_slice(bytes);
        Ok(SecretKey(key))
    }

    /// Get the bytes of the secret key
    ///
    /// # Returns
    /// * `&[u8; SECRETKEYBYTES]` - A reference to the secret key bytes
    pub fn as_bytes(&self) -> &[u8; SECRETKEYBYTES] {
        &self.0
    }

    /// Create a secret key from a fixed-size byte array
    ///
    /// # Arguments
    /// * `bytes` - Byte array of exactly SECRETKEYBYTES length
    ///
    /// # Returns
    /// * `Self` - A new secret key
    pub const fn from_bytes_exact(bytes: [u8; SECRETKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SECRETKEYBYTES]> for SecretKey {
    fn from(bytes: [u8; SECRETKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<SecretKey> for [u8; SECRETKEYBYTES] {
    fn from(key: SecretKey) -> [u8; SECRETKEYBYTES] {
        key.0
    }
}

impl KeyPair {
    /// Generate a new Ed25519 key pair for digital signatures
    ///
    /// This function generates a new random Ed25519 key pair suitable for creating and verifying
    /// digital signatures. The key pair consists of a public key that can be shared and a secret
    /// key that must be kept private.
    ///
    /// The key generation process uses a cryptographically secure random number generator to
    /// create a 32-byte seed, which is then used to deterministically derive both the secret
    /// and public keys according to the Ed25519 algorithm specification.
    ///
    /// ## Key Properties
    ///
    /// - **Public Key**: 32 bytes, can be safely shared with anyone
    /// - **Secret Key**: 64 bytes, contains both the seed (32 bytes) and public key (32 bytes)
    /// - **Security Level**: Equivalent to 128-bit symmetric encryption (highly secure)
    ///
    /// ## Security Considerations
    ///
    /// - The secret key must be kept confidential to maintain security
    /// - The public key can be freely distributed
    /// - Key generation is non-deterministic due to the use of a random seed
    /// - For deterministic key generation, use `KeyPair::from_seed` instead
    /// - The generated keys use the Ed25519 curve, which has strong security properties
    ///   including resistance to many side-channel attacks
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_sign;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a key pair
    /// let keypair = crypto_sign::KeyPair::generate().unwrap();
    /// let public_key = keypair.public_key;
    /// let secret_key = keypair.secret_key;
    ///
    /// // Use the keys for signing and verification
    /// let message = b"Hello, world!";
    /// let signature = crypto_sign::sign_detached(message, &secret_key).unwrap();
    /// assert!(crypto_sign::verify_detached(&signature, message, &public_key));
    ///
    /// // In a real application, you would securely store the secret key
    /// // and distribute the public key to verifiers
    /// ```
    ///
    /// # Returns
    /// * `Result<KeyPair>` - A newly generated key pair or an error
    ///
    /// # Errors
    /// Returns an error if key generation fails (extremely rare, typically only due to system issues)
    /// such as random number generator failure
    pub fn generate() -> Result<Self> {
        crate::ensure_init()?;

        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        unsafe {
            let ret = libsodium_sys::crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
            if ret != 0 {
                return Err(SodiumError::OperationError("key generation failed".into()));
            }
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Generate a new Ed25519 key pair from a seed.
    ///
    /// The seed must be exactly 32 bytes long.
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::{ensure_init, crypto_sign, random};
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a random seed
    /// let mut seed = [0u8; 32];
    /// random::fill_bytes(&mut seed);
    ///
    /// // Generate a keypair from the seed
    /// let keypair = crypto_sign::KeyPair::from_seed(&seed).unwrap();
    ///
    /// // The same seed will always produce the same keypair
    /// let keypair2 = crypto_sign::KeyPair::from_seed(&seed).unwrap();
    /// assert_eq!(keypair.public_key, keypair2.public_key);
    /// assert_eq!(keypair.secret_key, keypair2.secret_key);
    /// ```
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        crate::ensure_init()?;

        if seed.len() != SEEDBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid seed length: expected {}, got {}",
                SEEDBYTES,
                seed.len()
            )));
        }

        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        unsafe {
            let ret = libsodium_sys::crypto_sign_seed_keypair(
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
                seed.as_ptr(),
            );
            if ret != 0 {
                return Err(SodiumError::OperationError(
                    "Failed to generate keypair from seed".into(),
                ));
            }
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

/// Sign a message using a secret key (combined mode)
///
/// This function signs a message using the provided secret key and prepends the signature
/// to the message. The resulting signed message contains both the signature and the original
/// message concatenated together.
///
/// ## Combined Mode
///
/// This is known as "combined mode" because the signature and message are combined into
/// a single byte array. For detached signatures (where the signature is separate from the
/// message), use the `sign_detached` function instead.
///
/// ## Algorithm Details
///
/// Ed25519 signing works as follows:
/// 1. Compute a deterministic nonce from the secret key and message using SHA-512
/// 2. Compute point R = nonce * G (where G is the base point of the edwards25519 curve)
/// 3. Compute S = nonce + (hash(R || public_key || message) * secret_scalar)
/// 4. The signature is the concatenation of R and S
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key pair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let public_key = keypair.public_key;
/// let secret_key = keypair.secret_key;
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signed_message = crypto_sign::sign(message, &secret_key).unwrap();
///
/// // The signed message contains both the signature and the original message
/// assert_eq!(signed_message.len(), message.len() + crypto_sign::BYTES);
///
/// // Verify the signature and extract the original message
/// let original_message = crypto_sign::verify(&signed_message, &public_key).unwrap();
/// assert_eq!(original_message, message);
///
/// // Tamper with the signed message - verification should fail
/// let mut tampered = signed_message.clone();
/// tampered[0] ^= 1; // Flip a bit in the signature
/// assert!(crypto_sign::verify(&tampered, &public_key).is_none());
/// ```
///
/// # Arguments
/// * `message` - The message to sign
/// * `secret_key` - The secret key to sign with
///
/// # Returns
/// * `Result<Vec<u8>>` - The signed message (signature + original message) or an error
///
/// # Errors
/// Returns an error if signing fails (extremely rare, typically only due to system issues)
pub fn sign(message: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
    let mut signed_message = vec![0u8; message.len() + BYTES];
    let mut signed_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_sign(
            signed_message.as_mut_ptr(),
            &mut signed_len,
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            secret_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError("Ed25519 signing failed".into()));
    }

    signed_message.truncate(signed_len as usize);
    Ok(signed_message)
}

/// Verify a signed message using a public key (combined mode)
///
/// This function verifies a signed message using the provided public key and extracts
/// the original message if the signature is valid. The signed message must have been
/// created using the `sign` function.
///
/// ## Combined Mode
///
/// This function works with "combined mode" signatures, where the signature and message
/// are combined into a single byte array. For verifying detached signatures, use the
/// `verify_detached` function instead.
///
/// ## Algorithm Details
///
/// Ed25519 verification works as follows:
/// 1. Extract R and S from the signature
/// 2. Compute h = hash(R || public_key || message)
/// 3. Verify that R == S*G - h*public_key
///
/// ## Security Considerations
///
/// - The verification is performed in constant time to prevent timing attacks
/// - If verification fails, no part of the message is considered authentic
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key pair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let public_key = keypair.public_key;
/// let secret_key = keypair.secret_key;
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signed_message = crypto_sign::sign(message, &secret_key).unwrap();
///
/// // Verify the signature and extract the original message
/// let original_message = crypto_sign::verify(&signed_message, &public_key).unwrap();
/// assert_eq!(original_message, message);
///
/// // Tamper with the signed message - verification should fail
/// let mut tampered = signed_message.clone();
/// tampered[0] ^= 1; // Flip a bit in the signature
/// assert!(crypto_sign::verify(&tampered, &public_key).is_none());
/// ```
///
/// # Arguments
/// * `signed_message` - The signed message to verify
/// * `public_key` - The public key to verify with
///
/// # Returns
/// * `Option<Vec<u8>>` - The original message if verification succeeds, or `None` if verification fails
pub fn verify(signed_message: &[u8], public_key: &PublicKey) -> Option<Vec<u8>> {
    if signed_message.len() < BYTES {
        return None;
    }

    let mut message = vec![0u8; signed_message.len() - BYTES];
    let mut message_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_sign_open(
            message.as_mut_ptr(),
            &mut message_len,
            signed_message.as_ptr(),
            signed_message.len() as libc::c_ulonglong,
            public_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return None;
    }

    message.truncate(message_len as usize);
    Some(message)
}

/// Create a detached signature for a message
///
/// This function creates a signature for a message using the provided secret key, but
/// unlike `sign`, it returns only the signature, not the message with the signature.
/// This is useful when you want to transmit the signature separately from the message.
///
/// ## Detached Mode
///
/// This is known as "detached mode" because the signature is separate from the message.
/// For combined signatures (where the signature is prepended to the message), use the
/// `sign` function instead.
///
/// ## Signature Format
///
/// The signature is a 64-byte array containing:
/// - An R value (32 bytes): A point on the Edwards curve derived from a deterministic nonce
/// - An S value (32 bytes): A scalar value that proves knowledge of the secret key
///
/// ## Security Properties
///
/// - **Deterministic**: The same message signed with the same key always produces the same signature
/// - **Non-malleable**: Signatures cannot be modified to create new valid signatures
/// - **Forward secure**: Even if a signature is compromised, the secret key remains secure
/// - **Collision resistant**: Finding two different messages that produce the same signature is computationally infeasible
///
/// ## Use Cases
///
/// - **Document signing**: When you need to keep the original document intact
/// - **Large data**: When the data being signed is too large to duplicate in memory
/// - **Separate storage**: When you want to store or transmit signatures separately from the data
/// - **Signature databases**: When maintaining a database of signatures for verification
///
/// # Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key pair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let public_key = keypair.public_key;
/// let secret_key = keypair.secret_key;
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = crypto_sign::sign_detached(message, &secret_key).unwrap();
///
/// // Verify the signature
/// assert!(crypto_sign::verify_detached(&signature, message, &public_key));
///
/// // The signature can be stored or transmitted separately from the message
/// // For example, you might store it in a database or send it in a separate packet
/// let signature_hex = signature.iter().map(|b| format!("{:02x}", b)).collect::<String>();
/// println!("Signature: {}", signature_hex);
/// ```
///
/// # Arguments
/// * `message` - The message to sign
/// * `secret_key` - The secret key to sign with
///
/// # Returns
/// * `Result<[u8; BYTES]>` - The 64-byte signature or an error
///
/// # Errors
/// Returns an error if signing fails (extremely rare, typically only due to system issues)
///
/// # Performance Considerations
///
/// - Ed25519 signatures are designed to be fast to verify
/// - Signing is more computationally intensive than verification
/// - For large messages, the performance is dominated by the SHA-512 hashing of the message
pub fn sign_detached(message: &[u8], secret_key: &SecretKey) -> Result<[u8; BYTES]> {
    let mut signature = [0u8; BYTES];
    let mut signature_len = 0u64;

    let result = unsafe {
        libsodium_sys::crypto_sign_detached(
            signature.as_mut_ptr(),
            &mut signature_len,
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            secret_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "Ed25519 detached signing failed".into(),
        ));
    }

    Ok(signature)
}

/// Verify a detached signature
///
/// This function verifies a detached signature for a message using the provided public key.
/// The signature must have been created using the `sign_detached` function with the
/// corresponding secret key.
///
/// ## Detached Mode
///
/// This function works with "detached mode" signatures, where the signature is separate
/// from the message. For verifying combined signatures, use the `verify` function instead.
///
/// ## Security Considerations
///
/// - Verification is **constant-time** with respect to the public key and signature,
///   protecting against timing attacks
/// - The function will return false for any invalid input (wrong signature, wrong message,
///   or wrong public key)
/// - Ed25519 is resistant to many side-channel attacks
/// - Batch verification (verifying multiple signatures at once) can be more efficient
///   for high-throughput applications
///
/// ## Common Verification Scenarios
///
/// - **Document verification**: Ensuring a document hasn't been tampered with
/// - **Software updates**: Verifying the authenticity of software packages
/// - **API authentication**: Verifying that API requests come from authorized sources
/// - **Certificate validation**: Verifying certificate signatures in PKI systems
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a key pair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let public_key = keypair.public_key;
/// let secret_key = keypair.secret_key;
///
/// // Sign a message
/// let message = b"Hello, world!";
/// let signature = crypto_sign::sign_detached(message, &secret_key).unwrap();
///
/// // Verify the signature
/// let is_valid = crypto_sign::verify_detached(&signature, message, &public_key);
/// assert!(is_valid);
///
/// // Verification with a modified message should fail
/// let wrong_message = b"Modified message";
/// assert!(!crypto_sign::verify_detached(&signature, wrong_message, &public_key));
///
/// // Verification with a wrong public key should fail
/// let wrong_keypair = crypto_sign::KeyPair::generate().unwrap();
/// let wrong_public_key = wrong_keypair.public_key;
/// assert!(!crypto_sign::verify_detached(&signature, message, &wrong_public_key));
/// ```
///
/// # Arguments
/// * `signature` - The 64-byte signature to verify
/// * `message` - The message that was signed
/// * `public_key` - The public key to verify with
///
/// # Returns
/// * `bool` - `true` if the signature is valid, `false` otherwise
pub fn verify_detached(signature: &[u8; BYTES], message: &[u8], public_key: &PublicKey) -> bool {
    let result = unsafe {
        libsodium_sys::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            public_key.as_bytes().as_ptr(),
        )
    };

    result == 0
}

// Add implementation of Display for PublicKey and SecretKey for easier debugging
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show a prefix of the key for debugging, but not the entire key
        let bytes = self.as_bytes();
        write!(
            f,
            "PublicKey({:02x}{:02x}..{:02x}{:02x})",
            bytes[0],
            bytes[1],
            bytes[PUBLICKEYBYTES - 2],
            bytes[PUBLICKEYBYTES - 1]
        )
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For security reasons, don't show any part of the secret key
        // Even in debug output, it's better to be cautious
        write!(f, "SecretKey(*****)")
    }
}

// Add implementation of TryFrom for PublicKey and SecretKey for more idiomatic conversions
impl TryFrom<&[u8]> for PublicKey {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        PublicKey::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = SodiumError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        SecretKey::from_bytes(bytes)
    }
}

/// Generate a new Ed25519 key pair from a seed
///
/// This function deterministically generates an Ed25519 key pair from a seed. The same seed
/// will always produce the same key pair. This is useful for key derivation or when you need
/// reproducible keys.
///
/// ## Security Considerations
///
/// - The seed must be kept as secret as the secret key itself
/// - The seed should be high-entropy (ideally from a CSPRNG)
/// ```rust
/// use libsodium_rs::{ensure_init, crypto_sign};
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// ```
///
/// # Arguments
///
/// * `seed` - The seed to generate the key pair from
///
/// # Returns
///
/// * `Result<KeyPair>` - The generated key pair or an error
///
/// # Errors
///
/// Returns an error if key pair generation fails (extremely rare)
pub fn keypair_from_seed(seed: &[u8; SEEDBYTES]) -> Result<KeyPair> {
    let mut public_key = [0u8; PUBLICKEYBYTES];
    let mut secret_key = [0u8; SECRETKEYBYTES];

    let result = unsafe {
        libsodium_sys::crypto_sign_seed_keypair(
            public_key.as_mut_ptr(),
            secret_key.as_mut_ptr(),
            seed.as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "Ed25519 key pair generation failed".into(),
        ));
    }

    Ok(KeyPair {
        public_key: PublicKey::from_bytes(&public_key).unwrap(),
        secret_key: SecretKey::from_bytes(&secret_key).unwrap(),
    })
}

/// Extract the seed from a secret key
///
/// This function extracts the seed that was used to generate an Ed25519 secret key.
/// The seed is the first 32 bytes of the secret key.
///
/// ## Security Considerations
///
/// - The seed is as sensitive as the secret key itself and must be kept confidential
/// - This is mainly useful for key derivation or when you need to reconstruct keys
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::random;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate a random seed
/// let mut original_seed = [0u8; crypto_sign::SEEDBYTES];
/// random::fill_bytes(&mut original_seed);
///
/// // Generate a keypair from the seed
/// let keypair = crypto_sign::KeyPair::from_seed(&original_seed).unwrap();
/// let secret_key = keypair.secret_key;
///
/// // Extract the seed from the secret key
/// let extracted_seed = crypto_sign::secret_key_to_seed(&secret_key).unwrap();
///
/// // The extracted seed should match the original
/// assert_eq!(original_seed, extracted_seed);
/// ```
///
/// # Arguments
///
/// * `secret_key` - The secret key to extract the seed from
///
/// # Returns
///
/// * `Result<[u8; SEEDBYTES]>` - The extracted seed or an error
///
/// # Errors
///
/// Returns an error if the extraction fails (extremely rare)
pub fn secret_key_to_seed(secret_key: &SecretKey) -> Result<[u8; SEEDBYTES]> {
    let mut seed = [0u8; SEEDBYTES];

    let result = unsafe {
        libsodium_sys::crypto_sign_ed25519_sk_to_seed(
            seed.as_mut_ptr(),
            secret_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "Failed to extract seed from secret key".into(),
        ));
    }

    Ok(seed)
}

/// Convert an Ed25519 public key to a Curve25519 public key
///
/// This function converts an Ed25519 public key (used for signatures) to a Curve25519
/// public key (used for key exchange). This allows using the same key pair for both
/// signatures and key exchange.
///
/// ## Security Considerations
///
/// - Not all Ed25519 public keys can be converted to Curve25519 public keys
/// - This conversion is primarily useful when you want to use the same key pair for
///   both signatures and key exchange
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate an Ed25519 keypair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let ed25519_pk = keypair.public_key;
///
/// // Convert the Ed25519 public key to a Curve25519 public key
/// let curve25519_pk = crypto_sign::ed25519_pk_to_curve25519(&ed25519_pk).unwrap();
///
/// // The Curve25519 public key can now be used for key exchange
/// assert_eq!(curve25519_pk.len(), 32);
/// ```
///
/// # Arguments
///
/// * `ed25519_pk` - The Ed25519 public key to convert
///
/// # Returns
///
/// * `Result<[u8; 32]>` - The converted Curve25519 public key or an error
///
/// # Errors
///
/// Returns an error if the conversion fails (which can happen for some Ed25519 public keys)
pub fn ed25519_pk_to_curve25519(ed25519_pk: &PublicKey) -> Result<[u8; 32]> {
    let mut curve25519_pk = [0u8; 32];

    let result = unsafe {
        libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(
            curve25519_pk.as_mut_ptr(),
            ed25519_pk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "Failed to convert Ed25519 public key to Curve25519".into(),
        ));
    }

    Ok(curve25519_pk)
}

/// Convert an Ed25519 secret key to a Curve25519 secret key
///
/// This function converts an Ed25519 secret key (used for signatures) to a Curve25519
/// secret key (used for key exchange). This allows using the same key pair for both
/// signatures and key exchange.
///
/// ## Security Considerations
///
/// - The resulting Curve25519 secret key is as sensitive as the Ed25519 secret key
///   and must be kept confidential
/// - This conversion is primarily useful when you want to use the same key pair for
///   both signatures and key exchange
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
/// use sodium::ensure_init;
///
/// // Initialize libsodium
/// ensure_init().expect("Failed to initialize libsodium");
///
/// // Generate an Ed25519 keypair
/// let keypair = crypto_sign::KeyPair::generate().unwrap();
/// let ed25519_sk = keypair.secret_key;
///
/// // Convert the Ed25519 secret key to a Curve25519 secret key
/// let curve25519_sk = crypto_sign::ed25519_sk_to_curve25519(&ed25519_sk).unwrap();
///
/// // The Curve25519 secret key can now be used for key exchange
/// assert_eq!(curve25519_sk.len(), 32);
/// ```
///
/// # Arguments
///
/// * `ed25519_sk` - The Ed25519 secret key to convert
///
/// # Returns
///
/// * `Result<[u8; 32]>` - The converted Curve25519 secret key or an error
///
/// # Errors
///
/// Returns an error if the conversion fails (extremely rare)
pub fn ed25519_sk_to_curve25519(ed25519_sk: &SecretKey) -> Result<[u8; 32]> {
    let mut curve25519_sk = [0u8; 32];

    let result = unsafe {
        libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(
            curve25519_sk.as_mut_ptr(),
            ed25519_sk.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "Failed to convert Ed25519 secret key to Curve25519".into(),
        ));
    }

    Ok(curve25519_sk)
}

/// State for multi-part (streaming) signature creation and verification
///
/// This struct is used for creating or verifying signatures when the message is too large
/// to fit in memory at once, or when the message is being received in chunks.
#[derive(Debug, Clone)]
pub struct State {
    state: libsodium_sys::crypto_sign_state,
}

impl State {
    /// Create a new signature state
    ///
    /// This function initializes a new state for multi-part signature creation or verification.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_sign;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new signature state
    /// let state = crypto_sign::State::new().unwrap();
    /// ```
    ///
    /// # Returns
    /// * `Result<State>` - A new signature state or an error
    ///
    /// # Errors
    /// Returns an error if initialization fails (extremely rare)
    pub fn new() -> Result<Self> {
        let mut state = unsafe { std::mem::zeroed() };
        let result = unsafe { libsodium_sys::crypto_sign_init(&mut state) };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "Failed to initialize signature state".into(),
            ));
        }

        Ok(State { state })
    }

    /// Update the signature state with a message chunk
    ///
    /// This function updates the signature state with a chunk of the message to be signed
    /// or verified. It can be called multiple times to process a message in chunks.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_sign;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Create a new signature state
    /// let mut state = crypto_sign::State::new().unwrap();
    ///
    /// // Update the state with message chunks
    /// state.update(b"Hello, ").unwrap();
    /// state.update(b"world!").unwrap();
    /// ```
    ///
    /// # Arguments
    /// * `message_chunk` - A chunk of the message to update the state with
    ///
    /// # Returns
    /// * `Result<()>` - Success or an error
    ///
    /// # Errors
    /// Returns an error if the update fails (extremely rare)
    pub fn update(&mut self, message_chunk: &[u8]) -> Result<()> {
        let result = unsafe {
            libsodium_sys::crypto_sign_update(
                &mut self.state,
                message_chunk.as_ptr(),
                message_chunk.len() as c_ulonglong,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "Failed to update signature state".into(),
            ));
        }

        Ok(())
    }

    /// Finalize the signature creation process
    ///
    /// This function finalizes the signature creation process and returns the signature.
    /// It should be called after all message chunks have been processed with `update()`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_sign;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a keypair
    /// let keypair = crypto_sign::KeyPair::generate().unwrap();
    /// let secret_key = keypair.secret_key;
    ///
    /// // Create a multi-part signature
    /// let mut state = crypto_sign::State::new().unwrap();
    /// state.update(b"Hello, ").unwrap();
    /// state.update(b"world!").unwrap();
    ///
    /// // Finalize and get the signature
    /// let signature = state.finalize_create(&secret_key).unwrap();
    /// assert_eq!(signature.len(), crypto_sign::BYTES);
    /// ```
    ///
    /// # Arguments
    /// * `secret_key` - The secret key to sign with
    ///
    /// # Returns
    /// * `Result<[u8; BYTES]>` - The signature or an error
    ///
    /// # Errors
    /// Returns an error if finalization fails (extremely rare)
    pub fn finalize_create(&mut self, secret_key: &SecretKey) -> Result<[u8; BYTES]> {
        let mut sig = [0u8; BYTES];
        let mut sig_len: c_ulonglong = 0;

        let result = unsafe {
            libsodium_sys::crypto_sign_final_create(
                &mut self.state,
                sig.as_mut_ptr(),
                &mut sig_len,
                secret_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "Failed to finalize signature creation".into(),
            ));
        }

        Ok(sig)
    }

    /// Finalize the signature verification process
    ///
    /// This function finalizes the signature verification process. It should be called
    /// after all message chunks have been processed with `update()`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use sodium::crypto_sign;
    /// use sodium::ensure_init;
    ///
    /// // Initialize libsodium
    /// ensure_init().expect("Failed to initialize libsodium");
    ///
    /// // Generate a keypair
    /// let keypair = crypto_sign::KeyPair::generate().unwrap();
    /// let public_key = keypair.public_key;
    /// let secret_key = keypair.secret_key;
    ///
    /// // Create a multi-part signature
    /// let mut sign_state = crypto_sign::State::new().unwrap();
    /// sign_state.update(b"Hello, ").unwrap();
    /// sign_state.update(b"world!").unwrap();
    /// let signature = sign_state.finalize_create(&secret_key).unwrap();
    ///
    /// // Verify the signature
    /// let mut verify_state = crypto_sign::State::new().unwrap();
    /// verify_state.update(b"Hello, ").unwrap();
    /// verify_state.update(b"world!").unwrap();
    /// assert!(verify_state.finalize_verify(&signature, &public_key));
    /// ```
    ///
    /// # Arguments
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to verify with
    ///
    /// # Returns
    /// * `bool` - `true` if the signature is valid, `false` otherwise
    pub fn finalize_verify(&mut self, signature: &[u8; BYTES], public_key: &PublicKey) -> bool {
        let result = unsafe {
            libsodium_sys::crypto_sign_final_verify(
                &mut self.state,
                signature.as_ptr(),
                public_key.as_bytes().as_ptr(),
            )
        };

        result == 0
    }
}

/// Returns the name of the primitive used by this module
///
/// This function returns the string "ed25519", which is the name of the primitive
/// used by this module.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::crypto_sign;
///
/// assert_eq!(crypto_sign::primitive(), "ed25519");
/// ```
///
/// # Returns
/// * `&'static str` - The name of the primitive ("ed25519")
pub fn primitive() -> &'static str {
    PRIMITIVE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        // Generate a new keypair
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let sk = keypair.secret_key;

        // Verify the key sizes
        assert_eq!(pk.as_bytes().len(), PUBLICKEYBYTES);
        assert_eq!(sk.as_bytes().len(), SECRETKEYBYTES);
    }

    #[test]
    fn test_sign_verify() {
        // Generate a new keypair
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let sk = keypair.secret_key;
        let message = b"Hello, World!";

        // Sign the message
        let signed = sign(message, &sk).unwrap();

        // Verify the signature and extract the original message
        let verified = verify(&signed, &pk).unwrap();

        // The extracted message should match the original
        assert_eq!(message, &verified[..]);

        // Verify that the signed message is longer than the original
        assert!(signed.len() > message.len());
        assert_eq!(signed.len(), message.len() + BYTES);

        // Tamper with the signed message - verification should fail
        let mut tampered = signed.clone();
        tampered[0] ^= 1; // Flip a bit in the signature
        assert!(verify(&tampered, &pk).is_none());
    }

    #[test]
    fn test_verify_detached() {
        // Generate a keypair
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let sk = keypair.secret_key;

        // Sign a message
        let message = b"Test message";
        let signature = sign_detached(message, &sk).unwrap();

        // Verify the signature with the correct message
        assert!(verify_detached(&signature, message, &pk));

        // Verify with wrong message - should fail
        let wrong_message = b"Wrong message";
        assert!(!verify_detached(&signature, wrong_message, &pk));

        // Generate a new keypair and verify with wrong public key - should fail
        let wrong_keypair = KeyPair::generate().unwrap();
        let wrong_pk = wrong_keypair.public_key;
        assert!(!verify_detached(&signature, message, &wrong_pk));
    }

    #[test]
    fn test_seed_keypair() {
        // Generate a random seed
        let mut seed = [0u8; SEEDBYTES];
        crate::random::fill_bytes(&mut seed);

        // Generate two keypairs from the same seed
        let keypair1 = KeyPair::from_seed(&seed).unwrap();
        let pk1 = keypair1.public_key;
        let sk1 = keypair1.secret_key;

        // The same seed should produce the same keypair
        let keypair2 = KeyPair::from_seed(&seed).unwrap();
        let pk2 = keypair2.public_key;
        let sk2 = keypair2.secret_key;
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);

        // Invalid seed length should fail
        let invalid_seed = [0u8; SEEDBYTES - 1];
        assert!(KeyPair::from_seed(&invalid_seed).is_err());

        // Test deterministic key generation
        let seed = [0u8; SEEDBYTES];
        let keypair = KeyPair::from_seed(&seed).unwrap();
        let determ_pk = keypair.public_key;
        let determ_sk = keypair.secret_key;
        assert_ne!(determ_pk.0, [0u8; PUBLICKEYBYTES]);
        assert_ne!(determ_sk.0, [0u8; SECRETKEYBYTES]);
    }

    #[test]
    fn test_key_conversions() {
        // Generate a keypair
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let sk = keypair.secret_key;

        // Extract public key from secret key
        let extracted_pk = PublicKey::from_secret_key(&sk).unwrap();
        assert_eq!(pk, extracted_pk);

        // Test seed extraction (for deterministic keypairs)
        let seed = [0u8; SEEDBYTES];
        let keypair = KeyPair::from_seed(&seed).unwrap();
        let sk = keypair.secret_key;
        let extracted_seed = secret_key_to_seed(&sk).unwrap();
        assert_eq!(seed, extracted_seed);

        // Test conversion to Curve25519 keys
        let curve_pk = ed25519_pk_to_curve25519(&pk).unwrap();
        let curve_sk = ed25519_sk_to_curve25519(&sk).unwrap();

        assert_eq!(curve_pk.len(), 32);
        assert_eq!(curve_sk.len(), 32);
    }

    #[test]
    fn test_multipart_signing() {
        // Generate a keypair
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;
        let sk = keypair.secret_key;

        // Create a message in parts
        let part1 = b"Hello, ";
        let part2 = b"world!";

        // Sign using multi-part API
        let mut sign_state = State::new().unwrap();
        sign_state.update(part1).unwrap();
        sign_state.update(part2).unwrap();
        let signature = sign_state.finalize_create(&sk).unwrap();

        // Verify using multi-part API
        let mut verify_state = State::new().unwrap();
        verify_state.update(part1).unwrap();
        verify_state.update(part2).unwrap();
        assert!(verify_state.finalize_verify(&signature, &pk));

        // Test with different message - should fail
        let mut verify_state2 = State::new().unwrap();
        verify_state2.update(b"Different message").unwrap();
        assert!(!verify_state2.finalize_verify(&signature, &pk));

        // Test with wrong public key - should fail
        let wrong_keypair = KeyPair::generate().unwrap();
        let wrong_pk = wrong_keypair.public_key;
        let mut verify_state3 = State::new().unwrap();
        verify_state3.update(part1).unwrap();
        verify_state3.update(part2).unwrap();
        assert!(!verify_state3.finalize_verify(&signature, &wrong_pk));
    }

    #[test]
    fn test_publickey_traits() {
        let keypair = KeyPair::generate().unwrap();
        let pk = keypair.public_key;

        // Test AsRef<[u8]>
        let bytes_ref: &[u8] = pk.as_ref();
        assert_eq!(bytes_ref.len(), PUBLICKEYBYTES);
        assert_eq!(bytes_ref, pk.as_bytes());

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
        let keypair = KeyPair::generate().unwrap();
        let sk = keypair.secret_key;

        // Test AsRef<[u8]>
        let bytes_ref: &[u8] = sk.as_ref();
        assert_eq!(bytes_ref.len(), SECRETKEYBYTES);
        assert_eq!(bytes_ref, sk.as_bytes());

        // Test From<[u8; N]> for SecretKey
        let bytes: [u8; SECRETKEYBYTES] = sk.clone().into();
        let sk2 = SecretKey::from(bytes);
        assert_eq!(sk.as_bytes(), sk2.as_bytes());

        // Test From<SecretKey> for [u8; N]
        let extracted: [u8; SECRETKEYBYTES] = sk.into();
        assert_eq!(extracted, bytes);
    }
}
