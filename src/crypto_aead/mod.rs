//! # Authenticated Encryption with Associated Data (AEAD)
//!
//! This module provides Authenticated Encryption with Associated Data (AEAD) algorithms.
//! AEAD combines encryption and authentication to provide both confidentiality and integrity
//! for encrypted data. It also allows for additional authenticated data (AAD) that is not
//! encrypted but is still authenticated.
//!
//! ## What is AEAD?
//!
//! AEAD algorithms provide three critical security properties:
//!
//! 1. **Confidentiality**: The encrypted message cannot be read without the secret key
//! 2. **Integrity**: Any modification to the ciphertext will be detected during decryption
//! 3. **Authenticity**: The receiver can verify that the message was created by someone with the secret key
//!
//! Additionally, AEAD allows for **Additional Authenticated Data (AAD)** - information that is not
//! encrypted but is still authenticated. This is useful for including metadata, headers, or other
//! context that needs to be verified but doesn't need to be kept secret.
//!
//! ## Available AEAD Algorithms
//!
//! - **`xchacha20poly1305`**: XChaCha20-Poly1305-IETF - recommended for most use cases
//!   * Uses a 256-bit key and 192-bit nonce
//!   * Large nonce size makes random nonce generation safe
//!   * Excellent software performance on all platforms
//!   * Resistant to timing attacks
//!
//! - **`chacha20poly1305`**: ChaCha20-Poly1305-IETF
//!   * Uses a 256-bit key and 96-bit nonce
//!   * Standardized in RFC 8439
//!   * Good software performance
//!   * Requires careful nonce management (nonce reuse is catastrophic)
//!
//! - **`aes256gcm`**: AES-256-GCM
//!   * Uses a 256-bit key and 96-bit nonce
//!   * Hardware accelerated on modern CPUs with AES-NI
//!   * Standardized and widely used
//!   * Requires careful nonce management (nonce reuse is catastrophic)
//!
//! - **`aegis128l`**: AEGIS-128L
//!   * Uses a 128-bit key and 128-bit nonce
//!   * Extremely high performance
//!   * Winner of the CAESAR competition for high-performance applications
//!   * Currently being standardized by the IETF CFRG (draft-irtf-cfrg-aegis-aead)
//!   * Offers enhanced performance and a stronger security margin compared to other AEAD algorithms
//!
//! - **`aegis256`**: AEGIS-256
//!   * Uses a 256-bit key and 256-bit nonce
//!   * High-performance AEAD cipher with 256-bit security
//!   * Finalist in the CAESAR competition
//!   * Currently being standardized by the IETF CFRG (draft-irtf-cfrg-aegis-aead)
//!   * Allows for unlimited use of random nonces with no practical collision risk
//!
//! ## Algorithm Comparison and Selection Guide
//!
//! | Algorithm | Key Size | Nonce Size | Security Level | Performance | Hardware Acceleration | Standardization | Nonce Safety |
//! |-----------|----------|------------|----------------|------------|----------------------|-----------------|-------------|
//! | XChaCha20-Poly1305 | 256-bit | 192-bit | High | Good | No (SW optimized) | Widely used | Safe for random generation |
//! | ChaCha20-Poly1305 | 256-bit | 96-bit | High | Good | No (SW optimized) | RFC 8439 | Requires careful management |
//! | AES-256-GCM | 256-bit | 96-bit | High | Excellent* | Yes (AES-NI) | NIST SP 800-38D | Requires careful management |
//! | AEGIS-128L | 128-bit | 128-bit | Medium-High | Excellent* | Yes (AES-NI) | CAESAR finalist | Reasonably safe for random |
//! | AEGIS-256 | 256-bit | 256-bit | Very High | Very Good* | Yes (AES-NI) | CAESAR finalist | Safe for random generation |
//!
//! *Performance with hardware acceleration. Performance may be significantly lower without hardware support.
//!
//! ### Choosing the Right Algorithm
//!
//! - **For most applications**: Use `xchacha20poly1305`
//!   * Large nonce space makes it resistant to accidental nonce reuse
//!   * Good performance across all platforms without special hardware
//!   * Strong security properties and widely trusted
//!   * Simple to use correctly without complex nonce management
//!
//! - **For maximum performance on modern hardware**: Use `aes256gcm` or `aegis128l`
//!   * `aes256gcm`: If you need standardization and hardware acceleration
//!   * `aegis128l`: If you need absolute maximum performance and have AES-NI
//!   * Both require checking for hardware support at runtime
//!
//! - **For maximum security**: Use `aegis256` or `xchacha20poly1305`
//!   * `aegis256`: Highest security level with 256-bit key and 256-bit nonce
//!   * Better future-proofing against quantum computing threats
//!   * Consider post-quantum security margins for long-term data protection
//!
//! - **For standards compliance**: Use `chacha20poly1305` (RFC 8439) or `aes256gcm` (NIST)
//!   * Essential for interoperability with other systems
//!   * Well-analyzed and widely deployed in protocols like TLS
//!   * Requires careful nonce management (counter-based approach recommended)
//!
//! - **For embedded or resource-constrained environments**:
//!   * Without AES hardware: Use `chacha20poly1305` or `xchacha20poly1305`
//!   * With AES hardware: Consider `aes256gcm`
//!   * Optimize for memory usage and power consumption
//!
//! ### Performance Considerations
//!
//! Performance varies significantly based on hardware support:
//!
//! - **With AES-NI and CLMUL instructions** (most modern x86/x64 CPUs):
//!   * `aegis128l` > `aes256gcm` > `aegis256` > `chacha20poly1305` ≈ `xchacha20poly1305`
//!
//! - **Without hardware acceleration** (older CPUs, many ARM devices):
//!   * `chacha20poly1305` ≈ `xchacha20poly1305` > `aegis256` > `aegis128l` > `aes256gcm`
//!
//! ### Security Considerations
//!
//! - **Nonce reuse resistance**: All algorithms are catastrophically broken if a nonce is reused with the same key
//!   * `xchacha20poly1305` and `aegis256` have large enough nonce spaces that random generation is safe
//!   * `chacha20poly1305` and `aes256gcm` require careful nonce management (counter-based approach)
//!   * `aegis128l` has a reasonable nonce size but still requires care in high-volume applications
//!
//! - **Quantum resistance**: All these algorithms provide similar security against current threats
//!   * For long-term security, algorithms with 256-bit keys (`xchacha20poly1305`, `chacha20poly1305`, `aes256gcm`, `aegis256`)
//!     provide better protection against future quantum computing threats
//!
//! - **Implementation security**: Consider side-channel attack resistance
//!   * Software implementations of AES may be vulnerable to cache-timing attacks
//!   * ChaCha20 is designed to be constant-time in software
//!   * Hardware-accelerated implementations are generally more resistant to timing attacks
//!
//! ## Common Use Cases
//!
//! - **Secure communication**: Protecting messages in transit between parties
//! - **Secure storage**: Protecting sensitive data at rest
//! - **API authentication**: Securing API requests and responses
//! - **Secure cookies**: Protecting web session data
//! - **Secure file formats**: Adding authenticated encryption to file formats
//!
//! ## Security Considerations
//!
//! - **Never reuse a nonce with the same key**: This is the most critical rule. Nonce reuse
//!   can completely compromise security. For algorithms with smaller nonces (like `chacha20poly1305`
//!   and `aes256gcm`), use a counter or other deterministic method to ensure uniqueness.
//!
//! - **Nonce handling strategies**:
//!
//!   * **Counter-based**: Simple and reliable for a single encryptor
//!     - Maintain a strictly increasing counter for each encryption with the same key
//!     - Store the counter persistently to avoid reuse after restarts
//!     - Can be as simple as a 64-bit or 128-bit integer that increments for each message
//!     - For `chacha20poly1305` and `aes256gcm`, this is the recommended approach
//!     - Example: Store the counter in a database or file, increment it for each encryption
//!
//!   * **Random**: Safe only with large nonce spaces
//!     - Only use with algorithms that have large nonce spaces (`xchacha20poly1305` with 192-bit nonce or `aegis256` with 256-bit nonce)
//!     - Simplest approach but requires sufficient nonce size to avoid collisions
//!     - Probability of collision with 192-bit random nonce is negligible for practical purposes
//!     - Example: `let nonce = xchacha20poly1305::Nonce::generate();`
//!
//!   * **Timestamp-based**: Useful for some scenarios
//!     - Combine a high-resolution timestamp with a unique identifier
//!     - Ensures uniqueness if timestamps are strictly increasing
//!     - Must account for clock skew in distributed systems
//!     - Example: Combine a 64-bit timestamp with a 32-bit device ID and a 32-bit counter
//!
//!   * **Synchronized**: For distributed systems
//!     - Partition the nonce space among different encryptors
//!     - Each encryptor uses a different prefix and maintains its own counter
//!     - Requires coordination to avoid overlap
//!     - Example: First 32 bits for server ID, remaining bits for a local counter
//!
//!   * **Key rotation**: Complementary strategy
//!     - Periodically generate a new key and reset the nonce counter
//!     - Limits the number of messages encrypted with the same key
//!     - Provides forward secrecy if old keys are securely deleted
//!     - Example: Rotate keys daily or after every million messages
//!
//! - **The nonce can be public**: It doesn't need to be kept secret, but must never be reused with the same key
//!
//! - **Additional authenticated data (AAD)**: Not encrypted but is authenticated. The same AAD
//!   must be provided during decryption.
//!
//! - **Authentication verification**: If authentication fails during decryption, the entire message
//!   is rejected and no plaintext is returned. Treat this as a serious security breach.
//!
//! ## Practical Nonce Management Examples
//!
//! ### Example 1: Counter-Based Nonce for ChaCha20-Poly1305 (96-bit nonce)
//!
//! ```rust
//! use std::fs::{self, File};
//! use std::io::{Read, Write};
//! use std::path::Path;
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::chacha20poly1305;
//! use sodium::ensure_init;
//!
//! // File to store the counter
//! const COUNTER_FILE: &str = "chacha20poly1305_counter.bin";
//!
//! // Initialize a counter or load it from persistent storage
//! fn get_next_nonce(key_id: &str) -> chacha20poly1305::Nonce {
//!     ensure_init().expect("Failed to initialize libsodium");
//!     
//!     let counter_path = format!("{}.{}", key_id, COUNTER_FILE);
//!     let path = Path::new(&counter_path);
//!     
//!     // Load or initialize the counter
//!     let mut counter = if path.exists() {
//!         let mut file = File::open(path).expect("Failed to open counter file");
//!         let mut buf = [0u8; 12]; // 96-bit counter
//!         file.read_exact(&mut buf).expect("Failed to read counter");
//!         u96_from_bytes(&buf)
//!     } else {
//!         0u128 // Start from 0
//!     };
//!     
//!     // Increment the counter
//!     counter += 1;
//!     
//!     // Save the updated counter
//!     let counter_bytes = u96_to_bytes(counter);
//!     let mut file = File::create(path).expect("Failed to create counter file");
//!     file.write_all(&counter_bytes).expect("Failed to write counter");
//!     
//!     // Create a nonce from the counter
//!     chacha20poly1305::Nonce::try_from_slice(&counter_bytes).expect("Invalid nonce")
//! }
//!
//! // Helper functions for 96-bit integer conversion
//! fn u96_to_bytes(value: u128) -> [u8; 12] {
//!     let mut bytes = [0u8; 12];
//!     for i in 0..12 {
//!         bytes[11 - i] = ((value >> (i * 8)) & 0xFF) as u8;
//!     }
//!     bytes
//! }
//!
//! fn u96_from_bytes(bytes: &[u8; 12]) -> u128 {
//!     let mut value: u128 = 0;
//!     for i in 0..12 {
//!         value |= (bytes[11 - i] as u128) << (i * 8);
//!     }
//!     value
//! }
//! ```
//!
//! ### Example 2: Random Nonce for XChaCha20-Poly1305 (192-bit nonce)
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Simple function to get a random nonce
//! fn get_random_nonce() -> xchacha20poly1305::Nonce {
//!     ensure_init().expect("Failed to initialize libsodium");
//!     
//!     // Generate a random nonce - safe because XChaCha20-Poly1305 has a 192-bit nonce
//!     xchacha20poly1305::Nonce::generate()
//! }
//!
//! // Example usage in an encryption function
//! fn encrypt_message(message: &[u8], key: &xchacha20poly1305::Key) -> (Vec<u8>, xchacha20poly1305::Nonce) {
//!     let nonce = get_random_nonce();
//!     let ciphertext = xchacha20poly1305::encrypt(message, None, &nonce, key)
//!         .expect("Encryption failed");
//!     
//!     // Return both the ciphertext and the nonce
//!     // The nonce needs to be stored or transmitted alongside the ciphertext
//!     (ciphertext, nonce)
//! }
//! ```
//!
//! ### Example 3: Distributed System with Partitioned Nonce Space
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::xchacha20poly1305;
//! use sodium::ensure_init;
//! use std::sync::atomic::{AtomicU64, Ordering};
//!
//! struct DistributedEncryptor {
//!     server_id: u32,        // Unique ID for this server (0-65535)
//!     counter: AtomicU64,    // Local message counter
//!     key: xchacha20poly1305::Key,
//! }
//!
//! impl DistributedEncryptor {
//!     // Create a new encryptor with a specific server ID
//!     fn new(server_id: u32, key: xchacha20poly1305::Key) -> Self {
//!         ensure_init().expect("Failed to initialize libsodium");
//!         
//!         if server_id > 65535 {
//!             panic!("Server ID must be 0-65535");
//!         }
//!         
//!         Self {
//!             server_id,
//!             counter: AtomicU64::new(0),
//!             key,
//!         }
//!     }
//!     
//!     // Generate a unique nonce combining server ID and local counter
//!     fn next_nonce(&self) -> xchacha20poly1305::Nonce {
//!         // Increment the counter atomically
//!         let counter = self.counter.fetch_add(1, Ordering::SeqCst);
//!         
//!         // Create a nonce with server ID in first 2 bytes, counter in next 8 bytes,
//!         // and random data in remaining bytes
//!         let mut nonce_bytes = [0u8; xchacha20poly1305::NPUBBYTES];
//!         
//!         // First 2 bytes: server ID
//!         nonce_bytes[0] = (self.server_id >> 8) as u8;
//!         nonce_bytes[1] = (self.server_id & 0xFF) as u8;
//!         
//!         // Next 8 bytes: counter
//!         for i in 0..8 {
//!             nonce_bytes[2 + i] = ((counter >> (i * 8)) & 0xFF) as u8;
//!         }
//!         
//!         // Remaining bytes: random data
//!         sodium::random::fill_bytes(&mut nonce_bytes[10..]);
//!         
//!         xchacha20poly1305::Nonce::from_bytes(nonce_bytes)
//!     }
//!     
//!     // Encrypt a message
//!     fn encrypt(&self, message: &[u8], additional_data: Option<&[u8]>) -> (Vec<u8>, xchacha20poly1305::Nonce) {
//!         let nonce = self.next_nonce();
//!         let ciphertext = xchacha20poly1305::encrypt(
//!             message,
//!             additional_data,
//!             &nonce,
//!             &self.key,
//!         ).expect("Encryption failed");
//!         
//!         (ciphertext, nonce)
//!     }
//! }
//! ```
//!
//! - **Key management**: Protect your secret keys. Consider using key derivation functions (KDFs)
//!   to derive encryption keys from passwords or master keys.
//!
//! ## Example Usage
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::crypto_aead::xchacha20poly1305;
//! use sodium::ensure_init;
//!
//! // Initialize libsodium
//! ensure_init().expect("Failed to initialize libsodium");
//!
//! // Generate a random key
//! let key = xchacha20poly1305::Key::generate();
//!
//! // Create a nonce
//! let nonce = xchacha20poly1305::Nonce::generate();
//!
//! // Message to encrypt
//! let message = b"Hello, world!";
//!
//! // Additional authenticated data (not encrypted, but authenticated)
//! let additional_data = b"Important metadata";
//!
//! // Encrypt the message
//! let ciphertext = xchacha20poly1305::encrypt(
//!     message,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! // Decrypt the message
//! let decrypted = xchacha20poly1305::decrypt(
//!     &ciphertext,
//!     Some(additional_data),
//!     &nonce,
//!     &key,
//! ).unwrap();
//!
//! assert_eq!(message, &decrypted[..]);
//! ```

// Re-export submodules

// Re-export submodules
pub mod aegis128l;
pub mod aegis256;
pub mod aes256gcm;
pub mod chacha20poly1305;
pub mod chacha20poly1305_state;
pub mod xchacha20poly1305;
pub mod xchacha20poly1305_state;

// Re-export state modules
pub use aes256gcm::State as Aes256gcmState;
pub use chacha20poly1305_state::State as Chacha20poly1305State;
pub use xchacha20poly1305_state::State as Xchacha20poly1305State;

#[cfg(test)]
mod tests {
    use super::*;

    // Import state modules for testing
    use crate::crypto_aead::chacha20poly1305_state;
    use crate::crypto_aead::xchacha20poly1305_state;

    #[test]
    fn test_xchacha20poly1305() {
        let key = xchacha20poly1305::Key::generate();
        let nonce = xchacha20poly1305::Nonce::from_bytes([0u8; xchacha20poly1305::NPUBBYTES]);
        let message = b"Hello, World!";
        let ad = b"Additional data";

        // Test combined encryption/decryption
        let ciphertext = xchacha20poly1305::encrypt(message, Some(ad), &nonce, &key).unwrap();
        let decrypted = xchacha20poly1305::decrypt(&ciphertext, Some(ad), &nonce, &key).unwrap();
        assert_eq!(message, &decrypted[..]);

        // Test with wrong additional data
        let wrong_ad = b"Wrong data";
        assert!(xchacha20poly1305::decrypt(&ciphertext, Some(wrong_ad), &nonce, &key).is_err());

        // Test detached encryption/decryption
        let (detached_ciphertext, tag) =
            xchacha20poly1305::encrypt_detached(message, Some(ad), &nonce, &key).unwrap();
        let detached_decrypted =
            xchacha20poly1305::decrypt_detached(&detached_ciphertext, &tag, Some(ad), &nonce, &key)
                .unwrap();
        assert_eq!(message, &detached_decrypted[..]);

        // Test detached with wrong additional data
        assert!(xchacha20poly1305::decrypt_detached(
            &detached_ciphertext,
            &tag,
            Some(wrong_ad),
            &nonce,
            &key
        )
        .is_err());

        // Test detached with wrong tag
        let wrong_tag = vec![0u8; xchacha20poly1305::ABYTES];
        assert!(xchacha20poly1305::decrypt_detached(
            &detached_ciphertext,
            &wrong_tag,
            Some(ad),
            &nonce,
            &key
        )
        .is_err());

        // Test precomputation interface
        let state = xchacha20poly1305_state::State::from_key(&key).unwrap();
        let precomp_ciphertext =
            xchacha20poly1305_state::encrypt_afternm(message, Some(ad), &nonce, &state).unwrap();
        let precomp_decrypted =
            xchacha20poly1305_state::decrypt_afternm(&precomp_ciphertext, Some(ad), &nonce, &state)
                .unwrap();
        assert_eq!(message, &precomp_decrypted[..]);

        // Test precomputation interface with detached tag
        let (precomp_detached_ciphertext, precomp_tag) =
            xchacha20poly1305_state::encrypt_detached_afternm(message, Some(ad), &nonce, &state)
                .unwrap();
        let precomp_detached_decrypted = xchacha20poly1305_state::decrypt_detached_afternm(
            &precomp_detached_ciphertext,
            &precomp_tag,
            Some(ad),
            &nonce,
            &state,
        )
        .unwrap();
        assert_eq!(message, &precomp_detached_decrypted[..]);
        assert_eq!(message, &decrypted[..]);

        // The test is complete
    }

    #[test]
    fn test_aes256gcm() {
        use crate::crypto_aead::aes256gcm;

        if !aes256gcm::is_available() {
            println!("AES256-GCM not available on this CPU, skipping test");
            return;
        }

        // Create new variables with explicit types
        let aes_key = aes256gcm::Key::generate();
        let aes_nonce = aes256gcm::Nonce::from_bytes([0u8; aes256gcm::NPUBBYTES]);
        let message = b"Hello, World!";
        let ad = b"Additional data";

        let ciphertext = aes256gcm::encrypt(message, Some(ad), &aes_nonce, &aes_key).unwrap();
        let decrypted = aes256gcm::decrypt(&ciphertext, Some(ad), &aes_nonce, &aes_key).unwrap();
        assert_eq!(message, &decrypted[..]);

        // Test with wrong additional data
        let wrong_ad = b"Wrong data";
        assert!(aes256gcm::decrypt(&ciphertext, Some(wrong_ad), &aes_nonce, &aes_key).is_err());

        // Test precomputation interface
        let aes_state = aes256gcm::State::from_key(&aes_key).unwrap();
        let precomp_ciphertext =
            aes256gcm::encrypt_afternm(message, Some(ad), &aes_nonce, &aes_state).unwrap();
        let precomp_decrypted =
            aes256gcm::decrypt_afternm(&precomp_ciphertext, Some(ad), &aes_nonce, &aes_state)
                .unwrap();
        assert_eq!(message, &precomp_decrypted[..]);
    }

    #[test]
    fn test_aegis128l() {
        let key = aegis128l::Key::generate();
        let nonce = aegis128l::Nonce::from_bytes([0u8; aegis128l::NPUBBYTES]);
        let message = b"Hello, World!";
        let ad = b"Additional data";

        // Test combined encryption/decryption
        let ciphertext = aegis128l::encrypt(message, Some(ad), &nonce, &key).unwrap();
        let decrypted = aegis128l::decrypt(&ciphertext, Some(ad), &nonce, &key).unwrap();
        assert_eq!(message, &decrypted[..]);

        // Test with wrong additional data
        let wrong_ad = b"Wrong data";
        assert!(aegis128l::decrypt(&ciphertext, Some(wrong_ad), &nonce, &key).is_err());

        // Test detached encryption/decryption
        let (detached_ciphertext, tag) =
            aegis128l::encrypt_detached(message, Some(ad), &nonce, &key).unwrap();
        let detached_decrypted =
            aegis128l::decrypt_detached(&detached_ciphertext, &tag, Some(ad), &nonce, &key)
                .unwrap();
        assert_eq!(message, &detached_decrypted[..]);

        // Test detached with wrong additional data
        assert!(aegis128l::decrypt_detached(
            &detached_ciphertext,
            &tag,
            Some(wrong_ad),
            &nonce,
            &key
        )
        .is_err());

        // Test detached with wrong tag
        let wrong_tag = vec![0u8; aegis128l::ABYTES];
        assert!(aegis128l::decrypt_detached(
            &detached_ciphertext,
            &wrong_tag,
            Some(ad),
            &nonce,
            &key
        )
        .is_err());

        // Check that messagebytes_max returns a reasonable value
        assert!(aegis128l::messagebytes_max() > 0);
    }

    #[test]
    fn test_chacha20poly1305() {
        let key = chacha20poly1305::Key::generate();
        let nonce = chacha20poly1305::Nonce::from_bytes([0u8; chacha20poly1305::NPUBBYTES]);
        let message = b"Hello, World!";
        let ad = b"Additional data";

        // Test combined encryption/decryption
        let ciphertext = chacha20poly1305::encrypt(message, Some(ad), &nonce, &key).unwrap();
        let decrypted = chacha20poly1305::decrypt(&ciphertext, Some(ad), &nonce, &key).unwrap();
        assert_eq!(message, &decrypted[..]);

        // Test with wrong additional data
        let wrong_ad = b"Wrong data";
        assert!(chacha20poly1305::decrypt(&ciphertext, Some(wrong_ad), &nonce, &key).is_err());

        // Test detached encryption/decryption
        let (detached_ciphertext, tag) =
            chacha20poly1305::encrypt_detached(message, Some(ad), &nonce, &key).unwrap();
        let detached_decrypted =
            chacha20poly1305::decrypt_detached(&detached_ciphertext, &tag, Some(ad), &nonce, &key)
                .unwrap();
        assert_eq!(message, &detached_decrypted[..]);

        // Test detached with wrong additional data
        assert!(chacha20poly1305::decrypt_detached(
            &detached_ciphertext,
            &tag,
            Some(wrong_ad),
            &nonce,
            &key
        )
        .is_err());

        // Test detached with wrong tag
        let wrong_tag = vec![0u8; chacha20poly1305::ABYTES];
        assert!(chacha20poly1305::decrypt_detached(
            &detached_ciphertext,
            &wrong_tag,
            Some(ad),
            &nonce,
            &key
        )
        .is_err());

        // Test precomputation interface
        let state = chacha20poly1305_state::State::from_key(&key).unwrap();
        let precomp_ciphertext =
            chacha20poly1305_state::encrypt_afternm(message, Some(ad), &nonce, &state).unwrap();
        let precomp_decrypted =
            chacha20poly1305_state::decrypt_afternm(&precomp_ciphertext, Some(ad), &nonce, &state)
                .unwrap();
        assert_eq!(message, &precomp_decrypted[..]);

        // Test precomputation interface with detached tag
        let (precomp_detached_ciphertext, precomp_tag) =
            chacha20poly1305_state::encrypt_detached_afternm(message, Some(ad), &nonce, &state)
                .unwrap();
        let precomp_detached_decrypted = chacha20poly1305_state::decrypt_detached_afternm(
            &precomp_detached_ciphertext,
            &precomp_tag,
            Some(ad),
            &nonce,
            &state,
        )
        .unwrap();
        assert_eq!(message, &precomp_detached_decrypted[..]);
    }

    #[test]
    fn test_aegis256() {
        let key = aegis256::Key::generate();
        let nonce = aegis256::Nonce::from_bytes([0u8; aegis256::NPUBBYTES]);
        let message = b"Hello, World!";
        let ad = b"Additional data";

        // Test combined encryption/decryption
        let ciphertext = aegis256::encrypt(message, Some(ad), &nonce, &key).unwrap();
        let decrypted = aegis256::decrypt(&ciphertext, Some(ad), &nonce, &key).unwrap();
        assert_eq!(message, &decrypted[..]);

        // Test with wrong additional data
        let wrong_ad = b"Wrong data";
        assert!(aegis256::decrypt(&ciphertext, Some(wrong_ad), &nonce, &key).is_err());

        // Test detached encryption/decryption
        let (detached_ciphertext, tag) =
            aegis256::encrypt_detached(message, Some(ad), &nonce, &key).unwrap();
        let detached_decrypted =
            aegis256::decrypt_detached(&detached_ciphertext, &tag, Some(ad), &nonce, &key).unwrap();
        assert_eq!(message, &detached_decrypted[..]);

        // Test detached with wrong additional data
        assert!(aegis256::decrypt_detached(
            &detached_ciphertext,
            &tag,
            Some(wrong_ad),
            &nonce,
            &key
        )
        .is_err());

        // Test detached with wrong tag
        let wrong_tag = vec![0u8; aegis256::ABYTES];
        assert!(aegis256::decrypt_detached(
            &detached_ciphertext,
            &wrong_tag,
            Some(ad),
            &nonce,
            &key
        )
        .is_err());

        // Check that messagebytes_max returns a reasonable value
        assert!(aegis256::messagebytes_max() > 0);
    }
}
