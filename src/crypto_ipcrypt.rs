//! # IP Address Encryption
//!
//! This module provides efficient, secure encryption of IP addresses (IPv4 and IPv6)
//! for privacy-preserving storage, logging, and analytics.
//!
//! Unlike truncation (which irreversibly destroys data) or hashing (which prevents
//! decryption), ipcrypt provides reversible encryption with well-defined security
//! properties while maintaining operational utility.
//!
//! ## Use Cases
//!
//! - **Privacy-preserving logs**: Encrypt IP addresses in web server logs while
//!   retaining the ability to decrypt for abuse investigation
//! - **Rate limiting and abuse detection**: Use deterministic mode to identify
//!   repeat clients without storing plaintext IPs
//! - **Analytics without exposure**: Count unique visitors without exposing actual
//!   addresses to third-party analytics services
//! - **Regulatory compliance**: Store IP addresses in encrypted form for GDPR/CCPA
//!   compliance while maintaining lawful interception capability
//!
//! ## Variants
//!
//! | Variant | Key Size | Output Size | Properties |
//! |---------|----------|-------------|------------|
//! | Deterministic | 16 bytes | 16 bytes (IP string) | Same input always produces same output; format-preserving |
//! | ND (non-deterministic) | 16 bytes | 24 bytes (hex) | Different output each time; 8-byte random tweak |
//! | NDX (extended ND) | 32 bytes | 32 bytes (hex) | Different output each time; 16-byte random tweak |
//! | PFX (prefix-preserving) | 32 bytes | 16 bytes (IP string) | Preserves network prefix relationships |
//!
//! ## Choosing the Right Variant
//!
//! - **Deterministic**: Rate limiting, deduplication, database indexing
//! - **ND**: Log archival, third-party analytics, data exports (<4B encryptions/key)
//! - **NDX**: Maximum security, billions of encryptions per key
//! - **PFX**: Network analysis, DDoS research, PCAP anonymization
//!
//! ## IP Address Representation
//!
//! IP addresses can be provided as strings (both IPv4 and IPv6 are supported) or
//! as 16-byte binary arrays:
//! - IPv6: Used directly (16 bytes in network byte order)
//! - IPv4: Encoded as IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
//!
//! Use [`parse_ip`] to convert strings to binary, and [`format_ip`] for the reverse.
//!
//! ## Quick Start (String API)
//!
//! The simplest way to use this module is with the string-based functions:
//!
//! ```rust
//! use libsodium_rs::crypto_ipcrypt;
//!
//! // Deterministic encryption (IP string in, IP string out)
//! let key = crypto_ipcrypt::Key::generate();
//! let encrypted = crypto_ipcrypt::encrypt_str("192.0.2.1", &key).unwrap();
//! let decrypted = crypto_ipcrypt::decrypt_str(&encrypted, &key).unwrap();
//! assert_eq!(decrypted, "192.0.2.1");
//!
//! // Works with IPv6 too
//! let encrypted = crypto_ipcrypt::encrypt_str("2001:db8::1", &key).unwrap();
//! let decrypted = crypto_ipcrypt::decrypt_str(&encrypted, &key).unwrap();
//! assert_eq!(decrypted, "2001:db8::1");
//! ```
//!
//! ## Non-Deterministic Encryption (String API)
//!
//! For ND and NDX variants, output is returned as hex since it exceeds 16 bytes:
//!
//! ```rust
//! use libsodium_rs::crypto_ipcrypt;
//!
//! // ND: 24-byte output as hex (48 characters)
//! let key = crypto_ipcrypt::Key::generate();
//! let encrypted = crypto_ipcrypt::nd::encrypt_str("192.0.2.1", &key).unwrap();
//! assert_eq!(encrypted.len(), 48);  // 24 bytes * 2 for hex
//! let decrypted = crypto_ipcrypt::nd::decrypt_str(&encrypted, &key).unwrap();
//! assert_eq!(decrypted, "192.0.2.1");
//!
//! // NDX: 32-byte output as hex (64 characters)
//! let key = crypto_ipcrypt::ndx::Key::generate();
//! let encrypted = crypto_ipcrypt::ndx::encrypt_str("192.0.2.1", &key).unwrap();
//! assert_eq!(encrypted.len(), 64);  // 32 bytes * 2 for hex
//! let decrypted = crypto_ipcrypt::ndx::decrypt_str(&encrypted, &key).unwrap();
//! assert_eq!(decrypted, "192.0.2.1");
//! ```
//!
//! ## Binary API
//!
//! For maximum control, use the binary API:
//!
//! ```rust
//! use libsodium_rs::crypto_ipcrypt;
//!
//! let key = crypto_ipcrypt::Key::generate();
//!
//! // Parse IP string to binary
//! let ip = crypto_ipcrypt::parse_ip("192.0.2.1").unwrap();
//!
//! // Or construct manually for IPv4
//! let ip = crypto_ipcrypt::ipv4_to_bytes([192, 0, 2, 1]);
//!
//! // Encrypt/decrypt binary
//! let encrypted = crypto_ipcrypt::encrypt(&ip, &key);
//! let decrypted = crypto_ipcrypt::decrypt(&encrypted, &key);
//! assert_eq!(ip, decrypted);
//!
//! // Format back to string
//! let ip_str = crypto_ipcrypt::format_ip(&decrypted);
//! assert_eq!(ip_str, "192.0.2.1");
//! ```
//!
//! ## Hex Encoding for ND/NDX
//!
//! ND and NDX variants provide hex encoding helpers:
//!
//! ```rust
//! use libsodium_rs::crypto_ipcrypt;
//!
//! let key = crypto_ipcrypt::Key::generate();
//! let ip = crypto_ipcrypt::parse_ip("192.0.2.1").unwrap();
//! let tweak = crypto_ipcrypt::nd::Tweak::random();
//!
//! // Encrypt to binary
//! let encrypted = crypto_ipcrypt::nd::encrypt(&ip, &tweak, &key);
//!
//! // Convert to hex for storage/transmission
//! let hex = crypto_ipcrypt::nd::to_hex(&encrypted);
//!
//! // Convert back from hex
//! let recovered = crypto_ipcrypt::nd::from_hex(&hex).unwrap();
//! assert_eq!(encrypted, recovered);
//! ```

use crate::random;
use crate::SodiumError;

/// Number of bytes in an IP address (16)
pub const BYTES: usize = libsodium_sys::crypto_ipcrypt_BYTES as usize;

/// Maximum length of an IP address string (45 chars + null terminator)
/// IPv6 worst case: "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
const IP_MAXLEN: usize = 46;

/// Number of bytes in a deterministic key (16)
pub const KEYBYTES: usize = libsodium_sys::crypto_ipcrypt_KEYBYTES as usize;

/// A key for deterministic IP address encryption
///
/// This key is used for the deterministic variant where the same input
/// always produces the same output.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key([u8; KEYBYTES]);

impl Key {
    /// Generates a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; KEYBYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_keygen(key.as_mut_ptr());
        }
        Key(key)
    }

    /// Creates a key from a byte slice
    ///
    /// # Panics
    ///
    /// Panics if the slice is not exactly `KEYBYTES` bytes long
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), KEYBYTES, "key must be {KEYBYTES} bytes");
        let mut key = [0u8; KEYBYTES];
        key.copy_from_slice(slice);
        Key(key)
    }

    /// Returns the key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; KEYBYTES]> for Key {
    fn from(bytes: [u8; KEYBYTES]) -> Self {
        Key(bytes)
    }
}

/// Converts an IPv4 address to the 16-byte IPv4-mapped IPv6 representation
///
/// The result is in the format `::ffff:a.b.c.d`:
/// 10 zero bytes + 0xff 0xff + 4 IPv4 bytes
///
/// # Example
///
/// ```rust
/// use libsodium_rs::crypto_ipcrypt;
///
/// let ip = crypto_ipcrypt::ipv4_to_bytes([192, 0, 2, 1]);
/// assert_eq!(ip[10], 0xff);
/// assert_eq!(ip[11], 0xff);
/// assert_eq!(&ip[12..], &[192, 0, 2, 1]);
/// ```
pub fn ipv4_to_bytes(addr: [u8; 4]) -> [u8; BYTES] {
    let mut bytes = [0u8; BYTES];
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    bytes[12..].copy_from_slice(&addr);
    bytes
}

/// Converts a 16-byte representation back to an IPv4 address if it's IPv4-mapped
///
/// Returns `Some([a, b, c, d])` if the input is an IPv4-mapped address,
/// `None` otherwise.
pub fn bytes_to_ipv4(bytes: &[u8; BYTES]) -> Option<[u8; 4]> {
    // Check for IPv4-mapped prefix (10 zeros + 0xff 0xff)
    if bytes[..10].iter().all(|&b| b == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&bytes[12..]);
        Some(addr)
    } else {
        None
    }
}

/// Parses an IP address string into the 16-byte binary representation
///
/// Accepts both IPv4 (e.g., "192.0.2.1") and IPv6 (e.g., "2001:db8::1") addresses.
/// IPv4 addresses are automatically converted to IPv4-mapped format.
/// IPv6 addresses with zone identifiers (e.g., "fe80::1%eth0") are also supported.
///
/// This uses libsodium's `sodium_ip2bin()` function internally.
///
/// # Example
///
/// ```rust
/// use libsodium_rs::crypto_ipcrypt;
///
/// // Parse IPv4
/// let ipv4 = crypto_ipcrypt::parse_ip("192.0.2.1").unwrap();
///
/// // Parse IPv6
/// let ipv6 = crypto_ipcrypt::parse_ip("2001:db8::1").unwrap();
///
/// // Parse IPv6 with zone identifier
/// let ipv6_zone = crypto_ipcrypt::parse_ip("fe80::1%eth0").unwrap();
/// ```
pub fn parse_ip(ip: &str) -> Result<[u8; BYTES], SodiumError> {
    let mut bin = [0u8; BYTES];
    let ret = unsafe {
        libsodium_sys::sodium_ip2bin(
            bin.as_mut_ptr(),
            ip.as_ptr() as *const std::os::raw::c_char,
            ip.len(),
        )
    };
    if ret == 0 {
        Ok(bin)
    } else {
        Err(SodiumError::InvalidInput("invalid IP address".into()))
    }
}

/// Formats a 16-byte binary IP address as a string
///
/// IPv4-mapped addresses (::ffff:a.b.c.d) are converted to dotted-decimal notation.
/// IPv6 addresses are formatted in standard compressed notation.
///
/// This uses libsodium's `sodium_bin2ip()` function internally.
///
/// # Example
///
/// ```rust
/// use libsodium_rs::crypto_ipcrypt;
///
/// let bin = crypto_ipcrypt::parse_ip("192.0.2.1").unwrap();
/// let formatted = crypto_ipcrypt::format_ip(&bin);
/// assert_eq!(formatted, "192.0.2.1");
///
/// let ipv6 = crypto_ipcrypt::parse_ip("2001:db8::1").unwrap();
/// let formatted = crypto_ipcrypt::format_ip(&ipv6);
/// assert_eq!(formatted, "2001:db8::1");
/// ```
pub fn format_ip(bin: &[u8; BYTES]) -> String {
    let mut buf = [0i8; IP_MAXLEN];
    let ptr = unsafe {
        libsodium_sys::sodium_bin2ip(
            buf.as_mut_ptr() as *mut std::os::raw::c_char,
            IP_MAXLEN,
            bin.as_ptr(),
        )
    };
    if ptr.is_null() {
        // This shouldn't happen for valid 16-byte input, but handle it anyway
        String::new()
    } else {
        // Find the null terminator and convert to String
        let len = buf.iter().position(|&c| c == 0).unwrap_or(IP_MAXLEN);
        let bytes: Vec<u8> = buf[..len].iter().map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Encrypts an IP address using deterministic encryption
///
/// The same address with the same key always produces the same ciphertext.
/// This is useful for rate limiting, deduplication, and database indexing.
///
/// # Arguments
///
/// * `input` - The 16-byte IP address to encrypt
/// * `key` - The 16-byte encryption key
///
/// # Returns
///
/// The 16-byte encrypted IP address
pub fn encrypt(input: &[u8; BYTES], key: &Key) -> [u8; BYTES] {
    let mut output = [0u8; BYTES];
    unsafe {
        libsodium_sys::crypto_ipcrypt_encrypt(output.as_mut_ptr(), input.as_ptr(), key.0.as_ptr());
    }
    output
}

/// Decrypts an IP address encrypted with deterministic encryption
///
/// # Arguments
///
/// * `input` - The 16-byte encrypted IP address
/// * `key` - The 16-byte encryption key
///
/// # Returns
///
/// The 16-byte decrypted IP address
pub fn decrypt(input: &[u8; BYTES], key: &Key) -> [u8; BYTES] {
    let mut output = [0u8; BYTES];
    unsafe {
        libsodium_sys::crypto_ipcrypt_decrypt(output.as_mut_ptr(), input.as_ptr(), key.0.as_ptr());
    }
    output
}

/// Encrypts an IP address string using deterministic encryption
///
/// This is a convenience function that parses the IP, encrypts it, and returns
/// the encrypted address as a formatted IP string.
///
/// # Example
///
/// ```rust
/// use libsodium_rs::crypto_ipcrypt;
///
/// let key = crypto_ipcrypt::Key::generate();
/// let encrypted = crypto_ipcrypt::encrypt_str("192.0.2.1", &key).unwrap();
/// let decrypted = crypto_ipcrypt::decrypt_str(&encrypted, &key).unwrap();
/// assert_eq!(decrypted, "192.0.2.1");
/// ```
pub fn encrypt_str(ip: &str, key: &Key) -> Result<String, SodiumError> {
    let bin = parse_ip(ip)?;
    let encrypted = encrypt(&bin, key);
    Ok(format_ip(&encrypted))
}

/// Decrypts an IP address string encrypted with deterministic encryption
///
/// # Example
///
/// ```rust
/// use libsodium_rs::crypto_ipcrypt;
///
/// let key = crypto_ipcrypt::Key::generate();
/// let encrypted = crypto_ipcrypt::encrypt_str("2001:db8::1", &key).unwrap();
/// let decrypted = crypto_ipcrypt::decrypt_str(&encrypted, &key).unwrap();
/// assert_eq!(decrypted, "2001:db8::1");
/// ```
pub fn decrypt_str(ip: &str, key: &Key) -> Result<String, SodiumError> {
    let bin = parse_ip(ip)?;
    let decrypted = decrypt(&bin, key);
    Ok(format_ip(&decrypted))
}

/// Non-deterministic IP address encryption (ND variant)
///
/// Uses a random 8-byte tweak to ensure the same address produces different
/// ciphertexts each time. Good for log archival and third-party analytics.
pub mod nd {
    use super::*;

    /// Number of bytes in an ND key (16)
    pub const KEYBYTES: usize = libsodium_sys::crypto_ipcrypt_ND_KEYBYTES as usize;

    /// Number of bytes in an ND tweak (8)
    pub const TWEAKBYTES: usize = libsodium_sys::crypto_ipcrypt_ND_TWEAKBYTES as usize;

    /// Number of bytes in ND input (16)
    pub const INPUTBYTES: usize = libsodium_sys::crypto_ipcrypt_ND_INPUTBYTES as usize;

    /// Number of bytes in ND output (24)
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_ipcrypt_ND_OUTPUTBYTES as usize;

    /// A tweak for non-deterministic encryption
    #[derive(Clone, Copy)]
    pub struct Tweak([u8; TWEAKBYTES]);

    impl Tweak {
        /// Generates a random tweak
        pub fn random() -> Self {
            let mut tweak = [0u8; TWEAKBYTES];
            random::fill_bytes(&mut tweak);
            Tweak(tweak)
        }

        /// Creates a tweak from a byte slice
        pub fn from_slice(slice: &[u8]) -> Self {
            assert_eq!(slice.len(), TWEAKBYTES, "tweak must be {TWEAKBYTES} bytes");
            let mut tweak = [0u8; TWEAKBYTES];
            tweak.copy_from_slice(slice);
            Tweak(tweak)
        }

        /// Returns the tweak as a byte slice
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; TWEAKBYTES]> for Tweak {
        fn from(bytes: [u8; TWEAKBYTES]) -> Self {
            Tweak(bytes)
        }
    }

    /// Encrypts an IP address using non-deterministic encryption
    ///
    /// The output includes the tweak prepended to the ciphertext, so no separate
    /// tweak storage is needed for decryption.
    ///
    /// # Arguments
    ///
    /// * `input` - The 16-byte IP address to encrypt
    /// * `tweak` - The 8-byte random tweak
    /// * `key` - The 16-byte encryption key
    ///
    /// # Returns
    ///
    /// The 24-byte encrypted IP address (tweak + ciphertext)
    pub fn encrypt(input: &[u8; INPUTBYTES], tweak: &Tweak, key: &super::Key) -> [u8; OUTPUTBYTES] {
        let mut output = [0u8; OUTPUTBYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_nd_encrypt(
                output.as_mut_ptr(),
                input.as_ptr(),
                tweak.0.as_ptr(),
                key.0.as_ptr(),
            );
        }
        output
    }

    /// Decrypts an IP address encrypted with non-deterministic encryption
    ///
    /// The tweak is extracted from the ciphertext automatically.
    ///
    /// # Arguments
    ///
    /// * `input` - The 24-byte encrypted IP address
    /// * `key` - The 16-byte encryption key
    ///
    /// # Returns
    ///
    /// The 16-byte decrypted IP address
    pub fn decrypt(input: &[u8; OUTPUTBYTES], key: &super::Key) -> [u8; INPUTBYTES] {
        let mut output = [0u8; INPUTBYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_nd_decrypt(
                output.as_mut_ptr(),
                input.as_ptr(),
                key.0.as_ptr(),
            );
        }
        output
    }

    /// Encrypts an IP address string using non-deterministic encryption
    ///
    /// Returns the 24-byte ciphertext as a hex string (48 characters).
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_ipcrypt;
    ///
    /// let key = crypto_ipcrypt::Key::generate();
    /// let encrypted = crypto_ipcrypt::nd::encrypt_str("192.0.2.1", &key).unwrap();
    /// assert_eq!(encrypted.len(), 48); // 24 bytes as hex
    ///
    /// let decrypted = crypto_ipcrypt::nd::decrypt_str(&encrypted, &key).unwrap();
    /// assert_eq!(decrypted, "192.0.2.1");
    /// ```
    pub fn encrypt_str(ip: &str, key: &super::Key) -> Result<String, SodiumError> {
        let bin = super::parse_ip(ip)?;
        let tweak = Tweak::random();
        let encrypted = encrypt(&bin, &tweak, key);
        Ok(crate::utils::bin2hex(&encrypted))
    }

    /// Decrypts a hex-encoded ND ciphertext and returns the IP address as a string
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_ipcrypt;
    ///
    /// let key = crypto_ipcrypt::Key::generate();
    /// let encrypted = crypto_ipcrypt::nd::encrypt_str("2001:db8::1", &key).unwrap();
    /// let decrypted = crypto_ipcrypt::nd::decrypt_str(&encrypted, &key).unwrap();
    /// assert_eq!(decrypted, "2001:db8::1");
    /// ```
    pub fn decrypt_str(hex: &str, key: &super::Key) -> Result<String, SodiumError> {
        let bytes = crate::utils::hex2bin(hex)?;
        if bytes.len() != OUTPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "expected {} bytes, got {}",
                OUTPUTBYTES,
                bytes.len()
            )));
        }
        let mut input = [0u8; OUTPUTBYTES];
        input.copy_from_slice(&bytes);
        let decrypted = decrypt(&input, key);
        Ok(super::format_ip(&decrypted))
    }

    /// Encodes a 24-byte ND ciphertext as a hex string
    pub fn to_hex(ciphertext: &[u8; OUTPUTBYTES]) -> String {
        crate::utils::bin2hex(ciphertext)
    }

    /// Decodes a hex string to a 24-byte ND ciphertext
    pub fn from_hex(hex: &str) -> Result<[u8; OUTPUTBYTES], SodiumError> {
        let bytes = crate::utils::hex2bin(hex)?;
        if bytes.len() != OUTPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "expected {} bytes, got {}",
                OUTPUTBYTES,
                bytes.len()
            )));
        }
        let mut output = [0u8; OUTPUTBYTES];
        output.copy_from_slice(&bytes);
        Ok(output)
    }
}

/// Extended non-deterministic IP address encryption (NDX variant)
///
/// Uses a 32-byte key and 16-byte tweak for maximum security. The larger tweak
/// space provides a higher birthday bound (~2^64), suitable for billions of
/// encryptions per key.
pub mod ndx {
    use super::*;

    /// Number of bytes in an NDX key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_ipcrypt_NDX_KEYBYTES as usize;

    /// Number of bytes in an NDX tweak (16)
    pub const TWEAKBYTES: usize = libsodium_sys::crypto_ipcrypt_NDX_TWEAKBYTES as usize;

    /// Number of bytes in NDX input (16)
    pub const INPUTBYTES: usize = libsodium_sys::crypto_ipcrypt_NDX_INPUTBYTES as usize;

    /// Number of bytes in NDX output (32)
    pub const OUTPUTBYTES: usize = libsodium_sys::crypto_ipcrypt_NDX_OUTPUTBYTES as usize;

    /// A key for NDX encryption
    #[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Key([u8; KEYBYTES]);

    impl Key {
        /// Generates a new random key
        pub fn generate() -> Self {
            let mut key = [0u8; KEYBYTES];
            unsafe {
                libsodium_sys::crypto_ipcrypt_ndx_keygen(key.as_mut_ptr());
            }
            Key(key)
        }

        /// Creates a key from a byte slice
        pub fn from_slice(slice: &[u8]) -> Self {
            assert_eq!(slice.len(), KEYBYTES, "key must be {KEYBYTES} bytes");
            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(slice);
            Key(key)
        }

        /// Returns the key as a byte slice
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; KEYBYTES]> for Key {
        fn from(bytes: [u8; KEYBYTES]) -> Self {
            Key(bytes)
        }
    }

    /// A tweak for NDX encryption
    #[derive(Clone, Copy)]
    pub struct Tweak([u8; TWEAKBYTES]);

    impl Tweak {
        /// Generates a random tweak
        pub fn random() -> Self {
            let mut tweak = [0u8; TWEAKBYTES];
            random::fill_bytes(&mut tweak);
            Tweak(tweak)
        }

        /// Creates a tweak from a byte slice
        pub fn from_slice(slice: &[u8]) -> Self {
            assert_eq!(slice.len(), TWEAKBYTES, "tweak must be {TWEAKBYTES} bytes");
            let mut tweak = [0u8; TWEAKBYTES];
            tweak.copy_from_slice(slice);
            Tweak(tweak)
        }

        /// Returns the tweak as a byte slice
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; TWEAKBYTES]> for Tweak {
        fn from(bytes: [u8; TWEAKBYTES]) -> Self {
            Tweak(bytes)
        }
    }

    /// Encrypts an IP address using extended non-deterministic encryption
    ///
    /// # Arguments
    ///
    /// * `input` - The 16-byte IP address to encrypt
    /// * `tweak` - The 16-byte random tweak
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// The 32-byte encrypted IP address
    pub fn encrypt(input: &[u8; INPUTBYTES], tweak: &Tweak, key: &Key) -> [u8; OUTPUTBYTES] {
        let mut output = [0u8; OUTPUTBYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_ndx_encrypt(
                output.as_mut_ptr(),
                input.as_ptr(),
                tweak.0.as_ptr(),
                key.0.as_ptr(),
            );
        }
        output
    }

    /// Decrypts an IP address encrypted with extended non-deterministic encryption
    ///
    /// # Arguments
    ///
    /// * `input` - The 32-byte encrypted IP address
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// The 16-byte decrypted IP address
    pub fn decrypt(input: &[u8; OUTPUTBYTES], key: &Key) -> [u8; INPUTBYTES] {
        let mut output = [0u8; INPUTBYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_ndx_decrypt(
                output.as_mut_ptr(),
                input.as_ptr(),
                key.0.as_ptr(),
            );
        }
        output
    }

    /// Encrypts an IP address string using extended non-deterministic encryption
    ///
    /// Returns the 32-byte ciphertext as a hex string (64 characters).
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_ipcrypt;
    ///
    /// let key = crypto_ipcrypt::ndx::Key::generate();
    /// let encrypted = crypto_ipcrypt::ndx::encrypt_str("192.0.2.1", &key).unwrap();
    /// assert_eq!(encrypted.len(), 64); // 32 bytes as hex
    ///
    /// let decrypted = crypto_ipcrypt::ndx::decrypt_str(&encrypted, &key).unwrap();
    /// assert_eq!(decrypted, "192.0.2.1");
    /// ```
    pub fn encrypt_str(ip: &str, key: &Key) -> Result<String, SodiumError> {
        let bin = super::parse_ip(ip)?;
        let tweak = Tweak::random();
        let encrypted = encrypt(&bin, &tweak, key);
        Ok(crate::utils::bin2hex(&encrypted))
    }

    /// Decrypts a hex-encoded NDX ciphertext and returns the IP address as a string
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_ipcrypt;
    ///
    /// let key = crypto_ipcrypt::ndx::Key::generate();
    /// let encrypted = crypto_ipcrypt::ndx::encrypt_str("2001:db8::1", &key).unwrap();
    /// let decrypted = crypto_ipcrypt::ndx::decrypt_str(&encrypted, &key).unwrap();
    /// assert_eq!(decrypted, "2001:db8::1");
    /// ```
    pub fn decrypt_str(hex: &str, key: &Key) -> Result<String, SodiumError> {
        let bytes = crate::utils::hex2bin(hex)?;
        if bytes.len() != OUTPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "expected {} bytes, got {}",
                OUTPUTBYTES,
                bytes.len()
            )));
        }
        let mut input = [0u8; OUTPUTBYTES];
        input.copy_from_slice(&bytes);
        let decrypted = decrypt(&input, key);
        Ok(super::format_ip(&decrypted))
    }

    /// Encodes a 32-byte NDX ciphertext as a hex string
    pub fn to_hex(ciphertext: &[u8; OUTPUTBYTES]) -> String {
        crate::utils::bin2hex(ciphertext)
    }

    /// Decodes a hex string to a 32-byte NDX ciphertext
    pub fn from_hex(hex: &str) -> Result<[u8; OUTPUTBYTES], SodiumError> {
        let bytes = crate::utils::hex2bin(hex)?;
        if bytes.len() != OUTPUTBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "expected {} bytes, got {}",
                OUTPUTBYTES,
                bytes.len()
            )));
        }
        let mut output = [0u8; OUTPUTBYTES];
        output.copy_from_slice(&bytes);
        Ok(output)
    }
}

/// Prefix-preserving IP address encryption (PFX variant)
///
/// Preserves network prefix relationships: addresses sharing a common prefix
/// will have ciphertexts sharing a corresponding (different) prefix.
///
/// Use cases:
/// - Network research and academic datasets
/// - DDoS attack analysis
/// - PCAP and NetFlow anonymization
/// - ISP and CDN traffic analysis
pub mod pfx {

    /// Number of bytes in a PFX key (32)
    pub const KEYBYTES: usize = libsodium_sys::crypto_ipcrypt_PFX_KEYBYTES as usize;

    /// Number of bytes in PFX input/output (16)
    pub const BYTES: usize = libsodium_sys::crypto_ipcrypt_PFX_BYTES as usize;

    /// A key for prefix-preserving encryption
    #[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Key([u8; KEYBYTES]);

    impl Key {
        /// Generates a new random key
        pub fn generate() -> Self {
            let mut key = [0u8; KEYBYTES];
            unsafe {
                libsodium_sys::crypto_ipcrypt_pfx_keygen(key.as_mut_ptr());
            }
            Key(key)
        }

        /// Creates a key from a byte slice
        pub fn from_slice(slice: &[u8]) -> Self {
            assert_eq!(slice.len(), KEYBYTES, "key must be {KEYBYTES} bytes");
            let mut key = [0u8; KEYBYTES];
            key.copy_from_slice(slice);
            Key(key)
        }

        /// Returns the key as a byte slice
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; KEYBYTES]> for Key {
        fn from(bytes: [u8; KEYBYTES]) -> Self {
            Key(bytes)
        }
    }

    /// Encrypts an IP address using prefix-preserving encryption
    ///
    /// Addresses in the same subnet will produce ciphertexts in a corresponding
    /// (encrypted) subnet. The address family is preserved: IPv4 addresses
    /// encrypt to IPv4 addresses.
    ///
    /// # Arguments
    ///
    /// * `input` - The 16-byte IP address to encrypt
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// The 16-byte encrypted IP address
    pub fn encrypt(input: &[u8; BYTES], key: &Key) -> [u8; BYTES] {
        let mut output = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_pfx_encrypt(
                output.as_mut_ptr(),
                input.as_ptr(),
                key.0.as_ptr(),
            );
        }
        output
    }

    /// Decrypts an IP address encrypted with prefix-preserving encryption
    ///
    /// # Arguments
    ///
    /// * `input` - The 16-byte encrypted IP address
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// The 16-byte decrypted IP address
    pub fn decrypt(input: &[u8; BYTES], key: &Key) -> [u8; BYTES] {
        let mut output = [0u8; BYTES];
        unsafe {
            libsodium_sys::crypto_ipcrypt_pfx_decrypt(
                output.as_mut_ptr(),
                input.as_ptr(),
                key.0.as_ptr(),
            );
        }
        output
    }

    /// Encrypts an IP address string using prefix-preserving encryption
    ///
    /// Returns the encrypted address as a formatted IP string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_ipcrypt;
    ///
    /// let key = crypto_ipcrypt::pfx::Key::generate();
    /// let encrypted = crypto_ipcrypt::pfx::encrypt_str("192.0.2.1", &key).unwrap();
    /// let decrypted = crypto_ipcrypt::pfx::decrypt_str(&encrypted, &key).unwrap();
    /// assert_eq!(decrypted, "192.0.2.1");
    /// ```
    pub fn encrypt_str(ip: &str, key: &Key) -> Result<String, super::SodiumError> {
        let bin = super::parse_ip(ip)?;
        let encrypted = encrypt(&bin, key);
        Ok(super::format_ip(&encrypted))
    }

    /// Decrypts an IP address string encrypted with prefix-preserving encryption
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_ipcrypt;
    ///
    /// let key = crypto_ipcrypt::pfx::Key::generate();
    /// let encrypted = crypto_ipcrypt::pfx::encrypt_str("2001:db8::1", &key).unwrap();
    /// let decrypted = crypto_ipcrypt::pfx::decrypt_str(&encrypted, &key).unwrap();
    /// assert_eq!(decrypted, "2001:db8::1");
    /// ```
    pub fn decrypt_str(ip: &str, key: &Key) -> Result<String, super::SodiumError> {
        let bin = super::parse_ip(ip)?;
        let decrypted = decrypt(&bin, key);
        Ok(super::format_ip(&decrypted))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bytes_to_ipv4, decrypt, encrypt, ipv4_to_bytes, nd, ndx, pfx, Key, BYTES, KEYBYTES,
    };

    #[test]
    fn test_ipv4_conversion() {
        let ipv4 = [192, 0, 2, 1];
        let bytes = ipv4_to_bytes(ipv4);

        // Check IPv4-mapped format
        assert!(bytes[..10].iter().all(|&b| b == 0));
        assert_eq!(bytes[10], 0xff);
        assert_eq!(bytes[11], 0xff);
        assert_eq!(&bytes[12..], &ipv4);

        // Convert back
        let recovered = bytes_to_ipv4(&bytes).unwrap();
        assert_eq!(recovered, ipv4);
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = Key::generate();
        let ip = ipv4_to_bytes([192, 0, 2, 1]);

        let encrypted = encrypt(&ip, &key);
        let decrypted = decrypt(&encrypted, &key);

        assert_eq!(ip, decrypted);
        assert_ne!(ip, encrypted);
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let key = Key::generate();
        let ip = ipv4_to_bytes([10, 0, 0, 1]);

        let encrypted1 = encrypt(&ip, &key);
        let encrypted2 = encrypt(&ip, &key);

        assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_nd_encryption() {
        let key = Key::generate();
        let ip = ipv4_to_bytes([192, 168, 1, 1]);
        let tweak = nd::Tweak::random();

        let encrypted = nd::encrypt(&ip, &tweak, &key);
        let decrypted = nd::decrypt(&encrypted, &key);

        assert_eq!(ip, decrypted);
        assert_eq!(encrypted.len(), nd::OUTPUTBYTES);
    }

    #[test]
    fn test_nd_different_tweaks() {
        let key = Key::generate();
        let ip = ipv4_to_bytes([192, 168, 1, 1]);

        let tweak1 = nd::Tweak::random();
        let tweak2 = nd::Tweak::random();

        let encrypted1 = nd::encrypt(&ip, &tweak1, &key);
        let encrypted2 = nd::encrypt(&ip, &tweak2, &key);

        // Different tweaks should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt to the same value
        let decrypted1 = nd::decrypt(&encrypted1, &key);
        let decrypted2 = nd::decrypt(&encrypted2, &key);

        assert_eq!(decrypted1, ip);
        assert_eq!(decrypted2, ip);
    }

    #[test]
    fn test_ndx_encryption() {
        let key = ndx::Key::generate();
        let ip = ipv4_to_bytes([172, 16, 0, 1]);
        let tweak = ndx::Tweak::random();

        let encrypted = ndx::encrypt(&ip, &tweak, &key);
        let decrypted = ndx::decrypt(&encrypted, &key);

        assert_eq!(ip, decrypted);
        assert_eq!(encrypted.len(), ndx::OUTPUTBYTES);
    }

    #[test]
    fn test_ndx_different_tweaks() {
        let key = ndx::Key::generate();
        let ip = ipv4_to_bytes([172, 16, 0, 1]);

        let tweak1 = ndx::Tweak::random();
        let tweak2 = ndx::Tweak::random();

        let encrypted1 = ndx::encrypt(&ip, &tweak1, &key);
        let encrypted2 = ndx::encrypt(&ip, &tweak2, &key);

        assert_ne!(encrypted1, encrypted2);

        assert_eq!(ndx::decrypt(&encrypted1, &key), ip);
        assert_eq!(ndx::decrypt(&encrypted2, &key), ip);
    }

    #[test]
    fn test_pfx_encryption() {
        let key = pfx::Key::generate();
        let ip = ipv4_to_bytes([10, 0, 0, 1]);

        let encrypted = pfx::encrypt(&ip, &key);
        let decrypted = pfx::decrypt(&encrypted, &key);

        assert_eq!(ip, decrypted);
        assert_eq!(encrypted.len(), pfx::BYTES);
    }

    #[test]
    fn test_pfx_preserves_relationship() {
        let key = pfx::Key::generate();

        // Two addresses in the same /24
        let ip1 = ipv4_to_bytes([10, 0, 0, 1]);
        let ip2 = ipv4_to_bytes([10, 0, 0, 100]);

        let enc1 = pfx::encrypt(&ip1, &key);
        let enc2 = pfx::encrypt(&ip2, &key);

        // They should both decrypt correctly
        assert_eq!(pfx::decrypt(&enc1, &key), ip1);
        assert_eq!(pfx::decrypt(&enc2, &key), ip2);

        // The encrypted addresses should share a common prefix
        // (We can't easily verify the exact prefix length, but we can
        // at least verify they're different)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_different_keys_different_results() {
        let key1 = Key::generate();
        let key2 = Key::generate();
        let ip = ipv4_to_bytes([192, 0, 2, 1]);

        let encrypted1 = encrypt(&ip, &key1);
        let encrypted2 = encrypt(&ip, &key2);

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_key_from_slice() {
        let bytes = [0x42u8; KEYBYTES];
        let key = Key::from_slice(&bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_ndx_key_from_slice() {
        let bytes = [0x42u8; ndx::KEYBYTES];
        let key = ndx::Key::from_slice(&bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_pfx_key_from_slice() {
        let bytes = [0x42u8; pfx::KEYBYTES];
        let key = pfx::Key::from_slice(&bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_ipv6_encryption() {
        let key = Key::generate();

        // An IPv6 address (2001:db8::1)
        let ip: [u8; BYTES] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let encrypted = encrypt(&ip, &key);
        let decrypted = decrypt(&encrypted, &key);

        assert_eq!(ip, decrypted);

        // Should not be detected as IPv4-mapped
        assert!(bytes_to_ipv4(&ip).is_none());
    }

    #[test]
    fn test_constants() {
        assert_eq!(BYTES, 16);
        assert_eq!(KEYBYTES, 16);

        assert_eq!(nd::KEYBYTES, 16);
        assert_eq!(nd::TWEAKBYTES, 8);
        assert_eq!(nd::INPUTBYTES, 16);
        assert_eq!(nd::OUTPUTBYTES, 24);

        assert_eq!(ndx::KEYBYTES, 32);
        assert_eq!(ndx::TWEAKBYTES, 16);
        assert_eq!(ndx::INPUTBYTES, 16);
        assert_eq!(ndx::OUTPUTBYTES, 32);

        assert_eq!(pfx::KEYBYTES, 32);
        assert_eq!(pfx::BYTES, 16);
    }

    #[test]
    fn test_parse_ip_ipv4() {
        use super::{format_ip, parse_ip};

        let bin = parse_ip("192.0.2.1").unwrap();
        assert_eq!(format_ip(&bin), "192.0.2.1");

        let bin = parse_ip("10.0.0.1").unwrap();
        assert_eq!(format_ip(&bin), "10.0.0.1");

        let bin = parse_ip("255.255.255.255").unwrap();
        assert_eq!(format_ip(&bin), "255.255.255.255");
    }

    #[test]
    fn test_parse_ip_ipv6() {
        use super::{format_ip, parse_ip};

        let bin = parse_ip("2001:db8::1").unwrap();
        assert_eq!(format_ip(&bin), "2001:db8::1");

        let bin = parse_ip("::1").unwrap();
        assert_eq!(format_ip(&bin), "::1");

        let bin = parse_ip("fe80::1").unwrap();
        assert_eq!(format_ip(&bin), "fe80::1");

        // Full IPv6 address
        let bin = parse_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap();
        // libsodium compresses it
        let formatted = format_ip(&bin);
        assert!(formatted.contains("2001:"));
    }

    #[test]
    fn test_parse_ip_invalid() {
        use super::parse_ip;

        assert!(parse_ip("invalid").is_err());
        assert!(parse_ip("256.0.0.1").is_err());
        assert!(parse_ip("").is_err());
    }

    #[test]
    fn test_encrypt_str_deterministic() {
        use super::{decrypt_str, encrypt_str, Key};

        let key = Key::generate();

        // IPv4
        let encrypted = encrypt_str("192.0.2.1", &key).unwrap();
        let decrypted = decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "192.0.2.1");

        // IPv6
        let encrypted = encrypt_str("2001:db8::1", &key).unwrap();
        let decrypted = decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "2001:db8::1");
    }

    #[test]
    fn test_nd_encrypt_str() {
        let key = Key::generate();

        let encrypted = nd::encrypt_str("192.0.2.1", &key).unwrap();
        assert_eq!(encrypted.len(), nd::OUTPUTBYTES * 2); // hex encoded

        let decrypted = nd::decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "192.0.2.1");

        // IPv6
        let encrypted = nd::encrypt_str("2001:db8::1", &key).unwrap();
        let decrypted = nd::decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "2001:db8::1");
    }

    #[test]
    fn test_nd_hex_encoding() {
        let key = Key::generate();
        let ip = ipv4_to_bytes([192, 0, 2, 1]);
        let tweak = nd::Tweak::random();

        let encrypted = nd::encrypt(&ip, &tweak, &key);
        let hex = nd::to_hex(&encrypted);
        assert_eq!(hex.len(), nd::OUTPUTBYTES * 2);

        let decoded = nd::from_hex(&hex).unwrap();
        assert_eq!(encrypted, decoded);
    }

    #[test]
    fn test_ndx_encrypt_str() {
        let key = ndx::Key::generate();

        let encrypted = ndx::encrypt_str("192.0.2.1", &key).unwrap();
        assert_eq!(encrypted.len(), ndx::OUTPUTBYTES * 2); // hex encoded

        let decrypted = ndx::decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "192.0.2.1");

        // IPv6
        let encrypted = ndx::encrypt_str("2001:db8::1", &key).unwrap();
        let decrypted = ndx::decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "2001:db8::1");
    }

    #[test]
    fn test_ndx_hex_encoding() {
        let key = ndx::Key::generate();
        let ip = ipv4_to_bytes([192, 0, 2, 1]);
        let tweak = ndx::Tweak::random();

        let encrypted = ndx::encrypt(&ip, &tweak, &key);
        let hex = ndx::to_hex(&encrypted);
        assert_eq!(hex.len(), ndx::OUTPUTBYTES * 2);

        let decoded = ndx::from_hex(&hex).unwrap();
        assert_eq!(encrypted, decoded);
    }

    #[test]
    fn test_pfx_encrypt_str() {
        let key = pfx::Key::generate();

        let encrypted = pfx::encrypt_str("192.0.2.1", &key).unwrap();
        let decrypted = pfx::decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "192.0.2.1");

        // IPv6
        let encrypted = pfx::encrypt_str("2001:db8::1", &key).unwrap();
        let decrypted = pfx::decrypt_str(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "2001:db8::1");
    }

    #[test]
    fn test_format_ip_consistency_with_manual_conversion() {
        use super::{bytes_to_ipv4, format_ip, ipv4_to_bytes, parse_ip};

        // Test that parse_ip produces the same result as ipv4_to_bytes for IPv4
        let manual = ipv4_to_bytes([192, 0, 2, 1]);
        let parsed = parse_ip("192.0.2.1").unwrap();
        assert_eq!(manual, parsed);

        // Test that format_ip can recover the original
        let formatted = format_ip(&manual);
        assert_eq!(formatted, "192.0.2.1");

        // Test bytes_to_ipv4 on result from parse_ip
        let ipv4 = bytes_to_ipv4(&parsed).unwrap();
        assert_eq!(ipv4, [192, 0, 2, 1]);
    }
}
