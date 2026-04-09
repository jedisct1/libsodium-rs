//! # Extendable Output Functions (XOFs)
//!
//! This module provides extendable output functions (XOFs) based on the Keccak permutation.
//! Unlike regular hash functions with fixed-size output, XOFs can produce output of arbitrary
//! length from the same input.
//!
//! ## Available XOFs
//!
//! - **SHAKE128/SHAKE256**: NIST-standardized XOFs from FIPS 202, based on Keccak with 24 rounds
//! - **TurboSHAKE128/TurboSHAKE256**: Faster variants using 12 rounds, standardized in RFC 9861
//!
//! ## When to Use Each Variant
//!
//! **TurboSHAKE128** is recommended for most applications:
//! - ~2x faster than SHAKE
//! - 128-bit security (sufficient for virtually all use cases)
//! - Built-in domain separation support
//!
//! Use SHAKE variants only when NIST FIPS 202 compliance is required.
//!
//! ## Use Cases
//!
//! - **Key derivation**: Derive multiple keys from a single seed
//! - **Deterministic random generation**: Expand a seed into arbitrary-length output
//! - **Hash functions**: Use as a hash with any output size
//! - **Domain-separated hashing**: Use custom domain separators for independent functions
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs::crypto_xof::turboshake128;
//!
//! // One-shot hashing
//! let message = b"Arbitrary data to hash";
//! let hash = turboshake128::hash(message, 32).unwrap();
//!
//! // Multi-part hashing with incremental squeezing
//! let mut state = turboshake128::State::new().unwrap();
//! state.update(b"part 1").unwrap();
//! state.update(b"part 2").unwrap();
//!
//! // Squeeze multiple outputs
//! let key1 = state.squeeze(32).unwrap();
//! let key2 = state.squeeze(32).unwrap();
//! ```

use crate::{Result, SodiumError};

/// SHAKE128 XOF (128-bit security, 24 rounds)
///
/// SHAKE128 is a NIST-standardized XOF from FIPS 202. It provides 128-bit security
/// and uses 24 rounds of the Keccak permutation.
///
/// For most applications, prefer `turboshake128` which is faster while maintaining
/// the same security level.
pub mod shake128 {
    use super::*;

    /// Block size in bytes (168)
    pub const BLOCKBYTES: usize = libsodium_sys::crypto_xof_shake128_BLOCKBYTES as usize;

    /// State size in bytes (256)
    pub const STATEBYTES: usize = libsodium_sys::crypto_xof_shake128_STATEBYTES as usize;

    /// Standard domain separator (0x1F)
    pub const DOMAIN_STANDARD: u8 = libsodium_sys::crypto_xof_shake128_DOMAIN_STANDARD as u8;

    /// Returns the block size in bytes
    pub fn blockbytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_shake128_blockbytes() }
    }

    /// Returns the state size in bytes
    pub fn statebytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_shake128_statebytes() }
    }

    /// Returns the standard domain separator
    pub fn domain_standard() -> u8 {
        unsafe { libsodium_sys::crypto_xof_shake128_domain_standard() }
    }

    /// Computes the SHAKE128 XOF of the input in one shot
    ///
    /// # Arguments
    ///
    /// * `input` - The input data to hash
    /// * `output_len` - The desired output length in bytes
    ///
    /// # Returns
    ///
    /// The XOF output of the specified length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_xof::shake128;
    ///
    /// let message = b"Hello, World!";
    /// let hash = shake128::hash(message, 32).unwrap();
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn hash(input: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_len];
        let result = unsafe {
            libsodium_sys::crypto_xof_shake128(
                output.as_mut_ptr(),
                output_len,
                input.as_ptr(),
                input.len() as u64,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError("SHAKE128 hash failed".into()));
        }

        Ok(output)
    }

    /// State for incremental SHAKE128 hashing
    ///
    /// Allows absorbing data in chunks and squeezing output incrementally.
    /// Once squeezing begins, no more data can be absorbed.
    pub struct State {
        state: libsodium_sys::crypto_xof_shake128_state,
        squeezed: bool,
    }

    impl State {
        /// Creates a new SHAKE128 state with the standard domain separator
        pub fn new() -> Result<Self> {
            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe { libsodium_sys::crypto_xof_shake128_init(&mut state.state) };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE128 state initialization failed".into(),
                ));
            }

            Ok(state)
        }

        /// Creates a new SHAKE128 state with a custom domain separator
        ///
        /// Domain separators allow creating independent hash functions from the same primitive.
        /// The domain must be between 0x01 and 0x7F.
        ///
        /// # Arguments
        ///
        /// * `domain` - The domain separator (must be between 0x01 and 0x7F)
        pub fn new_with_domain(domain: u8) -> Result<Self> {
            if domain == 0 || domain > 0x7F {
                return Err(SodiumError::InvalidInput(
                    "domain must be between 0x01 and 0x7F".into(),
                ));
            }

            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe {
                libsodium_sys::crypto_xof_shake128_init_with_domain(&mut state.state, domain)
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE128 state initialization with domain failed".into(),
                ));
            }

            Ok(state)
        }

        /// Absorbs data into the state
        ///
        /// Can be called multiple times before squeezing.
        /// Returns an error if called after squeezing has begun.
        pub fn update(&mut self, input: &[u8]) -> Result<()> {
            if self.squeezed {
                return Err(SodiumError::OperationError(
                    "cannot absorb after squeezing".into(),
                ));
            }

            let result = unsafe {
                libsodium_sys::crypto_xof_shake128_update(
                    &mut self.state,
                    input.as_ptr(),
                    input.len() as u64,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError("SHAKE128 update failed".into()));
            }

            Ok(())
        }

        /// Squeezes output from the state
        ///
        /// Can be called multiple times to produce additional output.
        /// The concatenation of all squeezed outputs is identical to squeezing
        /// the total length at once.
        pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>> {
            self.squeezed = true;

            let mut output = vec![0u8; output_len];
            let result = unsafe {
                libsodium_sys::crypto_xof_shake128_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output_len,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE128 squeeze failed".into(),
                ));
            }

            Ok(output)
        }

        /// Squeezes output into a provided buffer
        pub fn squeeze_into(&mut self, output: &mut [u8]) -> Result<()> {
            self.squeezed = true;

            let result = unsafe {
                libsodium_sys::crypto_xof_shake128_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output.len(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE128 squeeze failed".into(),
                ));
            }

            Ok(())
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new().expect("SHAKE128 state initialization should not fail")
        }
    }
}

/// SHAKE256 XOF (256-bit security, 24 rounds)
///
/// SHAKE256 is a NIST-standardized XOF from FIPS 202. It provides 256-bit security
/// and uses 24 rounds of the Keccak permutation.
///
/// For most applications, prefer `turboshake256` which is faster while maintaining
/// the same security level.
pub mod shake256 {
    use super::*;

    /// Block size in bytes (136)
    pub const BLOCKBYTES: usize = libsodium_sys::crypto_xof_shake256_BLOCKBYTES as usize;

    /// State size in bytes (256)
    pub const STATEBYTES: usize = libsodium_sys::crypto_xof_shake256_STATEBYTES as usize;

    /// Standard domain separator (0x1F)
    pub const DOMAIN_STANDARD: u8 = libsodium_sys::crypto_xof_shake256_DOMAIN_STANDARD as u8;

    /// Returns the block size in bytes
    pub fn blockbytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_shake256_blockbytes() }
    }

    /// Returns the state size in bytes
    pub fn statebytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_shake256_statebytes() }
    }

    /// Returns the standard domain separator
    pub fn domain_standard() -> u8 {
        unsafe { libsodium_sys::crypto_xof_shake256_domain_standard() }
    }

    /// Computes the SHAKE256 XOF of the input in one shot
    ///
    /// # Arguments
    ///
    /// * `input` - The input data to hash
    /// * `output_len` - The desired output length in bytes
    ///
    /// # Returns
    ///
    /// The XOF output of the specified length
    pub fn hash(input: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_len];
        let result = unsafe {
            libsodium_sys::crypto_xof_shake256(
                output.as_mut_ptr(),
                output_len,
                input.as_ptr(),
                input.len() as u64,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError("SHAKE256 hash failed".into()));
        }

        Ok(output)
    }

    /// State for incremental SHAKE256 hashing
    pub struct State {
        state: libsodium_sys::crypto_xof_shake256_state,
        squeezed: bool,
    }

    impl State {
        /// Creates a new SHAKE256 state with the standard domain separator
        pub fn new() -> Result<Self> {
            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe { libsodium_sys::crypto_xof_shake256_init(&mut state.state) };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE256 state initialization failed".into(),
                ));
            }

            Ok(state)
        }

        /// Creates a new SHAKE256 state with a custom domain separator
        ///
        /// The domain must be between 0x01 and 0x7F.
        pub fn new_with_domain(domain: u8) -> Result<Self> {
            if domain == 0 || domain > 0x7F {
                return Err(SodiumError::InvalidInput(
                    "domain must be between 0x01 and 0x7F".into(),
                ));
            }

            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe {
                libsodium_sys::crypto_xof_shake256_init_with_domain(&mut state.state, domain)
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE256 state initialization with domain failed".into(),
                ));
            }

            Ok(state)
        }

        /// Absorbs data into the state
        pub fn update(&mut self, input: &[u8]) -> Result<()> {
            if self.squeezed {
                return Err(SodiumError::OperationError(
                    "cannot absorb after squeezing".into(),
                ));
            }

            let result = unsafe {
                libsodium_sys::crypto_xof_shake256_update(
                    &mut self.state,
                    input.as_ptr(),
                    input.len() as u64,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError("SHAKE256 update failed".into()));
            }

            Ok(())
        }

        /// Squeezes output from the state
        pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>> {
            self.squeezed = true;

            let mut output = vec![0u8; output_len];
            let result = unsafe {
                libsodium_sys::crypto_xof_shake256_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output_len,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE256 squeeze failed".into(),
                ));
            }

            Ok(output)
        }

        /// Squeezes output into a provided buffer
        pub fn squeeze_into(&mut self, output: &mut [u8]) -> Result<()> {
            self.squeezed = true;

            let result = unsafe {
                libsodium_sys::crypto_xof_shake256_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output.len(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "SHAKE256 squeeze failed".into(),
                ));
            }

            Ok(())
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new().expect("SHAKE256 state initialization should not fail")
        }
    }
}

/// TurboSHAKE128 XOF (128-bit security, 12 rounds)
///
/// TurboSHAKE128 is a faster variant of SHAKE128 that uses 12 rounds of the Keccak
/// permutation instead of 24. It is roughly twice as fast as SHAKE128 while
/// maintaining the same 128-bit security level.
///
/// This is the recommended XOF for most applications.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::crypto_xof::turboshake128;
///
/// // One-shot hashing
/// let hash = turboshake128::hash(b"message", 32).unwrap();
///
/// // Multi-part with domain separation
/// let mut state = turboshake128::State::new_with_domain(0x01).unwrap();
/// state.update(b"key derivation input").unwrap();
/// let key1 = state.squeeze(32).unwrap();
/// let key2 = state.squeeze(32).unwrap();
/// ```
pub mod turboshake128 {
    use super::*;

    /// Block size in bytes (168)
    pub const BLOCKBYTES: usize = libsodium_sys::crypto_xof_turboshake128_BLOCKBYTES as usize;

    /// State size in bytes (256)
    pub const STATEBYTES: usize = libsodium_sys::crypto_xof_turboshake128_STATEBYTES as usize;

    /// Standard domain separator (0x1F)
    pub const DOMAIN_STANDARD: u8 = libsodium_sys::crypto_xof_turboshake128_DOMAIN_STANDARD as u8;

    /// Returns the block size in bytes
    pub fn blockbytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_turboshake128_blockbytes() }
    }

    /// Returns the state size in bytes
    pub fn statebytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_turboshake128_statebytes() }
    }

    /// Returns the standard domain separator
    pub fn domain_standard() -> u8 {
        unsafe { libsodium_sys::crypto_xof_turboshake128_domain_standard() }
    }

    /// Computes the TurboSHAKE128 XOF of the input in one shot
    ///
    /// # Arguments
    ///
    /// * `input` - The input data to hash
    /// * `output_len` - The desired output length in bytes
    ///
    /// # Returns
    ///
    /// The XOF output of the specified length
    ///
    /// # Example
    ///
    /// ```rust
    /// use libsodium_rs::crypto_xof::turboshake128;
    ///
    /// let message = b"Hello, World!";
    /// let hash = turboshake128::hash(message, 32).unwrap();
    /// assert_eq!(hash.len(), 32);
    ///
    /// // Generate deterministic test data
    /// let seed = b"test seed";
    /// let test_data = turboshake128::hash(seed, 1000).unwrap();
    /// ```
    pub fn hash(input: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_len];
        let result = unsafe {
            libsodium_sys::crypto_xof_turboshake128(
                output.as_mut_ptr(),
                output_len,
                input.as_ptr(),
                input.len() as u64,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "TurboSHAKE128 hash failed".into(),
            ));
        }

        Ok(output)
    }

    /// State for incremental TurboSHAKE128 hashing
    ///
    /// Allows absorbing data in chunks and squeezing output incrementally.
    /// This is useful for:
    /// - Hashing large data that doesn't fit in memory
    /// - Deriving multiple keys from a single seed
    /// - Generating arbitrary amounts of deterministic output
    pub struct State {
        state: libsodium_sys::crypto_xof_turboshake128_state,
        squeezed: bool,
    }

    impl State {
        /// Creates a new TurboSHAKE128 state with the standard domain separator
        pub fn new() -> Result<Self> {
            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe { libsodium_sys::crypto_xof_turboshake128_init(&mut state.state) };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE128 state initialization failed".into(),
                ));
            }

            Ok(state)
        }

        /// Creates a new TurboSHAKE128 state with a custom domain separator
        ///
        /// Domain separators allow creating independent hash functions from the same primitive.
        /// This is useful for domain separation in cryptographic protocols.
        ///
        /// # Arguments
        ///
        /// * `domain` - The domain separator (must be between 0x01 and 0x7F)
        ///
        /// # Example
        ///
        /// ```rust
        /// use libsodium_rs::crypto_xof::turboshake128;
        ///
        /// const DOMAIN_KEY_DERIVATION: u8 = 0x01;
        /// const DOMAIN_COMMITMENT: u8 = 0x02;
        ///
        /// // These produce independent outputs even with the same input
        /// let mut state1 = turboshake128::State::new_with_domain(DOMAIN_KEY_DERIVATION).unwrap();
        /// let mut state2 = turboshake128::State::new_with_domain(DOMAIN_COMMITMENT).unwrap();
        ///
        /// state1.update(b"secret").unwrap();
        /// state2.update(b"secret").unwrap();
        ///
        /// let key = state1.squeeze(32).unwrap();
        /// let commitment = state2.squeeze(32).unwrap();
        ///
        /// assert_ne!(key, commitment);
        /// ```
        pub fn new_with_domain(domain: u8) -> Result<Self> {
            if domain == 0 || domain > 0x7F {
                return Err(SodiumError::InvalidInput(
                    "domain must be between 0x01 and 0x7F".into(),
                ));
            }

            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake128_init_with_domain(&mut state.state, domain)
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE128 state initialization with domain failed".into(),
                ));
            }

            Ok(state)
        }

        /// Absorbs data into the state
        ///
        /// Can be called multiple times before squeezing.
        /// Returns an error if called after squeezing has begun.
        pub fn update(&mut self, input: &[u8]) -> Result<()> {
            if self.squeezed {
                return Err(SodiumError::OperationError(
                    "cannot absorb after squeezing".into(),
                ));
            }

            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake128_update(
                    &mut self.state,
                    input.as_ptr(),
                    input.len() as u64,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE128 update failed".into(),
                ));
            }

            Ok(())
        }

        /// Squeezes output from the state
        ///
        /// Can be called multiple times to produce additional output.
        /// The concatenation of all squeezed outputs is identical to squeezing
        /// the total length at once.
        ///
        /// # Example
        ///
        /// ```rust
        /// use libsodium_rs::crypto_xof::turboshake128;
        ///
        /// let mut state = turboshake128::State::new().unwrap();
        /// state.update(b"seed").unwrap();
        ///
        /// // Squeeze three independent 32-byte keys
        /// let key1 = state.squeeze(32).unwrap();
        /// let key2 = state.squeeze(32).unwrap();
        /// let key3 = state.squeeze(32).unwrap();
        ///
        /// // Each key is different
        /// assert_ne!(key1, key2);
        /// assert_ne!(key2, key3);
        /// ```
        pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>> {
            self.squeezed = true;

            let mut output = vec![0u8; output_len];
            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake128_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output_len,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE128 squeeze failed".into(),
                ));
            }

            Ok(output)
        }

        /// Squeezes output into a provided buffer
        pub fn squeeze_into(&mut self, output: &mut [u8]) -> Result<()> {
            self.squeezed = true;

            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake128_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output.len(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE128 squeeze failed".into(),
                ));
            }

            Ok(())
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new().expect("TurboSHAKE128 state initialization should not fail")
        }
    }
}

/// TurboSHAKE256 XOF (256-bit security, 12 rounds)
///
/// TurboSHAKE256 is a faster variant of SHAKE256 that uses 12 rounds of the Keccak
/// permutation instead of 24. It provides 256-bit security (collision resistance
/// up to 2^128 work).
///
/// Use this when you need 256-bit collision resistance. For most applications,
/// `turboshake128` is sufficient and faster due to its larger block size.
pub mod turboshake256 {
    use super::*;

    /// Block size in bytes (136)
    pub const BLOCKBYTES: usize = libsodium_sys::crypto_xof_turboshake256_BLOCKBYTES as usize;

    /// State size in bytes (256)
    pub const STATEBYTES: usize = libsodium_sys::crypto_xof_turboshake256_STATEBYTES as usize;

    /// Standard domain separator (0x1F)
    pub const DOMAIN_STANDARD: u8 = libsodium_sys::crypto_xof_turboshake256_DOMAIN_STANDARD as u8;

    /// Returns the block size in bytes
    pub fn blockbytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_turboshake256_blockbytes() }
    }

    /// Returns the state size in bytes
    pub fn statebytes() -> usize {
        unsafe { libsodium_sys::crypto_xof_turboshake256_statebytes() }
    }

    /// Returns the standard domain separator
    pub fn domain_standard() -> u8 {
        unsafe { libsodium_sys::crypto_xof_turboshake256_domain_standard() }
    }

    /// Computes the TurboSHAKE256 XOF of the input in one shot
    ///
    /// # Arguments
    ///
    /// * `input` - The input data to hash
    /// * `output_len` - The desired output length in bytes
    ///
    /// # Returns
    ///
    /// The XOF output of the specified length
    pub fn hash(input: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_len];
        let result = unsafe {
            libsodium_sys::crypto_xof_turboshake256(
                output.as_mut_ptr(),
                output_len,
                input.as_ptr(),
                input.len() as u64,
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "TurboSHAKE256 hash failed".into(),
            ));
        }

        Ok(output)
    }

    /// State for incremental TurboSHAKE256 hashing
    pub struct State {
        state: libsodium_sys::crypto_xof_turboshake256_state,
        squeezed: bool,
    }

    impl State {
        /// Creates a new TurboSHAKE256 state with the standard domain separator
        pub fn new() -> Result<Self> {
            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe { libsodium_sys::crypto_xof_turboshake256_init(&mut state.state) };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE256 state initialization failed".into(),
                ));
            }

            Ok(state)
        }

        /// Creates a new TurboSHAKE256 state with a custom domain separator
        ///
        /// The domain must be between 0x01 and 0x7F.
        pub fn new_with_domain(domain: u8) -> Result<Self> {
            if domain == 0 || domain > 0x7F {
                return Err(SodiumError::InvalidInput(
                    "domain must be between 0x01 and 0x7F".into(),
                ));
            }

            let mut state = Self {
                state: unsafe { std::mem::zeroed() },
                squeezed: false,
            };

            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake256_init_with_domain(&mut state.state, domain)
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE256 state initialization with domain failed".into(),
                ));
            }

            Ok(state)
        }

        /// Absorbs data into the state
        pub fn update(&mut self, input: &[u8]) -> Result<()> {
            if self.squeezed {
                return Err(SodiumError::OperationError(
                    "cannot absorb after squeezing".into(),
                ));
            }

            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake256_update(
                    &mut self.state,
                    input.as_ptr(),
                    input.len() as u64,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE256 update failed".into(),
                ));
            }

            Ok(())
        }

        /// Squeezes output from the state
        pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>> {
            self.squeezed = true;

            let mut output = vec![0u8; output_len];
            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake256_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output_len,
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE256 squeeze failed".into(),
                ));
            }

            Ok(output)
        }

        /// Squeezes output into a provided buffer
        pub fn squeeze_into(&mut self, output: &mut [u8]) -> Result<()> {
            self.squeezed = true;

            let result = unsafe {
                libsodium_sys::crypto_xof_turboshake256_squeeze(
                    &mut self.state,
                    output.as_mut_ptr(),
                    output.len(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "TurboSHAKE256 squeeze failed".into(),
                ));
            }

            Ok(())
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new().expect("TurboSHAKE256 state initialization should not fail")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake128_constants() {
        assert_eq!(shake128::BLOCKBYTES, 168);
        assert_eq!(shake128::STATEBYTES, 256);
        assert_eq!(shake128::DOMAIN_STANDARD, 0x1F);

        assert_eq!(shake128::blockbytes(), 168);
        assert_eq!(shake128::statebytes(), 256);
        assert_eq!(shake128::domain_standard(), 0x1F);
    }

    #[test]
    fn test_shake256_constants() {
        assert_eq!(shake256::BLOCKBYTES, 136);
        assert_eq!(shake256::STATEBYTES, 256);
        assert_eq!(shake256::DOMAIN_STANDARD, 0x1F);

        assert_eq!(shake256::blockbytes(), 136);
        assert_eq!(shake256::statebytes(), 256);
        assert_eq!(shake256::domain_standard(), 0x1F);
    }

    #[test]
    fn test_turboshake128_constants() {
        assert_eq!(turboshake128::BLOCKBYTES, 168);
        assert_eq!(turboshake128::STATEBYTES, 256);
        assert_eq!(turboshake128::DOMAIN_STANDARD, 0x1F);

        assert_eq!(turboshake128::blockbytes(), 168);
        assert_eq!(turboshake128::statebytes(), 256);
        assert_eq!(turboshake128::domain_standard(), 0x1F);
    }

    #[test]
    fn test_turboshake256_constants() {
        assert_eq!(turboshake256::BLOCKBYTES, 136);
        assert_eq!(turboshake256::STATEBYTES, 256);
        assert_eq!(turboshake256::DOMAIN_STANDARD, 0x1F);

        assert_eq!(turboshake256::blockbytes(), 136);
        assert_eq!(turboshake256::statebytes(), 256);
        assert_eq!(turboshake256::domain_standard(), 0x1F);
    }

    #[test]
    fn test_shake128_hash() {
        let message = b"Hello, World!";
        let hash = shake128::hash(message, 32).unwrap();
        assert_eq!(hash.len(), 32);

        // Same input should produce same output
        let hash2 = shake128::hash(message, 32).unwrap();
        assert_eq!(hash, hash2);

        // Different output lengths are prefixes of each other
        let hash_short = shake128::hash(message, 16).unwrap();
        let hash_long = shake128::hash(message, 32).unwrap();
        assert_eq!(&hash_short[..], &hash_long[..16]);
    }

    #[test]
    fn test_shake256_hash() {
        let message = b"Hello, World!";
        let hash = shake256::hash(message, 64).unwrap();
        assert_eq!(hash.len(), 64);

        // Prefix property
        let hash_short = shake256::hash(message, 32).unwrap();
        assert_eq!(&hash_short[..], &hash[..32]);
    }

    #[test]
    fn test_turboshake128_hash() {
        let message = b"Hello, World!";
        let hash = turboshake128::hash(message, 32).unwrap();
        assert_eq!(hash.len(), 32);

        // Different from SHAKE128 (different number of rounds)
        let shake_hash = shake128::hash(message, 32).unwrap();
        assert_ne!(hash, shake_hash);
    }

    #[test]
    fn test_turboshake256_hash() {
        let message = b"Hello, World!";
        let hash = turboshake256::hash(message, 64).unwrap();
        assert_eq!(hash.len(), 64);

        // Different from SHAKE256
        let shake_hash = shake256::hash(message, 64).unwrap();
        assert_ne!(hash, shake_hash);
    }

    #[test]
    fn test_shake128_incremental() {
        let message = b"Hello, World!";

        // One-shot
        let hash1 = shake128::hash(message, 32).unwrap();

        // Incremental
        let mut state = shake128::State::new().unwrap();
        state.update(b"Hello, ").unwrap();
        state.update(b"World!").unwrap();
        let hash2 = state.squeeze(32).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_shake256_incremental() {
        let message = b"Hello, World!";

        let hash1 = shake256::hash(message, 64).unwrap();

        let mut state = shake256::State::new().unwrap();
        state.update(message).unwrap();
        let hash2 = state.squeeze(64).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_turboshake128_incremental() {
        let message = b"Hello, World!";

        let hash1 = turboshake128::hash(message, 32).unwrap();

        let mut state = turboshake128::State::new().unwrap();
        state.update(b"Hello, ").unwrap();
        state.update(b"World!").unwrap();
        let hash2 = state.squeeze(32).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_turboshake256_incremental() {
        let message = b"Hello, World!";

        let hash1 = turboshake256::hash(message, 64).unwrap();

        let mut state = turboshake256::State::new().unwrap();
        state.update(message).unwrap();
        let hash2 = state.squeeze(64).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_incremental_squeeze() {
        // Squeezing in parts should equal squeezing all at once
        let message = b"seed";

        let full = turboshake128::hash(message, 96).unwrap();

        let mut state = turboshake128::State::new().unwrap();
        state.update(message).unwrap();
        let part1 = state.squeeze(32).unwrap();
        let part2 = state.squeeze(32).unwrap();
        let part3 = state.squeeze(32).unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(&part1);
        combined.extend_from_slice(&part2);
        combined.extend_from_slice(&part3);

        assert_eq!(full, combined);
    }

    #[test]
    fn test_domain_separation() {
        let message = b"same input";

        // Different domains should produce different outputs
        let mut state1 = turboshake128::State::new_with_domain(0x01).unwrap();
        let mut state2 = turboshake128::State::new_with_domain(0x02).unwrap();

        state1.update(message).unwrap();
        state2.update(message).unwrap();

        let hash1 = state1.squeeze(32).unwrap();
        let hash2 = state2.squeeze(32).unwrap();

        assert_ne!(hash1, hash2);

        // Standard domain should also be different
        let mut state3 = turboshake128::State::new().unwrap();
        state3.update(message).unwrap();
        let hash3 = state3.squeeze(32).unwrap();

        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_invalid_domain() {
        // Domain 0 is invalid
        assert!(shake128::State::new_with_domain(0x00).is_err());
        assert!(shake256::State::new_with_domain(0x00).is_err());
        assert!(turboshake128::State::new_with_domain(0x00).is_err());
        assert!(turboshake256::State::new_with_domain(0x00).is_err());

        // Domain > 0x7F is invalid
        assert!(shake128::State::new_with_domain(0x80).is_err());
        assert!(shake256::State::new_with_domain(0x80).is_err());
        assert!(turboshake128::State::new_with_domain(0x80).is_err());
        assert!(turboshake256::State::new_with_domain(0x80).is_err());

        // Valid domain
        assert!(turboshake128::State::new_with_domain(0x01).is_ok());
        assert!(turboshake128::State::new_with_domain(0x7F).is_ok());
    }

    #[test]
    fn test_no_update_after_squeeze() {
        let mut state = turboshake128::State::new().unwrap();
        state.update(b"data").unwrap();
        state.squeeze(32).unwrap();

        // Should fail to update after squeezing
        assert!(state.update(b"more data").is_err());
    }

    #[test]
    fn test_squeeze_into() {
        let message = b"test";
        let mut state = turboshake128::State::new().unwrap();
        state.update(message).unwrap();

        let mut output = [0u8; 32];
        state.squeeze_into(&mut output).unwrap();

        let expected = turboshake128::hash(message, 32).unwrap();
        assert_eq!(&output[..], &expected[..]);
    }

    #[test]
    fn test_variable_output_lengths() {
        let message = b"test";

        // Various output sizes
        for len in [1, 16, 32, 64, 100, 256, 1000] {
            let output = turboshake128::hash(message, len).unwrap();
            assert_eq!(output.len(), len);
        }
    }

    #[test]
    fn test_empty_input() {
        // Empty input should work
        let hash = turboshake128::hash(&[], 32).unwrap();
        assert_eq!(hash.len(), 32);

        let mut state = turboshake128::State::new().unwrap();
        let hash2 = state.squeeze(32).unwrap();
        assert_eq!(hash, hash2);
    }
}
