//! # Key Encapsulation Mechanisms
//!
//! This module provides safe wrappers for libsodium's KEM APIs.
//! KEMs allow one party to encapsulate a shared secret to a recipient's public key,
//! and the recipient to decapsulate the same shared secret using its secret key.
//!
//! The default `crypto_kem` API currently maps to X-Wing in libsodium 1.24.0.
//! Algorithm-specific submodules are also available for direct use.

use crate::{Result, SodiumError};
use std::ffi::CStr;

/// Number of bytes in a public key for the default KEM primitive.
pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_kem_PUBLICKEYBYTES as usize;

/// Number of bytes in a secret key for the default KEM primitive.
pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_kem_SECRETKEYBYTES as usize;

/// Number of bytes in a ciphertext for the default KEM primitive.
pub const CIPHERTEXTBYTES: usize = libsodium_sys::crypto_kem_CIPHERTEXTBYTES as usize;

/// Number of bytes in an encapsulated shared secret.
pub const SHAREDSECRETBYTES: usize = libsodium_sys::crypto_kem_SHAREDSECRETBYTES as usize;

/// Number of bytes in a seed used for deterministic key generation.
pub const SEEDBYTES: usize = libsodium_sys::crypto_kem_SEEDBYTES as usize;

/// Name of the default KEM primitive.
pub const PRIMITIVE: &str = "xwing";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ciphertext([u8; CIPHERTEXTBYTES]);

#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHAREDSECRETBYTES]);

#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Seed([u8; SEEDBYTES]);

pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

macro_rules! impl_bytes_type {
    ($name:ident, $len:ident, $err:literal) => {
        impl $name {
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $len {
                    return Err(SodiumError::InvalidInput(format!(
                        concat!($err, " must be exactly {} bytes"),
                        $len
                    )));
                }

                let mut value = [0u8; $len];
                value.copy_from_slice(bytes);
                Ok(Self(value))
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = SodiumError;

            fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
                Self::from_bytes(bytes)
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

impl_bytes_type!(PublicKey, PUBLICKEYBYTES, "public key");
impl_bytes_type!(SecretKey, SECRETKEYBYTES, "secret key");
impl_bytes_type!(Ciphertext, CIPHERTEXTBYTES, "ciphertext");
impl_bytes_type!(SharedSecret, SHAREDSECRETBYTES, "shared secret");
impl_bytes_type!(Seed, SEEDBYTES, "seed");

impl KeyPair {
    /// Generates a new random KEM keypair.
    pub fn generate() -> Result<Self> {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        let result = unsafe { libsodium_sys::crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to generate KEM keypair".into(),
            ));
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    /// Generates a deterministic KEM keypair from a seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != SEEDBYTES {
            return Err(SodiumError::InvalidInput(format!(
                "invalid seed length: expected {}, got {}",
                SEEDBYTES,
                seed.len()
            )));
        }

        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to generate KEM keypair from seed".into(),
            ));
        }

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        })
    }

    pub fn into_tuple(self) -> (PublicKey, SecretKey) {
        (self.public_key, self.secret_key)
    }
}

/// Encapsulates a shared secret to a recipient public key.
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    let mut ciphertext = [0u8; CIPHERTEXTBYTES];
    let mut shared_secret = [0u8; SHAREDSECRETBYTES];

    let result = unsafe {
        libsodium_sys::crypto_kem_enc(
            ciphertext.as_mut_ptr(),
            shared_secret.as_mut_ptr(),
            public_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "failed to encapsulate shared secret".into(),
        ));
    }

    Ok((Ciphertext(ciphertext), SharedSecret(shared_secret)))
}

/// Decapsulates a shared secret using a secret key.
pub fn decapsulate(ciphertext: &Ciphertext, secret_key: &SecretKey) -> Result<SharedSecret> {
    let mut shared_secret = [0u8; SHAREDSECRETBYTES];

    let result = unsafe {
        libsodium_sys::crypto_kem_dec(
            shared_secret.as_mut_ptr(),
            ciphertext.as_bytes().as_ptr(),
            secret_key.as_bytes().as_ptr(),
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "failed to decapsulate shared secret".into(),
        ));
    }

    Ok(SharedSecret(shared_secret))
}

pub fn publickeybytes() -> usize {
    unsafe { libsodium_sys::crypto_kem_publickeybytes() }
}

pub fn secretkeybytes() -> usize {
    unsafe { libsodium_sys::crypto_kem_secretkeybytes() }
}

pub fn ciphertextbytes() -> usize {
    unsafe { libsodium_sys::crypto_kem_ciphertextbytes() }
}

pub fn sharedsecretbytes() -> usize {
    unsafe { libsodium_sys::crypto_kem_sharedsecretbytes() }
}

pub fn seedbytes() -> usize {
    unsafe { libsodium_sys::crypto_kem_seedbytes() }
}

pub fn primitive() -> &'static str {
    unsafe {
        CStr::from_ptr(libsodium_sys::crypto_kem_primitive())
            .to_str()
            .expect("crypto_kem primitive should be valid UTF-8")
    }
}

pub mod mlkem768 {
    use crate::{Result, SodiumError};

    pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_kem_mlkem768_PUBLICKEYBYTES as usize;
    pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_kem_mlkem768_SECRETKEYBYTES as usize;
    pub const CIPHERTEXTBYTES: usize = libsodium_sys::crypto_kem_mlkem768_CIPHERTEXTBYTES as usize;
    pub const SHAREDSECRETBYTES: usize =
        libsodium_sys::crypto_kem_mlkem768_SHAREDSECRETBYTES as usize;
    pub const SEEDBYTES: usize = libsodium_sys::crypto_kem_mlkem768_SEEDBYTES as usize;

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct PublicKey([u8; PUBLICKEYBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct SecretKey([u8; SECRETKEYBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct Ciphertext([u8; CIPHERTEXTBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct SharedSecret([u8; SHAREDSECRETBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Seed([u8; SEEDBYTES]);

    pub struct KeyPair {
        pub public_key: PublicKey,
        pub secret_key: SecretKey,
    }

    macro_rules! impl_bytes_type {
        ($name:ident, $len:ident, $err:literal) => {
            impl $name {
                pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                    if bytes.len() != $len {
                        return Err(SodiumError::InvalidInput(format!(
                            concat!($err, " must be exactly {} bytes"),
                            $len
                        )));
                    }

                    let mut value = [0u8; $len];
                    value.copy_from_slice(bytes);
                    Ok(Self(value))
                }

                pub fn as_bytes(&self) -> &[u8; $len] {
                    &self.0
                }
            }

            impl AsRef<[u8]> for $name {
                fn as_ref(&self) -> &[u8] {
                    self.as_bytes()
                }
            }

            impl TryFrom<&[u8]> for $name {
                type Error = SodiumError;

                fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
                    Self::from_bytes(bytes)
                }
            }

            impl From<[u8; $len]> for $name {
                fn from(bytes: [u8; $len]) -> Self {
                    Self(bytes)
                }
            }

            impl From<$name> for [u8; $len] {
                fn from(value: $name) -> Self {
                    value.0
                }
            }
        };
    }

    impl_bytes_type!(PublicKey, PUBLICKEYBYTES, "public key");
    impl_bytes_type!(SecretKey, SECRETKEYBYTES, "secret key");
    impl_bytes_type!(Ciphertext, CIPHERTEXTBYTES, "ciphertext");
    impl_bytes_type!(SharedSecret, SHAREDSECRETBYTES, "shared secret");
    impl_bytes_type!(Seed, SEEDBYTES, "seed");

    impl KeyPair {
        pub fn generate() -> Result<Self> {
            let mut pk = [0u8; PUBLICKEYBYTES];
            let mut sk = [0u8; SECRETKEYBYTES];

            let result = unsafe {
                libsodium_sys::crypto_kem_mlkem768_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "failed to generate ML-KEM-768 keypair".into(),
                ));
            }

            Ok(Self {
                public_key: PublicKey(pk),
                secret_key: SecretKey(sk),
            })
        }

        pub fn from_seed(seed: &[u8]) -> Result<Self> {
            if seed.len() != SEEDBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "invalid seed length: expected {}, got {}",
                    SEEDBYTES,
                    seed.len()
                )));
            }

            let mut pk = [0u8; PUBLICKEYBYTES];
            let mut sk = [0u8; SECRETKEYBYTES];

            let result = unsafe {
                libsodium_sys::crypto_kem_mlkem768_seed_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr(),
                    seed.as_ptr(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "failed to generate ML-KEM-768 keypair from seed".into(),
                ));
            }

            Ok(Self {
                public_key: PublicKey(pk),
                secret_key: SecretKey(sk),
            })
        }

        pub fn into_tuple(self) -> (PublicKey, SecretKey) {
            (self.public_key, self.secret_key)
        }
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        let mut ciphertext = [0u8; CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; SHAREDSECRETBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_mlkem768_enc(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                public_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to encapsulate ML-KEM-768 shared secret".into(),
            ));
        }

        Ok((Ciphertext(ciphertext), SharedSecret(shared_secret)))
    }

    pub fn encapsulate_deterministic(
        public_key: &PublicKey,
        seed: &Seed,
    ) -> Result<(Ciphertext, SharedSecret)> {
        let mut ciphertext = [0u8; CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; SHAREDSECRETBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_mlkem768_enc_deterministic(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                public_key.as_bytes().as_ptr(),
                seed.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to deterministically encapsulate ML-KEM-768 shared secret".into(),
            ));
        }

        Ok((Ciphertext(ciphertext), SharedSecret(shared_secret)))
    }

    pub fn decapsulate(ciphertext: &Ciphertext, secret_key: &SecretKey) -> Result<SharedSecret> {
        let mut shared_secret = [0u8; SHAREDSECRETBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_mlkem768_dec(
                shared_secret.as_mut_ptr(),
                ciphertext.as_bytes().as_ptr(),
                secret_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to decapsulate ML-KEM-768 shared secret".into(),
            ));
        }

        Ok(SharedSecret(shared_secret))
    }

    pub fn publickeybytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_mlkem768_publickeybytes() }
    }

    pub fn secretkeybytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_mlkem768_secretkeybytes() }
    }

    pub fn ciphertextbytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_mlkem768_ciphertextbytes() }
    }

    pub fn sharedsecretbytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_mlkem768_sharedsecretbytes() }
    }

    pub fn seedbytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_mlkem768_seedbytes() }
    }
}

pub mod xwing {
    use crate::{Result, SodiumError};

    pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_kem_xwing_PUBLICKEYBYTES as usize;
    pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_kem_xwing_SECRETKEYBYTES as usize;
    pub const CIPHERTEXTBYTES: usize = libsodium_sys::crypto_kem_xwing_CIPHERTEXTBYTES as usize;
    pub const SHAREDSECRETBYTES: usize = libsodium_sys::crypto_kem_xwing_SHAREDSECRETBYTES as usize;
    pub const SEEDBYTES: usize = libsodium_sys::crypto_kem_xwing_SEEDBYTES as usize;

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct PublicKey([u8; PUBLICKEYBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct SecretKey([u8; SECRETKEYBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct Ciphertext([u8; CIPHERTEXTBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct SharedSecret([u8; SHAREDSECRETBYTES]);

    #[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct Seed([u8; SEEDBYTES]);

    pub struct KeyPair {
        pub public_key: PublicKey,
        pub secret_key: SecretKey,
    }

    macro_rules! impl_bytes_type {
        ($name:ident, $len:ident, $err:literal) => {
            impl $name {
                pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                    if bytes.len() != $len {
                        return Err(SodiumError::InvalidInput(format!(
                            concat!($err, " must be exactly {} bytes"),
                            $len
                        )));
                    }

                    let mut value = [0u8; $len];
                    value.copy_from_slice(bytes);
                    Ok(Self(value))
                }

                pub fn as_bytes(&self) -> &[u8; $len] {
                    &self.0
                }
            }

            impl AsRef<[u8]> for $name {
                fn as_ref(&self) -> &[u8] {
                    self.as_bytes()
                }
            }

            impl TryFrom<&[u8]> for $name {
                type Error = SodiumError;

                fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
                    Self::from_bytes(bytes)
                }
            }

            impl From<[u8; $len]> for $name {
                fn from(bytes: [u8; $len]) -> Self {
                    Self(bytes)
                }
            }

            impl From<$name> for [u8; $len] {
                fn from(value: $name) -> Self {
                    value.0
                }
            }
        };
    }

    impl_bytes_type!(PublicKey, PUBLICKEYBYTES, "public key");
    impl_bytes_type!(SecretKey, SECRETKEYBYTES, "secret key");
    impl_bytes_type!(Ciphertext, CIPHERTEXTBYTES, "ciphertext");
    impl_bytes_type!(SharedSecret, SHAREDSECRETBYTES, "shared secret");
    impl_bytes_type!(Seed, SEEDBYTES, "seed");

    impl KeyPair {
        pub fn generate() -> Result<Self> {
            let mut pk = [0u8; PUBLICKEYBYTES];
            let mut sk = [0u8; SECRETKEYBYTES];

            let result = unsafe {
                libsodium_sys::crypto_kem_xwing_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "failed to generate X-Wing keypair".into(),
                ));
            }

            Ok(Self {
                public_key: PublicKey(pk),
                secret_key: SecretKey(sk),
            })
        }

        pub fn from_seed(seed: &[u8]) -> Result<Self> {
            if seed.len() != SEEDBYTES {
                return Err(SodiumError::InvalidInput(format!(
                    "invalid seed length: expected {}, got {}",
                    SEEDBYTES,
                    seed.len()
                )));
            }

            let mut pk = [0u8; PUBLICKEYBYTES];
            let mut sk = [0u8; SECRETKEYBYTES];

            let result = unsafe {
                libsodium_sys::crypto_kem_xwing_seed_keypair(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr(),
                    seed.as_ptr(),
                )
            };

            if result != 0 {
                return Err(SodiumError::OperationError(
                    "failed to generate X-Wing keypair from seed".into(),
                ));
            }

            Ok(Self {
                public_key: PublicKey(pk),
                secret_key: SecretKey(sk),
            })
        }

        pub fn into_tuple(self) -> (PublicKey, SecretKey) {
            (self.public_key, self.secret_key)
        }
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        let mut ciphertext = [0u8; CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; SHAREDSECRETBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_xwing_enc(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                public_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to encapsulate X-Wing shared secret".into(),
            ));
        }

        Ok((Ciphertext(ciphertext), SharedSecret(shared_secret)))
    }

    pub fn encapsulate_deterministic(
        public_key: &PublicKey,
        seed: &Seed,
    ) -> Result<(Ciphertext, SharedSecret)> {
        let mut ciphertext = [0u8; CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; SHAREDSECRETBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_xwing_enc_deterministic(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                public_key.as_bytes().as_ptr(),
                seed.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to deterministically encapsulate X-Wing shared secret".into(),
            ));
        }

        Ok((Ciphertext(ciphertext), SharedSecret(shared_secret)))
    }

    pub fn decapsulate(ciphertext: &Ciphertext, secret_key: &SecretKey) -> Result<SharedSecret> {
        let mut shared_secret = [0u8; SHAREDSECRETBYTES];

        let result = unsafe {
            libsodium_sys::crypto_kem_xwing_dec(
                shared_secret.as_mut_ptr(),
                ciphertext.as_bytes().as_ptr(),
                secret_key.as_bytes().as_ptr(),
            )
        };

        if result != 0 {
            return Err(SodiumError::OperationError(
                "failed to decapsulate X-Wing shared secret".into(),
            ));
        }

        Ok(SharedSecret(shared_secret))
    }

    pub fn publickeybytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_xwing_publickeybytes() }
    }

    pub fn secretkeybytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_xwing_secretkeybytes() }
    }

    pub fn ciphertextbytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_xwing_ciphertextbytes() }
    }

    pub fn sharedsecretbytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_xwing_sharedsecretbytes() }
    }

    pub fn seedbytes() -> usize {
        unsafe { libsodium_sys::crypto_kem_xwing_seedbytes() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sizes_and_primitive() {
        assert_eq!(publickeybytes(), PUBLICKEYBYTES);
        assert_eq!(secretkeybytes(), SECRETKEYBYTES);
        assert_eq!(ciphertextbytes(), CIPHERTEXTBYTES);
        assert_eq!(sharedsecretbytes(), SHAREDSECRETBYTES);
        assert_eq!(seedbytes(), SEEDBYTES);
        assert_eq!(primitive(), PRIMITIVE);
    }

    #[test]
    fn test_keypair_generation_and_roundtrip() {
        let keypair = KeyPair::generate().unwrap();
        let (public_key, secret_key) = keypair.into_tuple();
        let (ciphertext, shared_secret_sender) = encapsulate(&public_key).unwrap();
        let shared_secret_recipient = decapsulate(&ciphertext, &secret_key).unwrap();

        assert_eq!(shared_secret_sender, shared_secret_recipient);
    }

    #[test]
    fn test_seeded_keypair_is_deterministic() {
        let seed = [7u8; SEEDBYTES];
        let keypair1 = KeyPair::from_seed(&seed).unwrap();
        let keypair2 = KeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.secret_key, keypair2.secret_key);
    }

    #[test]
    fn test_mlkem768_roundtrip() {
        let keypair = mlkem768::KeyPair::generate().unwrap();
        let (ciphertext, shared_secret_sender) =
            mlkem768::encapsulate(&keypair.public_key).unwrap();
        let shared_secret_recipient =
            mlkem768::decapsulate(&ciphertext, &keypair.secret_key).unwrap();

        assert_eq!(shared_secret_sender, shared_secret_recipient);
    }

    #[test]
    fn test_mlkem768_deterministic_apis() {
        let seed = [5u8; mlkem768::SEEDBYTES];
        let keypair1 = mlkem768::KeyPair::from_seed(&seed).unwrap();
        let keypair2 = mlkem768::KeyPair::from_seed(&seed).unwrap();
        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.secret_key, keypair2.secret_key);

        let enc_seed = mlkem768::Seed::from([9u8; mlkem768::SEEDBYTES]);
        let (ct1, ss1) =
            mlkem768::encapsulate_deterministic(&keypair1.public_key, &enc_seed).unwrap();
        let (ct2, ss2) =
            mlkem768::encapsulate_deterministic(&keypair1.public_key, &enc_seed).unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_xwing_roundtrip() {
        let keypair = xwing::KeyPair::generate().unwrap();
        let (ciphertext, shared_secret_sender) = xwing::encapsulate(&keypair.public_key).unwrap();
        let shared_secret_recipient = xwing::decapsulate(&ciphertext, &keypair.secret_key).unwrap();

        assert_eq!(shared_secret_sender, shared_secret_recipient);
    }

    #[test]
    fn test_xwing_deterministic_apis() {
        let seed = [3u8; xwing::SEEDBYTES];
        let keypair1 = xwing::KeyPair::from_seed(&seed).unwrap();
        let keypair2 = xwing::KeyPair::from_seed(&seed).unwrap();
        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.secret_key, keypair2.secret_key);

        let enc_seed = xwing::Seed::from([11u8; xwing::SEEDBYTES]);
        let (ct1, ss1) = xwing::encapsulate_deterministic(&keypair1.public_key, &enc_seed).unwrap();
        let (ct2, ss2) = xwing::encapsulate_deterministic(&keypair1.public_key, &enc_seed).unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }
}
