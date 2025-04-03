use crate::{Result, SodiumError};
use libc;

pub const ALG: i32 = libsodium_sys::crypto_pwhash_argon2i_ALG_ARGON2I13 as i32;

pub const BYTES_MIN: usize = libsodium_sys::crypto_pwhash_argon2i_BYTES_MIN as usize;
// Using a hardcoded value since we can't call functions in const contexts
pub const BYTES_MAX: usize = 0x001f_ffff_ffe0; // Value from libsodium
pub const PASSWD_MIN: usize = libsodium_sys::crypto_pwhash_argon2i_PASSWD_MIN as usize;
pub const PASSWD_MAX: usize = libsodium_sys::crypto_pwhash_argon2i_PASSWD_MAX as usize;
pub const SALTBYTES: usize = libsodium_sys::crypto_pwhash_argon2i_SALTBYTES as usize;
pub const STRBYTES: usize = libsodium_sys::crypto_pwhash_argon2i_STRBYTES as usize;

pub const OPSLIMIT_MIN: u64 = libsodium_sys::crypto_pwhash_argon2i_OPSLIMIT_MIN as u64;
pub const OPSLIMIT_MAX: u64 = libsodium_sys::crypto_pwhash_argon2i_OPSLIMIT_MAX as u64;
pub const MEMLIMIT_MIN: usize = libsodium_sys::crypto_pwhash_argon2i_MEMLIMIT_MIN as usize;
// Using a hardcoded value since we can't call functions in const contexts
pub const MEMLIMIT_MAX: usize = 4_398_046_510_080; // Value from libsodium

pub const OPSLIMIT_INTERACTIVE: u64 =
    libsodium_sys::crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE as u64;
pub const MEMLIMIT_INTERACTIVE: usize =
    libsodium_sys::crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE as usize;
pub const OPSLIMIT_MODERATE: u64 = libsodium_sys::crypto_pwhash_argon2i_OPSLIMIT_MODERATE as u64;
pub const MEMLIMIT_MODERATE: usize =
    libsodium_sys::crypto_pwhash_argon2i_MEMLIMIT_MODERATE as usize;
pub const OPSLIMIT_SENSITIVE: u64 = libsodium_sys::crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE as u64;
pub const MEMLIMIT_SENSITIVE: usize =
    libsodium_sys::crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE as usize;

/// Derives a key from a password using Argon2i
pub fn pwhash(
    out_len: usize,
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> Result<Vec<u8>> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&out_len) {
        return Err(SodiumError::InvalidInput(format!(
            "output length must be between {} and {} bytes",
            BYTES_MIN, BYTES_MAX
        )));
    }

    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be between {} and {} bytes",
            PASSWD_MIN, PASSWD_MAX
        )));
    }

    if salt.len() != SALTBYTES {
        return Err(SodiumError::InvalidInput(format!(
            "salt must be exactly {} bytes",
            SALTBYTES
        )));
    }

    if !(OPSLIMIT_MIN..=OPSLIMIT_MAX).contains(&opslimit) {
        return Err(SodiumError::InvalidInput(format!(
            "opslimit must be between {} and {}",
            OPSLIMIT_MIN, OPSLIMIT_MAX
        )));
    }

    if !(MEMLIMIT_MIN..=MEMLIMIT_MAX).contains(&memlimit) {
        return Err(SodiumError::InvalidInput(format!(
            "memlimit must be between {} and {}",
            MEMLIMIT_MIN, MEMLIMIT_MAX
        )));
    }

    let mut output = vec![0u8; out_len];
    let result = unsafe {
        libsodium_sys::crypto_pwhash_argon2i(
            output.as_mut_ptr(),
            out_len as libc::c_ulonglong,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
            salt.as_ptr(),
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
            ALG,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "password hashing failed".into(),
        ));
    }

    Ok(output)
}

/// Creates a password hash string for storage using Argon2i
pub fn pwhash_str(password: &[u8], opslimit: u64, memlimit: usize) -> Result<String> {
    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be between {} and {} bytes",
            PASSWD_MIN, PASSWD_MAX
        )));
    }

    if !(OPSLIMIT_MIN..=OPSLIMIT_MAX).contains(&opslimit) {
        return Err(SodiumError::InvalidInput(format!(
            "opslimit must be between {} and {}",
            OPSLIMIT_MIN, OPSLIMIT_MAX
        )));
    }

    if !(MEMLIMIT_MIN..=MEMLIMIT_MAX).contains(&memlimit) {
        return Err(SodiumError::InvalidInput(format!(
            "memlimit must be between {} and {}",
            MEMLIMIT_MIN, MEMLIMIT_MAX
        )));
    }

    let mut output = vec![0u8; STRBYTES];
    let result = unsafe {
        libsodium_sys::crypto_pwhash_argon2i_str(
            output.as_mut_ptr() as *mut libc::c_char,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
        )
    };

    if result != 0 {
        return Err(SodiumError::OperationError(
            "password hashing failed".into(),
        ));
    }

    // Find the null terminator
    let null_pos = output.iter().position(|&b| b == 0).unwrap_or(output.len());
    output.truncate(null_pos);

    String::from_utf8(output)
        .map_err(|_| SodiumError::OperationError("invalid UTF-8 in hash string".into()))
}

/// Verifies a password against a hash string using Argon2i
pub fn pwhash_str_verify(hash_str: &str, password: &[u8]) -> Result<bool> {
    if password.len() > PASSWD_MAX {
        return Err(SodiumError::InvalidInput(format!(
            "password length must be between {} and {} bytes",
            PASSWD_MIN, PASSWD_MAX
        )));
    }

    let result = unsafe {
        libsodium_sys::crypto_pwhash_argon2i_str_verify(
            hash_str.as_ptr() as *const libc::c_char,
            password.as_ptr() as *const libc::c_char,
            password.len() as libc::c_ulonglong,
        )
    };

    Ok(result == 0)
}

/// Checks if a password hash needs to be rehashed using Argon2i
pub fn pwhash_str_needs_rehash(hash_str: &str, opslimit: u64, memlimit: usize) -> Result<bool> {
    let result = unsafe {
        libsodium_sys::crypto_pwhash_argon2i_str_needs_rehash(
            hash_str.as_ptr() as *const libc::c_char,
            opslimit as libc::c_ulonglong,
            memlimit as libc::size_t,
        )
    };

    if result == -1 {
        return Err(SodiumError::InvalidInput("invalid hash string".into()));
    }

    Ok(result != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random;

    #[test]
    fn test_pwhash() {
        let password = b"test password";
        let mut salt = [0u8; SALTBYTES];
        random::fill_bytes(&mut salt);

        let key = pwhash(
            32,
            password,
            &salt,
            OPSLIMIT_INTERACTIVE,
            MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pwhash_str() {
        let password = b"test password";
        let hash_str = pwhash_str(password, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();

        assert!(pwhash_str_verify(&hash_str, password).unwrap());
        assert!(!pwhash_str_verify(&hash_str, b"wrong password").unwrap());
    }

    #[test]
    fn test_pwhash_str_needs_rehash() {
        let password = b"test password";
        let hash_str = pwhash_str(password, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();

        // Same parameters, shouldn't need rehash
        assert!(
            !pwhash_str_needs_rehash(&hash_str, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE,)
                .unwrap()
        );

        // Different parameters, should need rehash
        assert!(
            pwhash_str_needs_rehash(&hash_str, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE,).unwrap()
        );
    }
}
