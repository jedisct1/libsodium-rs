//! Utility functions for BLAKE2b

/// Returns the size of the BLAKE2b state in bytes
///
/// This function returns the size of the internal state used by the BLAKE2b hash function.
pub fn statebytes() -> usize {
    unsafe { libsodium_sys::crypto_generichash_blake2b_statebytes() }
}

/// Returns the size of the BLAKE2b salt in bytes
///
/// This function returns the size of the BLAKE2b salt in bytes,
/// which is always 16 bytes.
pub fn saltbytes() -> usize {
    unsafe { libsodium_sys::crypto_generichash_blake2b_saltbytes() }
}

/// Returns the size of the BLAKE2b personalization in bytes
///
/// This function returns the size of the BLAKE2b personalization in bytes,
/// which is always 16 bytes.
pub fn personalbytes() -> usize {
    unsafe { libsodium_sys::crypto_generichash_blake2b_personalbytes() }
}

/// Returns the default size of the BLAKE2b key in bytes
///
/// This function returns the default size of the BLAKE2b key in bytes,
/// which is always 32 bytes.
pub fn keybytes() -> usize {
    unsafe { libsodium_sys::crypto_generichash_blake2b_keybytes() }
}
