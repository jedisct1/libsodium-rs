//! # Cryptographic Utilities
//!
//! This module provides various utility functions for cryptographic operations, including
//! secure memory management, constant-time comparisons, and encoding/decoding functions.
//! These utilities are designed to help implement cryptographic protocols securely and
//! efficiently.
//!
//! ## Security Considerations
//!
//! - Many functions in this module are specifically designed to prevent side-channel attacks
//!   and other security vulnerabilities.
//! - The memory management functions help prevent sensitive data from being leaked or
//!   swapped to disk.
//! - Always use these utilities when handling sensitive cryptographic material.
//!
//! ## Key Features
//!
//! - **Secure Memory Management**: Functions for securely allocating, protecting, and
//!   clearing memory containing sensitive data.
//! - **Constant-Time Operations**: Functions for comparing data in constant time to prevent
//!   timing attacks.
//! - **Encoding/Decoding**: Functions for converting between binary data and hexadecimal or
//!   Base64 representations.
//! - **Arithmetic Operations**: Functions for performing arithmetic on big-endian encoded
//!   numbers, useful for nonce management.
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use sodium::utils;
//! use sodium::ensure_init;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     ensure_init()?;
//!
//!     // Secure memory operations
//!     let mut sensitive_data = [0x01, 0x02, 0x03, 0x04];
//!
//!     // Lock memory to prevent it from being swapped to disk
//!     utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
//!
//!     // Use the sensitive data...
//!
//!     // Securely zero the memory when done
//!     utils::memzero(&mut sensitive_data);
//!     assert_eq!(sensitive_data, [0, 0, 0, 0]);
//!
//!     // Unlock the memory
//!     utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
//!
//!     // Constant-time comparison
//!     let tag1 = [0x01, 0x02, 0x03, 0x04];
//!     let tag2 = [0x01, 0x02, 0x03, 0x04];
//!     assert!(utils::memcmp(&tag1, &tag2));
//!
//!     // Encoding/decoding
//!     let binary = [0xDE, 0xAD, 0xBE, 0xEF];
//!     let hex = utils::bin2hex(&binary);
//!     assert_eq!(hex, "deadbeef");
//!
//!     Ok(())
//! }
//! ```
//!

use crate::Result;
use libsodium_sys;
use std::ptr;

/// Base64 encoding variant: original (standard) Base64 encoding
pub const BASE64_VARIANT_ORIGINAL: i32 = libsodium_sys::sodium_base64_VARIANT_ORIGINAL as i32;

/// Base64 encoding variant: original (standard) Base64 encoding without padding
pub const BASE64_VARIANT_ORIGINAL_NO_PADDING: i32 =
    libsodium_sys::sodium_base64_VARIANT_ORIGINAL_NO_PADDING as i32;

/// Base64 encoding variant: URL-safe Base64 encoding
pub const BASE64_VARIANT_URLSAFE: i32 = libsodium_sys::sodium_base64_VARIANT_URLSAFE as i32;

/// Base64 encoding variant: URL-safe Base64 encoding without padding
pub const BASE64_VARIANT_URLSAFE_NO_PADDING: i32 =
    libsodium_sys::sodium_base64_VARIANT_URLSAFE_NO_PADDING as i32;

/// Compare two byte slices in constant time
///
/// This function compares two byte slices in constant time, which is important for
/// comparing secret data like authentication tags or passwords. It returns true if
/// the slices are equal, false otherwise.
///
/// ## Security Considerations
///
/// - This function is designed to prevent timing attacks that could leak information
///   about the contents of the slices being compared.
/// - It should be used whenever comparing sensitive data like authentication tags,
///   MACs, or password hashes.
/// - Regular comparison operators (==) should NOT be used for comparing secret data
///   as they may be vulnerable to timing attacks.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let tag1 = [0x01, 0x02, 0x03, 0x04];
/// let tag2 = [0x01, 0x02, 0x03, 0x04];
/// let tag3 = [0x01, 0x02, 0x03, 0x05];
///
/// // Compare in constant time
/// assert!(utils::memcmp(&tag1, &tag2)); // Equal
/// assert!(!utils::memcmp(&tag1, &tag3)); // Not equal
/// ```
///
/// # Arguments
/// * `a` - First byte slice to compare
/// * `b` - Second byte slice to compare
///
/// # Returns
/// * `bool` - `true` if the slices are equal, `false` otherwise
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    unsafe {
        libsodium_sys::sodium_memcmp(a.as_ptr() as *const _, b.as_ptr() as *const _, a.len()) == 0
    }
}

/// Zero a byte slice in a way that won't be optimized out
///
/// This function securely zeroes a byte slice, ensuring that the operation
/// won't be optimized out by the compiler. This is important for securely
/// clearing sensitive data from memory.
///
/// ## Security Considerations
///
/// - Regular assignment operations (like `buf = [0; N]`) might be optimized out
///   by the compiler if it determines the values won't be read again.
/// - This function guarantees that the memory will be zeroed regardless of
///   compiler optimizations.
/// - Use this whenever you need to clear sensitive data like keys, passwords,
///   or other secret material from memory.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// // Some sensitive data
/// let mut secret_key = [0x01, 0x02, 0x03, 0x04];
///
/// // Use the key for some operation...
///
/// // Securely clear the key from memory when done
/// utils::memzero(&mut secret_key);
/// assert_eq!(secret_key, [0, 0, 0, 0]);
/// ```
///
/// # Arguments
/// * `buf` - The byte slice to zero
pub fn memzero(buf: &mut [u8]) {
    unsafe {
        libsodium_sys::sodium_memzero(buf.as_mut_ptr() as *mut _, buf.len());
    }
}

/// Zero a region of the stack in a way that won't be optimized out
///
/// This function securely zeroes a region of the stack, ensuring that the operation
/// won't be optimized out by the compiler. This is useful for clearing sensitive
/// stack-allocated variables.
///
/// ## Security Considerations
///
/// - This function is specifically designed for clearing sensitive data from the stack.
/// - For heap-allocated memory, use `memzero()` instead.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// // Some sensitive stack data
/// let mut sensitive_data = [0x01u8; 1024];
///
/// // Use the data for some operation...
///
/// // Securely clear the data from the stack
/// utils::stackzero(sensitive_data.len());
/// ```
///
/// # Arguments
/// * `len` - The number of bytes to zero on the stack
pub fn stackzero(len: usize) {
    unsafe {
        libsodium_sys::sodium_stackzero(len);
    }
}

/// Lock memory pages containing this slice, preventing them from being swapped to disk
///
/// This function locks the memory pages containing the provided byte slice, preventing
/// them from being swapped to disk. This is important for sensitive data like encryption
/// keys, passwords, or other secret material.
///
/// # Returns
/// * `std::io::Result<()>` - Success or an IO error if the operation fails
///
/// # Examples
/// ```
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut sensitive_data = [0x01, 0x02, 0x03, 0x04];
/// utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
/// // Use the sensitive data...
/// utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
/// ```
pub fn mlock(buf: &mut [u8]) -> std::io::Result<()> {
    let result = unsafe {
        libsodium_sys::sodium_mlock(
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as libc::size_t,
        )
    };

    if result != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to lock memory",
        ));
    }
    Ok(())
}

/// Unlock previously locked memory pages
///
/// This function unlocks memory pages that were previously locked with `mlock`.
/// It should be called when the sensitive data is no longer needed.
///
/// # Returns
/// * `std::io::Result<()>` - Success or an IO error if the operation fails
///
/// # Examples
/// ```
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut sensitive_data = [0x01, 0x02, 0x03, 0x04];
/// utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
/// // Use the sensitive data...
/// utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
/// ```
pub fn munlock(buf: &mut [u8]) -> std::io::Result<()> {
    let result = unsafe {
        libsodium_sys::sodium_munlock(
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as libc::size_t,
        )
    };

    if result != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to unlock memory",
        ));
    }
    Ok(())
}

/// Increment a number (usually a nonce) stored as big-endian bytes
pub fn increment_be(n: &mut [u8]) {
    unsafe {
        libsodium_sys::sodium_increment(n.as_mut_ptr(), n.len());
    }
}

/// Add two numbers stored as big-endian bytes
///
/// This function adds two numbers stored as big-endian bytes. The result
/// is stored in the first array (`a`).
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut a = [0x01, 0x02, 0x03, 0x04];
/// let b = [0x00, 0x01, 0x00, 0x01];
///
/// utils::add_be(&mut a, &b);
/// assert_eq!(a, [0x01, 0x03, 0x03, 0x05]);
/// ```
///
/// # Arguments
/// * `a` - First number as big-endian bytes (will be modified to store the result)
/// * `b` - Second number as big-endian bytes
pub fn add_be(a: &mut [u8], b: &[u8]) {
    if a.len() != b.len() {
        return;
    }
    unsafe {
        libsodium_sys::sodium_add(a.as_mut_ptr(), b.as_ptr(), a.len());
    }
}

/// Subtract one number from another, both stored as big-endian bytes
///
/// This function subtracts the second number (`b`) from the first number (`a`),
/// both stored as big-endian bytes. The result is stored in the first array (`a`).
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut a = [0x01, 0x03, 0x03, 0x05];
/// let b = [0x00, 0x01, 0x00, 0x01];
///
/// utils::sub_be(&mut a, &b);
/// assert_eq!(a, [0x01, 0x02, 0x03, 0x04]);
/// ```
///
/// # Arguments
/// * `a` - First number as big-endian bytes (will be modified to store the result)
/// * `b` - Second number as big-endian bytes (will be subtracted from `a`)
pub fn sub_be(a: &mut [u8], b: &[u8]) {
    if a.len() != b.len() {
        return;
    }
    unsafe {
        libsodium_sys::sodium_sub(a.as_mut_ptr(), b.as_ptr(), a.len());
    }
}

/// Check if bytes is all zeros
///
/// This function checks if bytes contains only zeros. It is designed to be
/// constant-time regardless of the input data, which is important for security-sensitive
/// applications.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let zeros = [0, 0, 0, 0];
/// let non_zeros = [0, 0, 1, 0];
///
/// assert!(utils::is_zero(&zeros));
/// assert!(!utils::is_zero(&non_zeros));
/// ```
///
/// # Arguments
/// * `n` - The bytes to check
///
/// # Returns
/// * `bool` - `true` if the array contains only zeros, `false` otherwise
pub fn is_zero(n: &[u8]) -> bool {
    unsafe { libsodium_sys::sodium_is_zero(n.as_ptr(), n.len()) == 1 }
}

/// Compare two byte slices in lexicographical order
///
/// This function compares two byte slices in lexicographical order. It returns -1 if
/// the first array is less than the second, 1 if the first array is greater than the
/// second, and 0 if they are equal. If the shared prefix is equal, the shorter
/// slice is considered smaller.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let a = [0x01, 0x02, 0x03, 0x04];
/// let b = [0x01, 0x02, 0x03, 0x05];
/// let c = [0x01, 0x02, 0x03, 0x04];
///
/// assert_eq!(utils::compare(&a, &b), -1); // a < b
/// assert_eq!(utils::compare(&b, &a), 1);  // b > a
/// assert_eq!(utils::compare(&a, &c), 0);  // a == c
/// ```
///
/// # Arguments
/// * `a` - First bytes to compare
/// * `b` - Second bytes to compare
///
/// # Returns
/// * `i32` - -1 if a < b, 1 if a > b, 0 if a == b
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    let min_len = a.len().min(b.len());
    if min_len > 0 {
        let cmp = unsafe { libsodium_sys::sodium_compare(a.as_ptr(), b.as_ptr(), min_len) };
        if cmp != 0 {
            return cmp;
        }
    }

    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// Convert bytes to a hexadecimal string
///
/// This function converts bytes to a hexadecimal string representation.
/// Each byte is represented by two hexadecimal characters.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
/// let hex = utils::bin2hex(&bytes);
///
/// assert_eq!(hex, "deadbeef");
/// ```
///
/// # Arguments
/// * `bin` - The bytes to convert
///
/// # Returns
/// * `String` - The hexadecimal string representation
pub fn bin2hex(bin: &[u8]) -> String {
    let hex_len = bin.len() * 2 + 1;
    let mut hex = vec![0u8; hex_len];

    unsafe {
        libsodium_sys::sodium_bin2hex(hex.as_mut_ptr() as *mut _, hex_len, bin.as_ptr(), bin.len());
    }

    // Remove null terminator
    hex.pop();

    // This is safe because sodium_bin2hex guarantees valid UTF-8
    String::from_utf8(hex).unwrap()
}

/// Calculate the required length for Base64 encoding
///
/// This function calculates the required length for encoding a binary input
/// of the given length to Base64, including the null terminator.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let bin_len = 10;
/// let b64_len = utils::base64_encoded_len(bin_len, utils::BASE64_VARIANT_ORIGINAL);
///
/// // The exact length depends on the implementation details of libsodium
/// // and may vary between versions
/// ```
///
/// # Arguments
/// * `bin_len` - The length of the binary input
/// * `variant` - The Base64 encoding variant to use
///
/// # Returns
/// * `usize` - The required length for the Base64 encoding (including null terminator)
pub fn base64_encoded_len(bin_len: usize, variant: i32) -> usize {
    unsafe { libsodium_sys::sodium_base64_encoded_len(bin_len, variant) }
}

/// Convert bytes to a Base64 string
///
/// This function converts bytes to a Base64 string representation.
/// Different encoding variants are supported, including standard Base64 and
/// URL-safe Base64, with or without padding.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
///
/// // Standard Base64 encoding
/// let b64 = utils::bin2base64(&bytes, utils::BASE64_VARIANT_ORIGINAL);
/// assert_eq!(b64, "3q2+7w==");
///
/// // URL-safe Base64 encoding without padding
/// let b64_url = utils::bin2base64(&bytes, utils::BASE64_VARIANT_URLSAFE_NO_PADDING);
/// assert_eq!(b64_url, "3q2-7w");
/// ```
///
/// # Arguments
/// * `bin` - The bytes to convert
/// * `variant` - The Base64 encoding variant to use
///
/// # Returns
/// * `String` - The Base64 string representation
pub fn bin2base64(bin: &[u8], variant: i32) -> String {
    let b64_len = base64_encoded_len(bin.len(), variant);
    let mut b64 = vec![0u8; b64_len];

    unsafe {
        libsodium_sys::sodium_bin2base64(
            b64.as_mut_ptr() as *mut _,
            b64_len,
            bin.as_ptr(),
            bin.len(),
            variant,
        );
    }

    // Remove null terminator
    b64.pop();

    // This is safe because sodium_bin2base64 guarantees valid UTF-8
    String::from_utf8(b64).unwrap()
}

/// Convert a Base64 string to bytes
///
/// This function converts a Base64 string to its binary representation.
/// Different encoding variants are supported, including standard Base64 and
/// URL-safe Base64, with or without padding.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// // Standard Base64 encoding
/// let b64 = "3q2+7w==";
/// let bytes = utils::base642bin(b64, utils::BASE64_VARIANT_ORIGINAL).unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
///
/// // URL-safe Base64 encoding without padding
/// let b64_url = "3q2-7w";
/// let bytes = utils::base642bin(b64_url, utils::BASE64_VARIANT_URLSAFE_NO_PADDING).unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
///
/// # Arguments
/// * `b64` - The Base64 string to convert
/// * `variant` - The Base64 encoding variant to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The binary representation or an error
pub fn base642bin(b64: &str, variant: i32) -> Result<Vec<u8>> {
    let bin_maxlen = b64.len() * 3 / 4;
    let mut bin = vec![0u8; bin_maxlen];
    let mut bin_len = 0usize;

    let result = unsafe {
        libsodium_sys::sodium_base642bin(
            bin.as_mut_ptr(),
            bin_maxlen,
            b64.as_ptr() as *const _,
            b64.len(),
            ptr::null(),
            &mut bin_len,
            ptr::null_mut(),
            variant,
        )
    };

    if result != 0 {
        return Err(crate::SodiumError::InvalidInput(
            "invalid base64 string".into(),
        ));
    }

    bin.truncate(bin_len);
    Ok(bin)
}

/// Convert a hexadecimal string to bytes
///
/// This function converts a hexadecimal string to its binary representation.
/// It ignores characters specified in the ignore parameter.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let hex = "deadbeef";
/// let bytes = utils::hex2bin(hex).unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
///
/// // With ignored characters
/// let hex_with_colons = "de:ad:be:ef";
/// let bytes = utils::hex2bin_ignore(hex_with_colons, ":").unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
///
/// # Arguments
/// * `hex` - The hexadecimal string to convert
///
/// # Returns
/// * `Result<Vec<u8>>` - The binary representation or an error
pub fn hex2bin(hex: &str) -> Result<Vec<u8>> {
    hex2bin_ignore(hex, "")
}

/// Convert a hexadecimal string to bytes, ignoring specified characters
///
/// This function converts a hexadecimal string to its binary representation,
/// ignoring any characters specified in the `ignore` parameter.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// // With ignored characters
/// let hex_with_colons = "de:ad:be:ef";
/// let bytes = utils::hex2bin_ignore(hex_with_colons, ":").unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
///
/// // With spaces and colons
/// let hex_with_spaces = "de ad be:ef";
/// let bytes = utils::hex2bin_ignore(hex_with_spaces, ": ").unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
///
/// # Arguments
/// * `hex` - The hexadecimal string to convert
/// * `ignore` - Characters to ignore in the input string
///
/// # Returns
/// * `Result<Vec<u8>>` - The binary representation or an error
pub fn hex2bin_ignore(hex: &str, ignore: &str) -> Result<Vec<u8>> {
    let mut bin = vec![0u8; hex.len() / 2];
    let mut bin_len = 0usize;

    let ignore_ptr = if ignore.is_empty() {
        std::ptr::null()
    } else {
        ignore.as_ptr() as *const _
    };

    let result = unsafe {
        libsodium_sys::sodium_hex2bin(
            bin.as_mut_ptr(),
            bin.len(),
            hex.as_ptr() as *const _,
            hex.len(),
            ignore_ptr,
            &mut bin_len,
            std::ptr::null_mut(),
        )
    };

    if result != 0 {
        return Err(crate::SodiumError::InvalidInput(
            "invalid hex string".into(),
        ));
    }

    bin.truncate(bin_len);
    Ok(bin)
}

/// Secure memory allocation
///
/// This function allocates memory with extra protection, including:
/// - Protection against buffer overflows
/// - Protection against access after the memory is freed
/// - Automatic zeroing when freed
/// - Guarded pages to detect over/underflows
///
/// ## Security Considerations
///
/// - The allocated memory is automatically zeroed when freed
/// - The memory is protected from being swapped to disk
/// - This should be used for storing sensitive data like keys
///
/// ## Example
///
/// ```no_run
/// use libsodium_rs as sodium;
/// use sodium::utils;
/// use std::slice;
///
/// // Allocate 32 bytes of secure memory
/// let ptr = utils::malloc(32);
/// assert!(!ptr.is_null());
///
/// // Use the memory
/// unsafe {
///     let buf = slice::from_raw_parts_mut(ptr as *mut u8, 32);
///     // Fill with data...
///     for i in 0..32 {
///         buf[i] = i as u8;
///     }
/// }
///
/// // Free the memory (automatically zeroes it)
/// unsafe {
///     utils::free(ptr);
/// }
/// ```
///
/// # Arguments
/// * `size` - The number of bytes to allocate
///
/// # Returns
/// * `*mut libc::c_void` - A pointer to the allocated memory, or null if allocation failed
pub fn malloc(size: usize) -> *mut libc::c_void {
    unsafe { libsodium_sys::sodium_malloc(size) }
}

/// Allocate a buffer of a specific size and alignment
///
/// This function allocates a buffer with the specified size and alignment,
/// with the same protections as `malloc`.
///
/// ## Arguments
/// * `count` - The number of elements to allocate
/// * `size` - The size of each element
///
/// ## Returns
/// * `*mut libc::c_void` - A pointer to the allocated memory, or null if allocation failed
pub fn allocarray(count: usize, size: usize) -> *mut libc::c_void {
    unsafe { libsodium_sys::sodium_allocarray(count, size) }
}

/// Free memory allocated by sodium_malloc or sodium_allocarray
///
/// This function frees memory that was allocated by `malloc` or `allocarray`.
/// The memory is automatically zeroed before being freed.
///
/// ## Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and was allocated by `malloc` or `allocarray`.
///
/// ## Arguments
/// * `ptr` - A pointer to the memory to free
pub unsafe fn free(ptr: *mut libc::c_void) {
    unsafe { libsodium_sys::sodium_free(ptr) }
}

/// Make a region of memory inaccessible
///
/// This function makes a region of memory allocated with `malloc` or `allocarray`
/// completely inaccessible. It can be made accessible again with `mprotect_readwrite`
/// or `mprotect_readonly`.
///
/// ## Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and was allocated by `malloc` or `allocarray`.
///
/// ## Arguments
/// * `ptr` - A pointer to the memory region
///
/// ## Returns
/// * `i32` - 0 on success, -1 on failure
pub unsafe fn mprotect_noaccess(ptr: *mut libc::c_void) -> i32 {
    unsafe { libsodium_sys::sodium_mprotect_noaccess(ptr) }
}

/// Make a region of memory read-only
///
/// This function makes a region of memory allocated with `malloc` or `allocarray`
/// read-only. It can be made writable again with `mprotect_readwrite`.
///
/// ## Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and was allocated by `malloc` or `allocarray`.
///
/// ## Arguments
/// * `ptr` - A pointer to the memory region
///
/// ## Returns
/// * `i32` - 0 on success, -1 on failure
pub unsafe fn mprotect_readonly(ptr: *mut libc::c_void) -> i32 {
    unsafe { libsodium_sys::sodium_mprotect_readonly(ptr) }
}

/// Make a region of memory readable and writable
///
/// This function makes a region of memory allocated with `malloc` or `allocarray`
/// readable and writable.
///
/// ## Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and was allocated by `malloc` or `allocarray`.
///
/// ## Arguments
/// * `ptr` - A pointer to the memory region
///
/// ## Returns
/// * `i32` - 0 on success, -1 on failure
pub unsafe fn mprotect_readwrite(ptr: *mut libc::c_void) -> i32 {
    unsafe { libsodium_sys::sodium_mprotect_readwrite(ptr) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memcmp() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(memcmp(a, b));
        assert!(!memcmp(a, c));
    }

    #[test]
    fn test_memzero() {
        let mut buf = vec![1, 2, 3, 4, 5];
        memzero(&mut buf);
        assert_eq!(buf, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_increment_be() {
        let mut n = vec![0, 0, 0, 255];
        increment_be(&mut n);
        assert_eq!(n, vec![1, 0, 0, 255]);
    }

    #[test]
    fn test_hex_conversion() {
        let bin = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = bin2hex(&bin);
        assert_eq!(hex, "deadbeef");

        let bin2 = hex2bin(&hex).unwrap();
        assert_eq!(bin, bin2);

        // Test with ignored characters
        let hex_with_colons = "de:ad:be:ef";
        let bin3 = hex2bin_ignore(hex_with_colons, ":").unwrap();
        assert_eq!(bin, bin3);
    }

    #[test]
    fn test_base64() {
        let bin = [0xDE, 0xAD, 0xBE, 0xEF];

        // Test standard Base64
        let b64 = bin2base64(&bin, BASE64_VARIANT_ORIGINAL);
        assert_eq!(b64, "3q2+7w==");
        let bin2 = base642bin(&b64, BASE64_VARIANT_ORIGINAL).unwrap();
        assert_eq!(bin.to_vec(), bin2);

        // Test URL-safe Base64
        let b64_url = bin2base64(&bin, BASE64_VARIANT_URLSAFE);
        assert_eq!(b64_url, "3q2-7w==");
        let bin3 = base642bin(&b64_url, BASE64_VARIANT_URLSAFE).unwrap();
        assert_eq!(bin.to_vec(), bin3);

        // Test without padding
        let b64_no_pad = bin2base64(&bin, BASE64_VARIANT_ORIGINAL_NO_PADDING);
        assert_eq!(b64_no_pad, "3q2+7w");
        let bin4 = base642bin(&b64_no_pad, BASE64_VARIANT_ORIGINAL_NO_PADDING).unwrap();
        assert_eq!(bin.to_vec(), bin4);

        // Test base64_encoded_len
        // Just make sure it returns a reasonable value
        let len = base64_encoded_len(10, BASE64_VARIANT_ORIGINAL);
        assert!(len >= 14); // 10 bytes -> at least 14 base64 chars + null terminator
    }

    #[test]
    fn test_memory_locking() {
        let mut buf = vec![1, 2, 3, 4, 5];
        mlock(&mut buf).expect("Failed to lock memory");
        munlock(&mut buf).expect("Failed to unlock memory");
    }

    #[test]
    fn test_secure_memory_allocation() {
        // Test secure memory allocation
        let ptr = malloc(100);
        assert!(!ptr.is_null());

        // Test memory protection - these functions are now unsafe
        unsafe {
            let result = mprotect_noaccess(ptr);
            assert_eq!(result, 0);

            let result = mprotect_readonly(ptr);
            assert_eq!(result, 0);

            let result = mprotect_readwrite(ptr);
            assert_eq!(result, 0);

            // Free the memory
            free(ptr);
        }
    }
}
