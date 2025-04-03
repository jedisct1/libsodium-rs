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
/// - This function ensures that the memory is actually zeroed, even if the compiler
///   would normally optimize out the operation
/// - It should be used whenever a byte slice containing sensitive data (like cryptographic
///   keys or passwords) is no longer needed
/// - Regular assignment (e.g., `slice = [0; len]`) might be optimized out by the
///   compiler and not actually clear the memory
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// // Create a slice with sensitive data
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
/// data from the stack before returning from a function.
///
/// ## Security Considerations
///
/// - This function ensures that the stack memory is actually zeroed, even if the compiler
///   would normally optimize out the operation
/// - It should be used when sensitive data is stored on the stack and needs to be cleared
///   before returning from a function
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// fn process_sensitive_data() {
///     // Create sensitive data on the stack
///     let sensitive_data = [0x01, 0x02, 0x03, 0x04];
///
///     // Use the data for some operation...
///
///     // Securely clear the data from the stack
///     utils::stackzero(sensitive_data.len());
/// }
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
/// them from being swapped to disk. This is important for protecting sensitive
/// cryptographic material from being written to disk where it might be recovered later.
///
/// ## Security Considerations
///
/// - Locked memory is not swapped to disk, reducing the risk of sensitive data leakage
/// - This function should be used for byte slices containing highly sensitive data like
///   cryptographic keys or passwords
/// - Remember to call `munlock` when the byte slice is no longer needed
/// - There may be system-wide limits on the amount of memory that can be locked
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut sensitive_data = [0x01, 0x02, 0x03, 0x04];
/// utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
/// // Use the sensitive data...
/// utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
/// ```
pub fn mlock(buf: &mut [u8]) -> std::io::Result<()> {
    let result = unsafe { libsodium_sys::sodium_mlock(buf.as_mut_ptr() as *mut _, buf.len()) };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Unlock previously locked memory pages
///
/// This function unlocks memory pages that were previously locked with `mlock`.
/// It should be called when the sensitive data is no longer needed.
///
/// # Returns
///
/// * `io::Result<()>` - Success or an error if the memory couldn't be unlocked
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut sensitive_data = [0x01, 0x02, 0x03, 0x04];
/// utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
/// // Use the sensitive data...
/// utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
/// ```
pub fn munlock(buf: &mut [u8]) -> std::io::Result<()> {
    let result = unsafe { libsodium_sys::sodium_munlock(buf.as_mut_ptr() as *mut _, buf.len()) };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Increment a number (usually a nonce) stored as big-endian bytes
pub fn increment_be(n: &mut [u8]) {
    unsafe {
        libsodium_sys::sodium_increment(n.as_mut_ptr(), n.len());
    }
}

/// Add two numbers stored as big-endian bytes
///
/// This function adds two numbers stored as big-endian byte arrays. The result
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
/// utils::add_be(&mut a, &b);
/// assert_eq!(a, [0x01, 0x03, 0x03, 0x05]);
/// ```
///
/// # Arguments
/// * `a` - First number as big-endian bytes (will be modified to store the result)
/// * `b` - Second number as big-endian bytes
pub fn add_be(a: &mut [u8], b: &[u8]) {
    unsafe {
        libsodium_sys::sodium_add(a.as_mut_ptr(), b.as_ptr(), a.len().min(b.len()));
    }
}

/// Subtract one number from another, both stored as big-endian bytes
///
/// This function subtracts the second number (`b`) from the first number (`a`),
/// both stored as big-endian byte arrays. The result is stored in the first array (`a`).
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut a = [0x01, 0x03, 0x03, 0x05];
/// let b = [0x00, 0x01, 0x00, 0x01];
/// utils::sub_be(&mut a, &b);
/// assert_eq!(a, [0x01, 0x02, 0x03, 0x04]);
/// ```
///
/// # Arguments
/// * `a` - First number as big-endian bytes (will be modified to store the result)
/// * `b` - Second number as big-endian bytes (will be subtracted from `a`)
pub fn sub_be(a: &mut [u8], b: &[u8]) {
    unsafe {
        libsodium_sys::sodium_sub(a.as_mut_ptr(), b.as_ptr(), a.len().min(b.len()));
    }
}

/// Check if a byte array is all zeros
///
/// This function checks if a byte array contains only zeros. It is designed to be
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
/// * `n` - The byte array to check
///
/// # Returns
/// * `bool` - `true` if the array contains only zeros, `false` otherwise
pub fn is_zero(n: &[u8]) -> bool {
    unsafe { libsodium_sys::sodium_is_zero(n.as_ptr(), n.len()) == 1 }
}

/// Compare two byte arrays in lexicographical order
///
/// This function compares two byte arrays in lexicographical order. It returns -1 if
/// the first array is less than the second, 1 if the first array is greater than the
/// second, and 0 if the arrays are equal.
///
/// ## Security Considerations
///
/// - This function is constant-time, which is important for security-sensitive applications
/// - It should be used when comparing sensitive data that requires a lexicographical
///   comparison rather than just equality testing
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let a = [0x01, 0x02, 0x03, 0x04];
/// let b = [0x01, 0x02, 0x03, 0x05];
/// let c = [0x01, 0x02, 0x03, 0x03];
///
/// assert_eq!(utils::compare(&a, &b), -1); // a < b
/// assert_eq!(utils::compare(&b, &a), 1);  // b > a
/// assert_eq!(utils::compare(&a, &a), 0);  // a == a
/// assert_eq!(utils::compare(&a, &c), 1);  // a > c
/// ```
///
/// # Arguments
/// * `a` - First byte array to compare
/// * `b` - Second byte array to compare
///
/// # Returns
/// * `i32` - -1 if a < b, 1 if a > b, 0 if a == b
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    unsafe { libsodium_sys::sodium_compare(a.as_ptr(), b.as_ptr(), a.len().min(b.len())) }
}

/// Convert binary data to a hexadecimal string
///
/// This function converts a byte array to a hexadecimal string representation.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let binary = [0xDE, 0xAD, 0xBE, 0xEF];
/// let hex = utils::bin2hex(&binary);
/// assert_eq!(hex, "deadbeef");
/// ```
///
/// # Arguments
/// * `bin` - The binary data to convert
///
/// # Returns
/// * `String` - The hexadecimal representation of the binary data
pub fn bin2hex(bin: &[u8]) -> String {
    let hex_len = bin.len() * 2 + 1;
    let mut hex = vec![0u8; hex_len];

    unsafe {
        libsodium_sys::sodium_bin2hex(hex.as_mut_ptr() as *mut _, hex_len, bin.as_ptr(), bin.len());
    }

    // Remove the null terminator
    hex.pop();

    // Convert to a String
    String::from_utf8(hex).unwrap_or_else(|_| String::new())
}

/// Calculate the length of a hexadecimal string needed to encode binary data
///
/// This function calculates the length of a hexadecimal string needed to encode
/// binary data of a given length.
///
/// # Arguments
/// * `bin_len` - The length of the binary data
///
/// # Returns
/// * `usize` - The length of the hexadecimal string, including the null terminator
pub fn hex_encoded_len(bin_len: usize) -> usize {
    bin_len * 2 + 1
}

/// Convert a hexadecimal string to binary data
///
/// This function converts a hexadecimal string to binary data.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let hex = "deadbeef";
/// let binary = utils::hex2bin(hex).unwrap();
/// assert_eq!(binary, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
///
/// # Arguments
/// * `hex` - The hexadecimal string to convert
///
/// # Returns
/// * `Result<Vec<u8>>` - The binary data or an error if the string is not valid hexadecimal
pub fn hex2bin(hex: &str) -> Result<Vec<u8>> {
    let hex_bytes = hex.as_bytes();
    let bin_len = (hex_bytes.len() + 1) / 2;
    let mut bin = vec![0u8; bin_len];
    let mut bin_len_ptr = bin_len;

    let result = unsafe {
        libsodium_sys::sodium_hex2bin(
            bin.as_mut_ptr(),
            bin_len,
            hex_bytes.as_ptr() as *const _,
            hex_bytes.len(),
            std::ptr::null_mut(),
            &mut bin_len_ptr,
            std::ptr::null_mut(),
        )
    };

    if result != 0 {
        return Err(crate::SodiumError::HexDecodingFailed);
    }

    bin.truncate(bin_len_ptr);
    Ok(bin)
}

/// Convert a hexadecimal string to binary data, ignoring specified characters
///
/// This function converts a hexadecimal string to binary data, ignoring any characters
/// specified in the `ignore` parameter.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let hex = "de:ad:be:ef";
/// let binary = utils::hex2bin_ignore(hex, ":").unwrap();
/// assert_eq!(binary, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
///
/// # Arguments
/// * `hex` - The hexadecimal string to convert
/// * `ignore` - Characters to ignore in the hexadecimal string
///
/// # Returns
/// * `Result<Vec<u8>>` - The binary data or an error if the string is not valid hexadecimal
pub fn hex2bin_ignore(hex: &str, ignore: &str) -> Result<Vec<u8>> {
    let hex_bytes = hex.as_bytes();
    let ignore_bytes = ignore.as_bytes();
    let bin_len = (hex_bytes.len() + 1) / 2;
    let mut bin = vec![0u8; bin_len];
    let mut bin_len_ptr = bin_len;

    let result = unsafe {
        libsodium_sys::sodium_hex2bin(
            bin.as_mut_ptr(),
            bin_len,
            hex_bytes.as_ptr() as *const _,
            hex_bytes.len(),
            ignore_bytes.as_ptr() as *const _,
            &mut bin_len_ptr,
            std::ptr::null_mut(),
        )
    };

    if result != 0 {
        return Err(crate::SodiumError::HexDecodingFailed);
    }

    bin.truncate(bin_len_ptr);
    Ok(bin)
}

/// Calculate the length of a Base64 string needed to encode binary data
///
/// This function calculates the length of a Base64 string needed to encode
/// binary data of a given length, using the specified variant.
///
/// # Arguments
/// * `bin_len` - The length of the binary data
/// * `variant` - The Base64 variant to use
///
/// # Returns
/// * `usize` - The length of the Base64 string, including the null terminator
pub fn base64_encoded_len(bin_len: usize, variant: i32) -> usize {
    unsafe { libsodium_sys::sodium_base64_encoded_len(bin_len, variant) }
}

/// Convert binary data to a Base64 string
///
/// This function converts a byte array to a Base64 string representation,
/// using the specified variant.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let binary = [0xDE, 0xAD, 0xBE, 0xEF];
/// let b64 = utils::bin2base64(&binary, utils::BASE64_VARIANT_ORIGINAL);
/// assert_eq!(b64, "3q2+7w==");
/// ```
///
/// # Arguments
/// * `bin` - The binary data to convert
/// * `variant` - The Base64 variant to use
///
/// # Returns
/// * `String` - The Base64 representation of the binary data
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

    // Find the null terminator
    let null_pos = b64.iter().position(|&x| x == 0).unwrap_or(b64.len());
    b64.truncate(null_pos);

    // Convert to a String
    String::from_utf8(b64).unwrap_or_else(|_| String::new())
}

/// Convert a Base64 string to binary data
///
/// This function converts a Base64 string to binary data, using the specified variant.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let b64 = "3q2+7w==";
/// let binary = utils::base642bin(b64, utils::BASE64_VARIANT_ORIGINAL).unwrap();
/// assert_eq!(binary, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
///
/// # Arguments
/// * `b64` - The Base64 string to convert
/// * `variant` - The Base64 variant to use
///
/// # Returns
/// * `Result<Vec<u8>>` - The binary data or an error if the string is not valid Base64
pub fn base642bin(b64: &str, variant: i32) -> Result<Vec<u8>> {
    let b64_bytes = b64.as_bytes();
    let bin_len = (b64_bytes.len() * 3) / 4 + 1;
    let mut bin = vec![0u8; bin_len];
    let mut bin_len_ptr = bin_len;

    let result = unsafe {
        libsodium_sys::sodium_base642bin(
            bin.as_mut_ptr(),
            bin_len,
            b64_bytes.as_ptr() as *const _,
            b64_bytes.len(),
            std::ptr::null_mut(),
            &mut bin_len_ptr,
            std::ptr::null_mut(),
            variant,
        )
    };

    if result != 0 {
        return Err(crate::SodiumError::Base64DecodingFailed);
    }

    bin.truncate(bin_len_ptr);
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

/// Allocate an array of elements with secure memory
///
/// This function allocates an array of elements with secure memory protection.
/// It is similar to `malloc`, but allocates an array of elements instead of a
/// single block of memory.
///
/// ## Safety
/// This function is unsafe because it returns a raw pointer.
/// The caller is responsible for freeing the memory with `free`.
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
/// inaccessible. It can be made accessible again with `mprotect_readwrite`.
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

// Export the vec_utils module
pub mod vec_utils;

// Re-export SecureVec and secure_vec from vec_utils
pub use vec_utils::{secure_vec, SecureVec};
