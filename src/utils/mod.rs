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
//! - **Padding**: Functions for padding and unpadding buffers to a block boundary, which
//!   hides the exact length of a message before it is encrypted.
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

/// Increment a little-endian number in place, wrapping around on overflow.
///
/// This is libsodium's `sodium_increment`, usually applied to nonces.
/// It runs in constant time for a given length.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut nonce = [0xff, 0x00, 0x00];
/// utils::increment_le(&mut nonce);
/// assert_eq!(nonce, [0x00, 0x01, 0x00]);
/// ```
pub fn increment_le(n: &mut [u8]) {
    unsafe {
        libsodium_sys::sodium_increment(n.as_mut_ptr(), n.len());
    }
}

/// Add `b` to `a`, treating both as little-endian numbers.
///
/// This is libsodium's `sodium_add`, which runs in constant time for a given length.
/// Only the first `min(a.len(), b.len())` bytes of each operand are used.
/// The sum wraps around within those bytes: a carry out of them is discarded,
/// and the rest of `a` is left unchanged.
/// Use operands of the same length for ordinary modular addition.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut a = [0xff, 0x00, 0x00, 0x00];
/// utils::add_le(&mut a, &[0x01, 0x00, 0x00, 0x00]);
/// assert_eq!(a, [0x00, 0x01, 0x00, 0x00]);
/// ```
pub fn add_le(a: &mut [u8], b: &[u8]) {
    let len = a.len().min(b.len());
    unsafe {
        libsodium_sys::sodium_add(a.as_mut_ptr(), b.as_ptr(), len);
    }
}

/// Subtract `b` from `a`, treating both as little-endian numbers.
///
/// This is libsodium's `sodium_sub`, which runs in constant time for a given length.
/// Only the first `min(a.len(), b.len())` bytes of each operand are used.
/// The difference wraps around within those bytes: a borrow out of them is discarded,
/// and the rest of `a` is left unchanged.
/// Use operands of the same length for ordinary modular subtraction.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let mut a = [0x00, 0x01, 0x00, 0x00];
/// utils::sub_le(&mut a, &[0x01, 0x00, 0x00, 0x00]);
/// assert_eq!(a, [0xff, 0x00, 0x00, 0x00]);
/// ```
pub fn sub_le(a: &mut [u8], b: &[u8]) {
    let len = a.len().min(b.len());
    unsafe {
        libsodium_sys::sodium_sub(a.as_mut_ptr(), b.as_ptr(), len);
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

/// Compare two little-endian numbers in constant time.
///
/// This uses libsodium's `sodium_compare` and returns -1, 0 or 1 when `a` is
/// less than, equal to, or greater than `b`.
/// The last byte is the most significant one, so this is not lexicographic order.
///
/// Only the first `min(a.len(), b.len())` bytes are compared, and those are the
/// least significant bytes of each number.
/// If they are equal, the shorter slice is considered smaller.
/// Pass slices of the same length to compare them as numbers.
///
/// Comparing the shared bytes takes constant time for a given length.
/// The lengths themselves are not treated as secret.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
///
/// let a = [0x02, 0x01]; // 0x0102
/// let b = [0x01, 0x02]; // 0x0201
///
/// assert_eq!(utils::compare_le(&a, &b), -1);
/// assert_eq!(utils::compare_le(&b, &a), 1);
/// assert_eq!(utils::compare_le(&a, &a), 0);
/// ```
pub fn compare_le(a: &[u8], b: &[u8]) -> i32 {
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

    // sodium_bin2hex always yields valid UTF-8
    String::from_utf8(hex).expect("sodium_bin2hex returned invalid UTF-8")
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
    let bin_len = hex_bytes.len().div_ceil(2);
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
    let ignore_chars =
        std::ffi::CString::new(ignore).map_err(|_| crate::SodiumError::HexDecodingFailed)?;
    let bin_len = hex_bytes.len().div_ceil(2);
    let mut bin = vec![0u8; bin_len];
    let mut bin_len_ptr = bin_len;

    let result = unsafe {
        libsodium_sys::sodium_hex2bin(
            bin.as_mut_ptr(),
            bin_len,
            hex_bytes.as_ptr() as *const _,
            hex_bytes.len(),
            ignore_chars.as_ptr(),
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

    // sodium_bin2base64 always yields valid UTF-8
    String::from_utf8(b64).expect("sodium_bin2base64 returned invalid UTF-8")
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

/// Pad a buffer before encryption to hide its exact length.
///
/// Uses ISO/IEC 7816-4 padding to reach the next multiple of `blocksize`.
/// Adds a full block if `buf` is already aligned.
/// Remove the padding after decryption.
///
/// The encrypted message still reveals the number of padded blocks.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs::{ensure_init, utils};
///
/// ensure_init().unwrap();
///
/// let message = b"secret";
/// let padded = utils::pad(message, 16).unwrap();
/// assert_eq!(padded.len(), 16);
/// assert_eq!(utils::unpad(&padded, 16).unwrap(), message);
/// ```
///
/// With authenticated encryption:
///
/// ```rust
/// use libsodium_rs::{crypto_box, ensure_init, utils};
///
/// ensure_init().unwrap();
///
/// let recipient = crypto_box::KeyPair::generate();
/// let sender = crypto_box::KeyPair::generate();
/// let nonce = crypto_box::Nonce::generate();
///
/// let message = b"yes";
/// let padded = utils::pad(message, 64).unwrap();
/// let ciphertext = crypto_box::seal(
///     &padded, &nonce, &recipient.public_key, &sender.secret_key,
/// ).unwrap();
///
/// let opened = crypto_box::open(
///     &ciphertext, &nonce, &sender.public_key, &recipient.secret_key,
/// ).unwrap();
/// assert_eq!(utils::unpad(&opened, 64).unwrap(), message);
/// ```
///
/// # Errors
///
/// Returns [`SodiumError::InvalidPadding`] if `blocksize` is zero or the
/// padded buffer would be too large to allocate.
///
/// [`SodiumError::InvalidPadding`]: crate::SodiumError::InvalidPadding
pub fn pad(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
    if blocksize == 0 {
        return Err(crate::SodiumError::InvalidPadding);
    }

    let unpadded_len = buf.len();
    let padding_len = blocksize - unpadded_len % blocksize;
    let max_len = unpadded_len
        .checked_add(padding_len)
        .filter(|&len| len <= isize::MAX as usize)
        .ok_or(crate::SodiumError::InvalidPadding)?;
    let mut padded = vec![0u8; max_len];
    padded[..unpadded_len].copy_from_slice(buf);

    let mut padded_len = 0usize;
    let result = unsafe {
        libsodium_sys::sodium_pad(
            &mut padded_len,
            padded.as_mut_ptr(),
            unpadded_len,
            blocksize,
            max_len,
        )
    };

    if result != 0 {
        return Err(crate::SodiumError::InvalidPadding);
    }

    padded.truncate(padded_len);
    Ok(padded)
}

/// Remove ISO/IEC 7816-4 padding previously added by [`pad`]
///
/// This function verifies and strips the padding from `buf`, returning a new buffer with
/// the original, unpadded data. The padding bytes are validated during this process, so an
/// invalid trailing pattern is rejected rather than silently mistaken for data.
///
/// Padding must be removed *after* decryption: unpad the recovered plaintext, never the
/// ciphertext.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use sodium::utils;
/// use sodium::ensure_init;
///
/// ensure_init().unwrap();
///
/// let message = b"a slightly longer secret message";
/// let padded = utils::pad(message, 16).unwrap();
/// let unpadded = utils::unpad(&padded, 16).unwrap();
/// assert_eq!(unpadded, message);
/// ```
///
/// # Arguments
/// * `buf` - The padded data
/// * `blocksize` - The block size used when the data was padded; must be greater than zero
///
/// # Returns
/// * `Result<Vec<u8>>` - The unpadded data, or [`SodiumError::InvalidPadding`] if `blocksize`
///   is zero or the buffer does not contain valid padding
///
/// [`SodiumError::InvalidPadding`]: crate::SodiumError::InvalidPadding
pub fn unpad(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
    if blocksize == 0 {
        return Err(crate::SodiumError::InvalidPadding);
    }

    let padded_len = buf.len();
    let mut unpadded_len = 0usize;
    let result = unsafe {
        libsodium_sys::sodium_unpad(&mut unpadded_len, buf.as_ptr(), padded_len, blocksize)
    };

    if result != 0 {
        return Err(crate::SodiumError::InvalidPadding);
    }

    let mut unpadded = buf.to_vec();
    unpadded.truncate(unpadded_len);
    Ok(unpadded)
}

// Export the vec_utils module
pub mod vec_utils;

// Re-export SecureVec and secure_vec from vec_utils
pub use vec_utils::{secure_vec, SecureVec};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_little_endian_arithmetic_carries_and_wraps() {
        let mut n = [255, 0];
        increment_le(&mut n);
        assert_eq!(n, [0, 1]);
        let mut n = [255, 255];
        increment_le(&mut n);
        assert_eq!(n, [0, 0]);
        increment_le(&mut []);

        let mut a = [255, 0];
        add_le(&mut a, &[1, 0]);
        assert_eq!(a, [0, 1]);
        sub_le(&mut a, &[1, 0]);
        assert_eq!(a, [255, 0]);

        let mut a = [0, 0];
        sub_le(&mut a, &[1, 0]);
        assert_eq!(a, [255, 255]);
        add_le(&mut a, &[1, 0]);
        assert_eq!(a, [0, 0]);
    }

    #[test]
    fn test_little_endian_arithmetic_uses_shared_length() {
        let mut a = [255, 7];
        add_le(&mut a, &[1]);
        assert_eq!(a, [0, 7]);
        sub_le(&mut a, &[1]);
        assert_eq!(a, [255, 7]);

        let mut a = [1];
        add_le(&mut a, &[2, 9]);
        assert_eq!(a, [3]);
        sub_le(&mut a, &[1, 9]);
        assert_eq!(a, [2]);

        add_le(&mut a, &[]);
        sub_le(&mut a, &[]);
        assert_eq!(a, [2]);
        add_le(&mut [], &[1]);
        sub_le(&mut [], &[1]);
    }

    fn reference_add_le(a: &mut [u8], b: &[u8], subtract: bool) {
        let mut carry = 0i16;
        for (x, &y) in a.iter_mut().zip(b) {
            let v = if subtract {
                i16::from(*x) - i16::from(y) - carry
            } else {
                i16::from(*x) + i16::from(y) + carry
            };
            *x = v as u8;
            carry = i16::from(!(0..=255).contains(&v));
        }
    }

    #[test]
    fn test_little_endian_helpers_match_reference() {
        // 8, 12 and 24 bytes take dedicated native code paths on x86_64.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for len in [1, 7, 8, 12, 16, 24, 32] {
            let mut samples = vec![vec![0u8; len], vec![0xff; len]];
            let mut top = vec![0u8; len];
            top[len - 1] = 0x80;
            samples.push(top);
            for _ in 0..6 {
                samples.push(
                    (0..len)
                        .map(|_| {
                            seed ^= seed << 13;
                            seed ^= seed >> 7;
                            seed ^= seed << 17;
                            seed as u8
                        })
                        .collect(),
                );
            }
            let mut one = vec![0u8; len];
            one[0] = 1;
            for x in &samples {
                let mut n = x.clone();
                let mut expected = x.clone();
                increment_le(&mut n);
                reference_add_le(&mut expected, &one, false);
                assert_eq!(n, expected);
                for y in &samples {
                    for subtract in [false, true] {
                        let mut a = x.clone();
                        let mut expected = x.clone();
                        if subtract {
                            sub_le(&mut a, y);
                        } else {
                            add_le(&mut a, y);
                        }
                        reference_add_le(&mut expected, y, subtract);
                        assert_eq!(a, expected);
                    }
                    let expected = x.iter().rev().cmp(y.iter().rev()) as i32;
                    assert_eq!(compare_le(x, y), expected);
                }
            }
        }
    }

    #[test]
    fn test_compare_le_length_rule() {
        assert_eq!(compare_le(&[2, 1], &[1, 2]), -1);
        assert_eq!(compare_le(&[5], &[5, 0]), -1);
        assert_eq!(compare_le(&[5, 0], &[5]), 1);
        assert_eq!(compare_le(&[6], &[5, 9]), 1);
        assert_eq!(compare_le(&[], &[0]), -1);
        assert_eq!(compare_le(&[], &[]), 0);
    }

    #[test]
    fn test_hex_ignore_is_bounded_and_rejects_nul() {
        let backing = String::from(":x\0");
        assert_eq!(
            hex2bin_ignore("dexad", &backing[..1]),
            Err(crate::SodiumError::HexDecodingFailed)
        );
        assert_eq!(
            hex2bin_ignore("de:ad", &backing[..1]).unwrap(),
            [0xde, 0xad]
        );
        assert_eq!(hex2bin_ignore("dead", "").unwrap(), [0xde, 0xad]);
        assert_eq!(
            hex2bin_ignore("de:ad", "\0:"),
            Err(crate::SodiumError::HexDecodingFailed)
        );
    }

    #[test]
    fn test_pad_rejects_unrepresentable_sizes() {
        for blocksize in [usize::MAX, isize::MAX as usize + 1] {
            assert_eq!(
                pad(b"a", blocksize),
                Err(crate::SodiumError::InvalidPadding)
            );
            assert_eq!(pad(b"", blocksize), Err(crate::SodiumError::InvalidPadding));
        }
    }

    #[test]
    fn test_pad_rounds_up_to_block_boundary() {
        let message = b"secret";
        let padded = pad(message, 16).unwrap();
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..message.len()], message);

        let unpadded = unpad(&padded, 16).unwrap();
        assert_eq!(unpadded, message);
    }

    #[test]
    fn test_pad_adds_full_block_when_already_aligned() {
        // ISO/IEC 7816-4 always writes at least the 0x80 marker, so an already
        // aligned buffer grows by a whole block.
        let message = [0u8; 16];
        let padded = pad(&message, 16).unwrap();
        assert_eq!(padded.len(), 32);
        assert_eq!(unpad(&padded, 16).unwrap(), message);
    }

    #[test]
    fn test_pad_empty_buffer() {
        let padded = pad(b"", 8).unwrap();
        assert_eq!(padded.len(), 8);
        assert_eq!(unpad(&padded, 8).unwrap(), b"");
    }

    #[test]
    fn test_pad_various_lengths_roundtrip() {
        for len in 0..40usize {
            let message: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pad(&message, 16).unwrap();
            assert!(padded.len() > message.len());
            assert_eq!(padded.len() % 16, 0);
            assert_eq!(unpad(&padded, 16).unwrap(), message);
        }
    }

    #[test]
    fn test_unpad_rejects_invalid_padding() {
        // A buffer that does not end with a valid padding marker is rejected.
        let invalid = [0u8; 16];
        assert_eq!(unpad(&invalid, 16), Err(crate::SodiumError::InvalidPadding));
    }

    #[test]
    fn test_zero_blocksize_is_rejected() {
        assert_eq!(pad(b"data", 0), Err(crate::SodiumError::InvalidPadding));
        assert_eq!(unpad(b"data", 0), Err(crate::SodiumError::InvalidPadding));
    }
}
