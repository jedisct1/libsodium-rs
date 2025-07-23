//! # Version Information
//!
//! This module provides functions to query the version of the libsodium library.
//!
//! ## Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//!
//! // Get the version string of the libsodium library
//! let version = sodium::version::version_string();
//! println!("libsodium version: {}", version);
//!
//! // Get the major and minor version numbers
//! let major = sodium::version::library_version_major();
//! let minor = sodium::version::library_version_minor();
//! println!("libsodium version: {}.{}", major, minor);
//!
//! // Check if the library meets the minimum requirements
//! let is_minimal = sodium::version::library_minimal();
//! println!("Is minimal implementation: {}", is_minimal);
//! ```

/// The version string of the libsodium library (e.g., "1.0.20")
pub const VERSION_STRING: &str = "1.0.20";

/// The major version number of the libsodium library
pub const LIBRARY_VERSION_MAJOR: i32 = 26;

/// The minor version number of the libsodium library
pub const LIBRARY_VERSION_MINOR: i32 = 2;

/// Returns the version string of the libsodium library
///
/// This function returns the version string of the libsodium library, which
/// typically includes the major and minor version numbers.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
///
/// let version = sodium::version::version_string();
/// println!("libsodium version: {}", version);
/// ```
///
/// # Returns
/// * `&'static str` - The version string of the libsodium library
pub fn version_string() -> &'static str {
    unsafe {
        let ptr = libsodium_sys::sodium_version_string();
        std::ffi::CStr::from_ptr(ptr)
            .to_str()
            .unwrap_or(VERSION_STRING)
    }
}

/// Returns the major version number of the libsodium library
///
/// This function returns the major version number of the libsodium library.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
///
/// let major = sodium::version::library_version_major();
/// println!("libsodium major version: {}", major);
/// ```
///
/// # Returns
/// * `i32` - The major version number of the libsodium library
pub fn library_version_major() -> i32 {
    unsafe { libsodium_sys::sodium_library_version_major() }
}

/// Returns the minor version number of the libsodium library
///
/// This function returns the minor version number of the libsodium library.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
///
/// let minor = sodium::version::library_version_minor();
/// println!("libsodium minor version: {}", minor);
/// ```
///
/// # Returns
/// * `i32` - The minor version number of the libsodium library
pub fn library_version_minor() -> i32 {
    unsafe { libsodium_sys::sodium_library_version_minor() }
}

/// Checks if the library is a minimal implementation
///
/// This function checks if the library is a minimal implementation, which
/// means it only includes the core functionality needed for the most common
/// use cases.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
///
/// let is_minimal = sodium::version::library_minimal();
/// println!("Is minimal implementation: {}", is_minimal);
/// ```
///
/// # Returns
/// * `bool` - `true` if the library is a minimal implementation, `false` otherwise
pub fn library_minimal() -> bool {
    unsafe { libsodium_sys::sodium_library_minimal() != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_string() {
        let version = version_string();
        assert!(!version.is_empty());
        println!("libsodium version: {version}");
    }

    #[test]
    fn test_version_numbers() {
        let major = library_version_major();
        let minor = library_version_minor();
        assert!(major >= 0);
        assert!(minor >= 0);
        println!("libsodium version: {major}.{minor}");
    }

    #[test]
    fn test_library_minimal() {
        let is_minimal = library_minimal();
        println!("Is minimal implementation: {is_minimal}");
    }
}
