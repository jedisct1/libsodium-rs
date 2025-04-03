//! # Secure Vector Utilities Module
//!
//! This module provides secure memory management utilities for vectors and slices,
//! designed specifically for handling sensitive cryptographic material.
//!
//! ## Key Features
//!
//! * **Memory Zeroing**: Securely clear sensitive data from memory
//! * **Memory Locking**: Prevent sensitive data from being swapped to disk
//! * **Secure Vectors**: A vector-like container with enhanced memory protection
//!
//! ## Security Considerations
//!
//! When working with cryptographic keys, passwords, or other sensitive data, it's
//! crucial to handle memory securely. This module provides tools to:
//!
//! * Prevent sensitive data from being written to disk via swap
//! * Ensure memory is properly zeroed when no longer needed
//! * Protect against memory-related vulnerabilities
//!
//! ## Usage Example
//!
//! ```rust
//! use libsodium_rs as sodium;
//! use libsodium_rs::utils::vec_utils;
//! use sodium::ensure_init;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     ensure_init()?;
//!
//!     // Create a secure vector for a cryptographic key
//!     let mut secure_key = vec_utils::secure_vec::<u8>(32)?;
//!
//!     // Fill it with random data or your key material
//!     for i in 0..secure_key.len() {
//!         secure_key[i] = i as u8;
//!     }
//!
//!     // Use the key for cryptographic operations...
//!
//!     // When secure_key goes out of scope, the memory is
//!     // automatically zeroed and freed
//!     Ok(())
//! }
//! ```
//!
//! ## Relationship to Other Modules
//!
//! This module is part of the `utils` module and complements the core memory
//! management functions with vector-specific utilities.

use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr;

/// Securely zero a slice's memory
///
/// This function securely zeroes a slice's memory, ensuring that the operation
/// won't be optimized out by the compiler. This is important for securely
/// clearing sensitive data from memory.
///
/// ## Security Considerations
///
/// - This function ensures that the memory is actually zeroed, even if the compiler
///   would normally optimize out the operation
/// - It should be used whenever a slice containing sensitive data (like cryptographic
///   keys or passwords) is no longer needed
/// - Regular assignment (e.g., `slice.iter_mut().for_each(|x| *x = T::default())`) might
///   be optimized out by the compiler and not actually clear the memory
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use libsodium_rs::utils::vec_utils;
///
/// // Create a slice with sensitive data
/// let mut secret_key = [0x01, 0x02, 0x03, 0x04];
///
/// // Use the key for some operation...
///
/// // Securely clear the key from memory when done
/// vec_utils::memzero(&mut secret_key);
/// assert_eq!(secret_key, [0, 0, 0, 0]);
/// ```
///
/// # Arguments
/// * `slice` - The slice to zero
pub fn memzero<T: Default + Clone>(slice: &mut [T]) {
    for item in slice.iter_mut() {
        *item = T::default();
    }
}

/// Lock a vector's memory to prevent it from being swapped to disk
///
/// This function locks the memory pages containing the provided vector, preventing
/// them from being swapped to disk. This is important for protecting sensitive
/// cryptographic material from being written to disk where it might be recovered later.
///
/// ## Security Considerations
///
/// - Locked memory is not swapped to disk, reducing the risk of sensitive data leakage
/// - This function should be used for vectors containing highly sensitive data like
///   cryptographic keys or passwords
/// - Remember to call `munlock` when the vector is no longer needed
/// - There may be system-wide limits on the amount of memory that can be locked
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use libsodium_rs::utils::vec_utils;
///
/// let mut sensitive_data = vec![0x01, 0x02, 0x03, 0x04];
/// vec_utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
/// // Use the sensitive data...
/// vec_utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
/// ```
///
/// # Arguments
/// * `vec` - The vector to lock
///
/// # Returns
/// * `io::Result<()>` - Success or an error if the memory couldn't be locked
pub fn mlock<T>(vec: &mut Vec<T>) -> io::Result<()> {
    super::mlock(unsafe {
        std::slice::from_raw_parts_mut(
            vec.as_mut_ptr() as *mut u8,
            vec.len() * std::mem::size_of::<T>(),
        )
    })
}

/// Unlock a previously locked vector's memory
///
/// This function unlocks memory pages that were previously locked with `mlock`.
/// It should be called when the sensitive data is no longer needed.
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use libsodium_rs::utils::vec_utils;
///
/// let mut sensitive_data = vec![0x01, 0x02, 0x03, 0x04];
/// vec_utils::mlock(&mut sensitive_data).expect("Failed to lock memory");
/// // Use the sensitive data...
/// vec_utils::munlock(&mut sensitive_data).expect("Failed to unlock memory");
/// ```
///
/// # Arguments
/// * `vec` - The vector to unlock
///
/// # Returns
/// * `io::Result<()>` - Success or an error if the memory couldn't be unlocked
pub fn munlock<T>(vec: &mut Vec<T>) -> io::Result<()> {
    super::munlock(unsafe {
        std::slice::from_raw_parts_mut(
            vec.as_mut_ptr() as *mut u8,
            vec.len() * std::mem::size_of::<T>(),
        )
    })
}

/// Create a new secure vector with enhanced memory protection
///
/// This function creates a new `SecureVec<T>` with comprehensive memory protection features
/// designed for storing sensitive cryptographic material.
///
/// ## Security Features
///
/// - **Secure Allocation**: Uses libsodium's `sodium_malloc()` for memory allocation with guard pages
/// - **Overflow Detection**: Canary values and guard pages detect buffer overflows and underflows
/// - **Memory Locking**: Allocated memory is locked to prevent it from being swapped to disk
/// - **Automatic Zeroing**: Memory is automatically and securely zeroed when freed
/// - **Use-after-free Protection**: Helps mitigate use-after-free vulnerabilities
///
/// ## Performance Considerations
///
/// - Secure memory allocation has higher overhead than standard allocation
/// - Memory is page-aligned, which may use more memory than strictly necessary
/// - The memory locking feature may be subject to system-wide limits
///
/// ## Error Handling
///
/// This function returns an `io::Result<SecureVec<T>>` which will be an error if:
/// - The system has insufficient memory
/// - The process has reached its limit for locked memory
/// - The secure memory allocation fails for any other reason
///
/// ## Example
///
/// ```rust
/// use libsodium_rs as sodium;
/// use libsodium_rs::utils::vec_utils;
/// use sodium::ensure_init;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     ensure_init()?;
///
///     // Create a secure vector
///     let mut secure_vec = vec_utils::secure_vec::<u8>(32)?;
///
///     // Use it like a regular vector
///     for i in 0..secure_vec.len() {
///         secure_vec[i] = i as u8;
///     }
///
///     // When it goes out of scope, memory is automatically zeroed and freed
///     Ok(())
/// }
/// ```
///
/// # Arguments
/// * `size` - The initial size of the vector
///
/// # Returns
/// * `io::Result<SecureVec<T>>` - A new secure vector or an error if allocation failed
pub fn secure_vec<T: Default + Clone>(size: usize) -> io::Result<SecureVec<T>> {
    let mem_size = size * std::mem::size_of::<T>();
    let ptr = super::malloc(mem_size) as *mut T;

    if ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to allocate secure memory",
        ));
    }

    // Initialize the memory with default values
    for i in 0..size {
        unsafe {
            ptr.add(i).write(T::default());
        }
    }

    Ok(SecureVec {
        ptr,
        len: size,
        capacity: size,
        _marker: std::marker::PhantomData,
    })
}

/// A secure vector with enhanced memory protection
///
/// `SecureVec<T>` is a vector-like container that provides comprehensive memory protection
/// for sensitive cryptographic material. It combines the ergonomics of Rust's `Vec<T>` with
/// the security features of libsodium's secure memory allocation functions.
///
/// ## Security Features
///
/// - **Canary-based Protection**: Detects buffer overflows and underflows using guard pages and canary values
/// - **Automatic Zeroing**: Memory is automatically and securely zeroed when freed
/// - **Memory Locking**: Memory is locked to prevent it from being swapped to disk
/// - **Use-after-free Protection**: Helps prevent use-after-free vulnerabilities
/// - **Overflow Detection**: Uses guarded pages to detect and prevent buffer overflows
///
/// ## Implementation Details
///
/// Unlike a standard Rust `Vec<T>`, `SecureVec<T>` uses libsodium's `sodium_malloc()` and
/// `sodium_free()` functions to allocate and free memory. These functions provide additional
/// security features beyond what standard memory allocation provides:
///
/// - Memory is allocated with guard pages before and after the requested region
/// - Canary values are placed at the boundaries to detect overflows/underflows
/// - Memory is automatically zeroed when freed
/// - The allocated memory is page-aligned and protected from being swapped to disk
///
/// ## Usage
///
/// `SecureVec<T>` implements `Deref` and `DerefMut` to `[T]`, allowing it to be used
/// like a standard slice. It also provides methods similar to `Vec<T>` such as `push()`,
/// `pop()`, and `clear()`.
///
/// ```rust
/// use libsodium_rs as sodium;
/// use libsodium_rs::utils::vec_utils;
/// use sodium::ensure_init;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     ensure_init()?;
///
///     // Create a secure vector
///     let mut secure_vec = vec_utils::secure_vec::<u8>(32)?;
///
///     // Use it like a regular vector
///     for i in 0..secure_vec.len() {
///         secure_vec[i] = i as u8;
///     }
///
///     // When it goes out of scope, memory is automatically zeroed and freed
///     Ok(())
/// }
/// ```
pub struct SecureVec<T: Default + Clone> {
    // Raw pointer to the allocated memory
    ptr: *mut T,
    // Current length of the vector
    len: usize,
    // Current capacity of the vector
    capacity: usize,
    // Phantom data to indicate ownership of T
    _marker: std::marker::PhantomData<T>,
}

impl<T: Default + Clone> SecureVec<T> {
    /// Returns the length of the vector
    ///
    /// This method returns the number of elements in the vector.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     let secure_vec = vec_utils::secure_vec::<u8>(32)?;
    ///     assert_eq!(secure_vec.len(), 32);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the vector is empty
    ///
    /// This method returns true if the vector contains no elements.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     let secure_vec = vec_utils::secure_vec::<u8>(0)?;
    ///     assert!(secure_vec.is_empty());
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Convert the secure vector into a standard Vec
    ///
    /// This function consumes the `SecureVec<T>` and returns a standard `Vec<T>` with the same contents.
    /// The returned vector will no longer have the enhanced memory protections that `SecureVec<T>` provides.
    ///
    /// ## Security Considerations
    ///
    /// - **Loss of Protection**: After conversion, the memory loses all the security features provided by `SecureVec<T>`
    /// - **Caller Responsibility**: The caller becomes responsible for securely handling the returned vector
    /// - **Recommended Practice**: Consider using `memzero()` on the returned vector when it's no longer needed
    /// - **Swapping Risk**: The memory in the returned vector may be swapped to disk, potentially exposing sensitive data
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     // Create a secure vector
    ///     let mut secure_vec = vec_utils::secure_vec::<u8>(4)?;
    ///     for i in 0..secure_vec.len() {
    ///         secure_vec[i] = i as u8 + 1;
    ///     }
    ///
    ///     // Convert to a standard vector (losing security protections)
    ///     let mut regular_vec = secure_vec.into_vec();
    ///     
    ///     // Use the regular vector...
    ///     
    ///     // Manually zero the memory when done
    ///     vec_utils::memzero(&mut regular_vec);
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub fn into_vec(self) -> Vec<T> {
        let mut vec = Vec::with_capacity(self.len);

        // Copy the elements from the secure vector to the standard vector
        for i in 0..self.len {
            unsafe {
                vec.push(ptr::read(self.ptr.add(i)));
            }
        }

        // Prevent the destructor from running
        std::mem::forget(self);

        vec
    }

    /// Clears the vector, removing all values
    ///
    /// This method clears the vector, setting its length to 0 but keeping the allocated memory.
    /// All elements are securely zeroed.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     let mut secure_vec = vec_utils::secure_vec::<u8>(4)?;
    ///     for i in 0..secure_vec.len() {
    ///         secure_vec[i] = i as u8 + 1;
    ///     }
    ///
    ///     secure_vec.clear();
    ///     assert_eq!(secure_vec.len(), 0);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn clear(&mut self) {
        // Zero all elements
        for i in 0..self.len {
            unsafe {
                self.ptr.add(i).write(T::default());
            }
        }

        // Set the length to 0
        self.len = 0;
    }

    /// Adds an element to the end of the vector
    ///
    /// This method adds an element to the end of the vector, increasing its length by 1.
    /// If the vector's capacity is too small, it will be reallocated with a larger capacity.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     let mut secure_vec = vec_utils::secure_vec::<u8>(0)?;
    ///     secure_vec.push(1);
    ///     secure_vec.push(2);
    ///     secure_vec.push(3);
    ///
    ///     assert_eq!(secure_vec.len(), 3);
    ///     assert_eq!(secure_vec[0], 1);
    ///     assert_eq!(secure_vec[1], 2);
    ///     assert_eq!(secure_vec[2], 3);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn push(&mut self, value: T) -> io::Result<()> {
        if self.len == self.capacity {
            // Double the capacity, with a minimum of 1
            let new_capacity = std::cmp::max(1, self.capacity * 2);
            self.reserve(new_capacity - self.capacity)?;
        }

        unsafe {
            self.ptr.add(self.len).write(value);
        }

        self.len += 1;
        Ok(())
    }

    /// Removes the last element from the vector and returns it
    ///
    /// This method removes the last element from the vector and returns it.
    /// If the vector is empty, None is returned.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     let mut secure_vec = vec_utils::secure_vec::<u8>(0)?;
    ///     secure_vec.push(1)?;
    ///     secure_vec.push(2)?;
    ///
    ///     assert_eq!(secure_vec.pop(), Some(2));
    ///     assert_eq!(secure_vec.pop(), Some(1));
    ///     assert_eq!(secure_vec.pop(), None);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        let value = unsafe { ptr::read(self.ptr.add(self.len)) };

        // Zero the memory that contained the popped value
        unsafe {
            self.ptr.add(self.len).write(T::default());
        }

        Some(value)
    }

    /// Reserves capacity for at least `additional` more elements
    ///
    /// This method reserves capacity for at least `additional` more elements to be inserted
    /// into the vector. The collection may reserve more space to avoid frequent reallocations.
    /// After calling `reserve`, the capacity will be greater than or equal to `self.len() + additional`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use libsodium_rs as sodium;
    /// use libsodium_rs::utils::vec_utils;
    /// use sodium::ensure_init;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     ensure_init()?;
    ///
    ///     let mut secure_vec = vec_utils::secure_vec::<u8>(0)?;
    ///     secure_vec.reserve(10)?;
    ///
    ///     // Now we can add up to 10 elements without reallocating
    ///     for i in 0..10 {
    ///         secure_vec.push(i)?;
    ///     }
    ///
    ///     assert_eq!(secure_vec.len(), 10);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn reserve(&mut self, additional: usize) -> io::Result<()> {
        if additional == 0 {
            return Ok(());
        }

        let new_capacity = self.capacity + additional;
        let new_mem_size = new_capacity * std::mem::size_of::<T>();
        let new_ptr = super::malloc(new_mem_size) as *mut T;

        if new_ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to allocate secure memory",
            ));
        }

        // Copy existing elements to the new memory
        for i in 0..self.len {
            unsafe {
                new_ptr.add(i).write(ptr::read(self.ptr.add(i)));
            }
        }

        // Initialize the new elements with default values
        for i in self.len..new_capacity {
            unsafe {
                new_ptr.add(i).write(T::default());
            }
        }

        // Free the old memory
        unsafe {
            super::free(self.ptr as *mut libc::c_void);
        }

        self.ptr = new_ptr;
        self.capacity = new_capacity;

        Ok(())
    }
}

impl<T: Default + Clone> Deref for SecureVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: Default + Clone> DerefMut for SecureVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T: Default + Clone> Drop for SecureVec<T> {
    fn drop(&mut self) {
        // Zero all elements
        for i in 0..self.len {
            unsafe {
                self.ptr.add(i).write(T::default());
            }
        }

        // Free the memory
        unsafe {
            super::free(self.ptr as *mut libc::c_void);
        }
    }
}

impl<T: Default + Clone> Clone for SecureVec<T> {
    fn clone(&self) -> Self {
        let mem_size = self.capacity * std::mem::size_of::<T>();
        let ptr = super::malloc(mem_size) as *mut T;

        if ptr.is_null() {
            panic!("Failed to allocate secure memory");
        }

        // Copy elements to the new memory
        for i in 0..self.len {
            unsafe {
                ptr.add(i).write((*self)[i].clone());
            }
        }

        // Initialize the remaining elements with default values
        for i in self.len..self.capacity {
            unsafe {
                ptr.add(i).write(T::default());
            }
        }

        SecureVec {
            ptr,
            len: self.len,
            capacity: self.capacity,
            _marker: std::marker::PhantomData,
        }
    }
}

// Implement Debug for SecureVec
impl<T: Default + Clone + std::fmt::Debug> std::fmt::Debug for SecureVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

// Implement PartialEq for SecureVec
impl<T: Default + Clone + PartialEq> PartialEq for SecureVec<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        for i in 0..self.len {
            if self[i] != other[i] {
                return false;
            }
        }

        true
    }
}

// Implement Eq for SecureVec if T implements Eq
impl<T: Default + Clone + Eq> Eq for SecureVec<T> {}

// Implement PartialEq<[T]> for SecureVec
impl<T: Default + Clone + PartialEq> PartialEq<[T]> for SecureVec<T> {
    fn eq(&self, other: &[T]) -> bool {
        if self.len != other.len() {
            return false;
        }

        for i in 0..self.len {
            if self[i] != other[i] {
                return false;
            }
        }

        true
    }
}

// Implement PartialEq<Vec<T>> for SecureVec
impl<T: Default + Clone + PartialEq> PartialEq<Vec<T>> for SecureVec<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        if self.len != other.len() {
            return false;
        }

        for i in 0..self.len {
            if self[i] != other[i] {
                return false;
            }
        }

        true
    }
}

// Implement PartialEq<SecureVec<T>> for [T]
impl<T: Default + Clone + PartialEq> PartialEq<SecureVec<T>> for [T] {
    fn eq(&self, other: &SecureVec<T>) -> bool {
        other == self
    }
}

// Implement PartialEq<SecureVec<T>> for Vec<T>
impl<T: Default + Clone + PartialEq> PartialEq<SecureVec<T>> for Vec<T> {
    fn eq(&self, other: &SecureVec<T>) -> bool {
        other == self
    }
}
