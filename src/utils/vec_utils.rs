//! Secure erasure, memory locking, and guarded storage for vectors and slices.
//!
//! [`SecureVec`] zeroizes live elements before dropping them.
//! Its guards and best-effort locks cover element storage, not heap buffers
//! owned by elements.
//!
//! ```rust
//! use libsodium_rs::{ensure_init, utils::vec_utils};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! ensure_init()?;
//! let mut key = vec_utils::secure_vec::<u8>(32)?;
//! key.fill(0x42);
//! # Ok(())
//! # }
//! ```

use std::alloc::Layout;
use std::io;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr::{self, NonNull};
use zeroize::Zeroize;

/// Erase each element using its [`Zeroize`] implementation.
///
/// Owned buffers are erased as that implementation allows, without replacing
/// elements with defaults or overwriting their raw representations.
///
/// ```rust
/// use libsodium_rs::utils::vec_utils;
///
/// let mut key = [1u8, 2, 3, 4];
/// vec_utils::memzero(&mut key);
/// assert_eq!(key, [0; 4]);
/// ```
pub fn memzero<T: Zeroize>(slice: &mut [T]) {
    slice.iter_mut().zeroize();
}

/// Lock a byte vector's live contents against swapping.
///
/// Reallocation does not preserve the lock.
/// Operating-system limits may prevent locking.
/// [`munlock`] erases the bytes and releases the lock.
///
/// ```rust,no_run
/// use libsodium_rs::{ensure_init, utils::vec_utils};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// ensure_init()?;
/// let mut key = vec![1u8, 2, 3, 4];
/// vec_utils::mlock(&mut key)?;
/// vec_utils::munlock(&mut key)?;
/// assert_eq!(key, [0; 4]);
/// # Ok(())
/// # }
/// ```
///
/// Other element types are rejected, since they could never be unlocked:
///
/// ```compile_fail
/// use libsodium_rs::utils::vec_utils;
///
/// let mut strings = vec![String::from("secret")];
/// vec_utils::mlock(&mut strings).unwrap();
/// ```
pub fn mlock(vec: &mut Vec<u8>) -> io::Result<()> {
    if vec.is_empty() {
        return Ok(());
    }
    super::mlock(vec.as_mut_slice())
}

/// Erase a byte vector's live contents and unlock their memory pages.
///
/// The bytes are erased even if unlocking fails; spare capacity is untouched.
/// Other element types are not supported because zeroing their storage can
/// make them invalid Rust values.
///
/// ```compile_fail
/// use libsodium_rs::utils::vec_utils;
///
/// let mut strings = vec![String::from("secret")];
/// vec_utils::munlock(&mut strings).unwrap();
/// ```
pub fn munlock(vec: &mut Vec<u8>) -> io::Result<()> {
    if vec.is_empty() {
        return Ok(());
    }
    super::munlock(vec.as_mut_slice())
}

struct SecureAllocation {
    base: NonNull<libc::c_void>,
}

impl Drop for SecureAllocation {
    fn drop(&mut self) {
        unsafe { super::free(self.base.as_ptr()) };
    }
}

fn capacity_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Secure vector capacity overflow",
    )
}

/// Create a guarded vector filled with default values.
///
/// Invalid sizes and allocation failures return an error.
/// If `Default` panics, initialized elements are zeroized and dropped,
/// and the guarded allocation is freed.
///
/// See [`SecureVec`] for memory-protection limits.
/// Storage is aligned for `T`, but need not be page-aligned.
/// Empty vectors and zero-sized elements need no guarded allocation.
///
/// ```rust
/// use libsodium_rs::{ensure_init, utils::vec_utils};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// ensure_init()?;
/// let key = vec_utils::secure_vec::<u8>(32)?;
/// assert_eq!(key.len(), 32);
/// assert!(key.iter().all(|&byte| byte == 0));
/// # Ok(())
/// # }
/// ```
pub fn secure_vec<T: Zeroize + Default>(size: usize) -> io::Result<SecureVec<T>> {
    let mut values = SecureVec::<T>::with_capacity(size)?;
    for _ in 0..size {
        let value = T::default();
        unsafe { values.ptr.add(values.len).write(value) };
        values.len += 1;
    }
    Ok(values)
}

/// A vector whose element storage uses libsodium's guarded allocator.
///
/// Only live elements are initialized; removal and destruction create no defaults.
/// Each element is zeroized before its destructor runs during [`clear`](Self::clear)
/// or drop.
/// Spare capacity is erased when the allocation is freed.
///
/// Guard pages and a canary cannot detect every out-of-bounds access,
/// especially when alignment padding separates elements from the guards.
/// Memory locking is best effort and may fail under operating-system limits.
/// Guards and locks do not cover heap buffers owned by elements.
/// Element erasure, including owned buffers, depends on [`Zeroize`].
///
/// If zeroization or a destructor panics, remaining elements may leak,
/// but are never dropped twice.
/// The allocation is still freed when the vector is dropped, even during unwinding.
///
/// ```rust
/// use libsodium_rs::{ensure_init, utils::vec_utils};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// ensure_init()?;
/// let mut key = vec_utils::secure_vec::<u8>(0)?;
/// key.push(7)?;
/// assert_eq!(&*key, &[7]);
/// key.clear();
/// assert!(key.is_empty());
/// # Ok(())
/// # }
/// ```
pub struct SecureVec<T: Zeroize> {
    ptr: *mut T,
    len: usize,
    capacity: usize,
    _allocation: Option<SecureAllocation>,
    _marker: PhantomData<T>,
}

impl<T: Zeroize> SecureVec<T> {
    /// Create an empty vector with room for `capacity` elements.
    ///
    /// Unlike [`secure_vec`], this needs no `Default` implementation.
    /// Invalid sizes and allocation failures return an error.
    ///
    /// ```rust
    /// use libsodium_rs::{ensure_init, utils::vec_utils::SecureVec};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// ensure_init()?;
    /// let mut values = SecureVec::<u8>::with_capacity(4)?;
    /// assert!(values.is_empty());
    /// values.push(1)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_capacity(capacity: usize) -> io::Result<Self> {
        let layout = Layout::array::<T>(capacity).map_err(|_| capacity_error())?;
        if layout.size() == 0 {
            return Ok(Self {
                ptr: NonNull::<T>::dangling().as_ptr(),
                len: 0,
                capacity,
                _allocation: None,
                _marker: PhantomData,
            });
        }

        let padding = layout.align() - 1;
        let byte_len = layout
            .size()
            .checked_add(padding)
            .ok_or_else(capacity_error)?;
        let base = NonNull::new(super::malloc(byte_len))
            .ok_or_else(|| io::Error::other("Failed to allocate secure memory"))?;
        let allocation = SecureAllocation { base };
        let bytes = base.as_ptr().cast::<u8>();
        let offset = bytes.align_offset(layout.align());
        if offset > padding {
            return Err(io::Error::other("Failed to align secure memory"));
        }
        let ptr = unsafe { bytes.add(offset).cast::<T>() };
        Ok(Self {
            ptr,
            len: 0,
            capacity,
            _allocation: Some(allocation),
            _marker: PhantomData,
        })
    }

    /// Return the number of live elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Move elements into an ordinary `Vec` and free the guarded allocation.
    ///
    /// The returned vector neither locks nor automatically erases its storage.
    /// The caller is responsible for keeping the data secure.
    ///
    /// ```rust
    /// use libsodium_rs::{ensure_init, utils::vec_utils};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// ensure_init()?;
    /// let mut secure = vec_utils::secure_vec::<u8>(2)?;
    /// secure.copy_from_slice(&[1, 2]);
    /// let mut ordinary = secure.into_vec();
    /// assert_eq!(ordinary, [1, 2]);
    /// vec_utils::memzero(&mut ordinary);
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_vec(mut self) -> Vec<T> {
        let mut values = Vec::with_capacity(self.len);
        unsafe {
            ptr::copy_nonoverlapping(self.ptr, values.as_mut_ptr(), self.len);
            let len = std::mem::replace(&mut self.len, 0);
            values.set_len(len);
        }
        values
    }

    /// Zeroize and drop every live element, retaining the allocated capacity.
    ///
    /// No default values are constructed.
    /// If zeroization or a destructor panics, the vector remains empty and the
    /// remaining elements may be leaked rather than dropped again.
    pub fn clear(&mut self) {
        let len = std::mem::replace(&mut self.len, 0);
        for i in 0..len {
            unsafe {
                let item = self.ptr.add(i);
                (*item).zeroize();
                ptr::drop_in_place(item);
            }
        }
    }

    /// Append an element, growing the guarded allocation if necessary.
    ///
    /// Capacity overflow and allocation failure return an error without changing
    /// the existing elements.
    /// The rejected value is zeroized before it is dropped.
    ///
    /// ```rust
    /// use libsodium_rs::{ensure_init, utils::vec_utils};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// ensure_init()?;
    /// let mut values = vec_utils::secure_vec::<u8>(0)?;
    /// values.push(1)?;
    /// values.push(2)?;
    /// assert_eq!(&*values, &[1, 2]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn push(&mut self, mut value: T) -> io::Result<()> {
        if let Err(error) = self.reserve_for_push() {
            value.zeroize();
            return Err(error);
        }
        unsafe { self.ptr.add(self.len).write(value) };
        self.len += 1;
        Ok(())
    }

    fn reserve_for_push(&mut self) -> io::Result<()> {
        let len = self.len.checked_add(1).ok_or_else(capacity_error)?;
        if len > self.capacity {
            let capacity = self.capacity.checked_mul(2).unwrap_or(len).max(len);
            self.reserve(capacity - self.len)?;
        }
        Ok(())
    }

    /// Remove and return the last element, erasing its former storage slot.
    ///
    /// The caller owns the returned value, which is not zeroized.
    /// Only its former storage slot is erased as raw bytes.
    ///
    /// ```rust
    /// use libsodium_rs::{ensure_init, utils::vec_utils};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// ensure_init()?;
    /// let mut values = vec_utils::secure_vec::<u8>(0)?;
    /// values.push(7)?;
    /// assert_eq!(values.pop(), Some(7));
    /// assert_eq!(values.pop(), None);
    /// # Ok(())
    /// # }
    /// ```
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let slot = unsafe { self.ptr.add(self.len) };
        let value = unsafe { slot.read() };
        if std::mem::size_of::<T>() != 0 {
            unsafe { libsodium_sys::sodium_memzero(slot.cast(), std::mem::size_of::<T>()) };
        }
        Some(value)
    }

    /// Reserve space for at least `additional` elements beyond the current length.
    ///
    /// Does nothing if capacity is already sufficient.
    /// Reallocation moves live elements without cloning them or creating defaults.
    /// Overflow and allocation failures leave the vector unchanged.
    ///
    /// ```rust
    /// use libsodium_rs::{ensure_init, utils::vec_utils};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// ensure_init()?;
    /// let mut values = vec_utils::secure_vec::<u8>(0)?;
    /// values.reserve(10)?;
    /// for byte in 0..10 {
    ///     values.push(byte)?;
    /// }
    /// assert_eq!(values.len(), 10);
    /// # Ok(())
    /// # }
    /// ```
    pub fn reserve(&mut self, additional: usize) -> io::Result<()> {
        let capacity = self
            .len
            .checked_add(additional)
            .ok_or_else(capacity_error)?;
        if capacity <= self.capacity {
            return Ok(());
        }
        let mut values = Self::with_capacity(capacity)?;
        unsafe { ptr::copy_nonoverlapping(self.ptr, values.ptr, self.len) };
        values.len = std::mem::replace(&mut self.len, 0);
        std::mem::swap(self, &mut values);
        Ok(())
    }
}

impl<T: Zeroize> Deref for SecureVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: Zeroize> DerefMut for SecureVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T: Zeroize> Drop for SecureVec<T> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T: Zeroize + Clone> Clone for SecureVec<T> {
    fn clone(&self) -> Self {
        let mut values = Self::with_capacity(self.capacity)
            .unwrap_or_else(|error| panic!("Failed to clone secure vector: {error}"));
        for item in self.iter() {
            let value = item.clone();
            unsafe { values.ptr.add(values.len).write(value) };
            values.len += 1;
        }
        values
    }
}

impl<T: Zeroize + std::fmt::Debug> std::fmt::Debug for SecureVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Zeroize + PartialEq> PartialEq for SecureVec<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Zeroize + Eq> Eq for SecureVec<T> {}

impl<T: Zeroize + PartialEq> PartialEq<[T]> for SecureVec<T> {
    fn eq(&self, other: &[T]) -> bool {
        &**self == other
    }
}

impl<T: Zeroize + PartialEq> PartialEq<Vec<T>> for SecureVec<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        &**self == other.as_slice()
    }
}

impl<T: Zeroize + PartialEq> PartialEq<SecureVec<T>> for [T] {
    fn eq(&self, other: &SecureVec<T>) -> bool {
        other == self
    }
}

impl<T: Zeroize + PartialEq> PartialEq<SecureVec<T>> for Vec<T> {
    fn eq(&self, other: &SecureVec<T>) -> bool {
        other == self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[derive(Clone, Debug, Default)]
    struct Counts {
        defaults: usize,
        clones: usize,
        zeroizes: usize,
        drops: usize,
        unwiped_drops: usize,
        panic_default: Option<usize>,
        panic_clone: Option<usize>,
        panic_drop: Option<usize>,
    }

    thread_local! {
        static COUNTS: RefCell<Counts> = RefCell::new(Counts::default());
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Tracked(String);

    impl Default for Tracked {
        fn default() -> Self {
            COUNTS.with(|counts| {
                let mut counts = counts.borrow_mut();
                counts.defaults += 1;
                assert_ne!(counts.panic_default, Some(counts.defaults), "default panic");
            });
            Self(String::from("sensitive value"))
        }
    }

    impl Clone for Tracked {
        fn clone(&self) -> Self {
            COUNTS.with(|counts| {
                let mut counts = counts.borrow_mut();
                counts.clones += 1;
                assert_ne!(counts.panic_clone, Some(counts.clones), "clone panic");
            });
            Self(self.0.clone())
        }
    }

    impl Zeroize for Tracked {
        fn zeroize(&mut self) {
            COUNTS.with(|counts| counts.borrow_mut().zeroizes += 1);
            self.0.zeroize();
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            COUNTS.with(|counts| {
                let mut counts = counts.borrow_mut();
                counts.drops += 1;
                counts.unwiped_drops += usize::from(!self.0.is_empty());
                assert_ne!(counts.panic_drop, Some(counts.drops), "drop panic");
            });
        }
    }

    #[repr(align(4096))]
    #[derive(Default, Clone)]
    struct AlignedZst;

    impl Zeroize for AlignedZst {
        fn zeroize(&mut self) {
            COUNTS.with(|counts| counts.borrow_mut().zeroizes += 1);
        }
    }

    impl Drop for AlignedZst {
        fn drop(&mut self) {
            COUNTS.with(|counts| counts.borrow_mut().drops += 1);
        }
    }

    #[repr(align(1048576))]
    #[derive(Default, Clone, Debug)]
    struct OverAligned(u8);

    impl Zeroize for OverAligned {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    fn reset() {
        crate::ensure_init().unwrap();
        COUNTS.with(|counts| *counts.borrow_mut() = Counts::default());
    }

    fn counts() -> Counts {
        COUNTS.with(|counts| counts.borrow().clone())
    }

    #[test]
    fn memzero_uses_generic_zeroize_without_default_or_clone() {
        struct Secret(u8);
        impl Zeroize for Secret {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        let mut values = [Secret(91), Secret(42)];
        memzero(&mut values);
        assert_eq!((values[0].0, values[1].0), (0, 0));
        let mut strings = [String::from("secret")];
        memzero(&mut strings);
        assert!(strings[0].is_empty());
    }

    #[test]
    fn clear_and_drop_zeroize_live_elements_once() {
        reset();
        let mut values = secure_vec::<Tracked>(3).unwrap();
        let storage = values.ptr;
        values.clear();
        assert!(values.is_empty());
        assert_eq!(values.ptr, storage);
        assert_eq!(values.capacity, 3);
        assert_eq!(counts().defaults, 3);
        assert_eq!((counts().zeroizes, counts().drops), (3, 3));
        assert_eq!(counts().unwiped_drops, 0);
        values.clear();
        values.push(Tracked(String::from("next secret"))).unwrap();
        drop(values);
        assert_eq!((counts().zeroizes, counts().drops), (4, 4));
        assert_eq!(counts().defaults, 3);
        assert_eq!(counts().unwiped_drops, 0);

        drop(secure_vec::<Tracked>(2).unwrap());
        assert_eq!(
            (counts().defaults, counts().zeroizes, counts().drops),
            (5, 6, 6)
        );
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn reserve_push_pop_and_drop_never_construct_spare_defaults() {
        reset();
        let mut values = secure_vec::<Tracked>(1).unwrap();
        COUNTS.with(|counts| counts.borrow_mut().panic_default = Some(2));
        values.reserve(7).unwrap();
        assert_eq!(counts().defaults, 1);
        assert_eq!(counts().clones, 0);
        assert_eq!(counts().drops, 0);
        assert_eq!(values[0].0, "sensitive value");
        values.push(Tracked(String::from("popped secret"))).unwrap();
        let mut popped = values.pop().unwrap();
        assert_eq!(popped.0, "popped secret");
        assert_eq!(counts().zeroizes, 0);
        popped.zeroize();
        drop(popped);
        drop(values);
        assert_eq!(
            (counts().defaults, counts().zeroizes, counts().drops),
            (1, 2, 2)
        );
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn reserve_uses_length_plus_additional_and_reuses_spare_capacity() {
        reset();
        let mut values = secure_vec::<u8>(2).unwrap();
        values.copy_from_slice(&[7, 9]);
        values.reserve(8).unwrap();
        assert_eq!(values.capacity, 10);
        let storage = values.ptr;
        values.reserve(8).unwrap();
        values.reserve(0).unwrap();
        assert_eq!(values.ptr, storage);
        assert_eq!(values.capacity, 10);
        assert_eq!(&*values, &[7, 9]);
        values.reserve(9).unwrap();
        assert_eq!(values.capacity, 11);
        assert_eq!(&*values, &[7, 9]);
    }

    #[test]
    fn clone_initializes_only_live_elements_and_owns_independent_values() {
        reset();
        let mut values = secure_vec::<Tracked>(2).unwrap();
        values.reserve(6).unwrap();
        COUNTS.with(|counts| counts.borrow_mut().panic_default = Some(3));
        let mut cloned = values.clone();
        assert_eq!(cloned.capacity, 8);
        assert_eq!(cloned.len(), 2);
        assert_eq!(counts().defaults, 2);
        assert_eq!(counts().clones, 2);
        cloned[0].0.push('!');
        assert_ne!(cloned[0], values[0]);
        drop(cloned);
        drop(values);
        assert_eq!((counts().zeroizes, counts().drops), (4, 4));
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn empty_clone_does_not_initialize_reserved_storage() {
        reset();
        let mut values = secure_vec::<Tracked>(0).unwrap();
        values.reserve(4).unwrap();
        COUNTS.with(|counts| counts.borrow_mut().panic_default = Some(1));
        let cloned = values.clone();
        assert!(cloned.is_empty());
        assert_eq!(cloned.capacity, 4);
        drop(cloned);
        drop(values);
        assert_eq!(
            (counts().defaults, counts().clones, counts().drops),
            (0, 0, 0)
        );
    }

    #[test]
    fn constructor_panic_cleans_up_initialized_prefix() {
        reset();
        COUNTS.with(|counts| counts.borrow_mut().panic_default = Some(2));
        assert!(catch_unwind(|| secure_vec::<Tracked>(3)).is_err());
        assert_eq!(
            (counts().defaults, counts().zeroizes, counts().drops),
            (2, 1, 1)
        );
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn clone_panic_cleans_up_prefix_and_leaves_source_unchanged() {
        reset();
        let values = secure_vec::<Tracked>(3).unwrap();
        COUNTS.with(|counts| counts.borrow_mut().panic_clone = Some(2));
        assert!(catch_unwind(AssertUnwindSafe(|| values.clone())).is_err());
        assert_eq!(
            (counts().clones, counts().zeroizes, counts().drops),
            (2, 1, 1)
        );
        assert_eq!(values.len(), 3);
        assert!(values.iter().all(|value| value.0 == "sensitive value"));
        drop(values);
        assert_eq!((counts().zeroizes, counts().drops), (4, 4));
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn clear_destructor_panic_does_not_double_drop() {
        reset();
        let mut values = secure_vec::<Tracked>(1).unwrap();
        COUNTS.with(|counts| counts.borrow_mut().panic_drop = Some(1));
        assert!(catch_unwind(AssertUnwindSafe(|| values.clear())).is_err());
        assert!(values.is_empty());
        values.push(Tracked(String::from("replacement"))).unwrap();
        drop(values);
        assert_eq!((counts().zeroizes, counts().drops), (2, 2));
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn zeroize_panic_removes_elements_from_ownership_before_callback() {
        reset();
        #[derive(Default, Clone)]
        struct PanickingZeroize;
        impl Zeroize for PanickingZeroize {
            fn zeroize(&mut self) {
                panic!("zeroize panic");
            }
        }
        impl Drop for PanickingZeroize {
            fn drop(&mut self) {
                COUNTS.with(|counts| counts.borrow_mut().drops += 1);
            }
        }
        let mut values = secure_vec::<PanickingZeroize>(2).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| values.clear())).is_err());
        assert!(values.is_empty());
        drop(values);
        assert_eq!(counts().drops, 0);
    }

    #[test]
    fn into_vec_moves_owned_values_without_cloning_zeroizing_or_dropping() {
        reset();
        let mut values = secure_vec::<Tracked>(2).unwrap();
        values.reserve(4).unwrap();
        let mut ordinary = values.into_vec();
        assert_eq!(ordinary.len(), 2);
        assert_eq!(ordinary[0].0, "sensitive value");
        assert_eq!(
            (counts().clones, counts().zeroizes, counts().drops),
            (0, 0, 0)
        );
        memzero(ordinary.as_mut_slice());
        drop(ordinary);
        assert_eq!((counts().zeroizes, counts().drops), (2, 2));
        assert_eq!(counts().unwiped_drops, 0);
    }

    #[test]
    fn push_pop_moves_values_and_erases_removed_byte_slots() {
        reset();
        let mut values = secure_vec::<u8>(0).unwrap();
        for byte in 1..=9 {
            values.push(byte).unwrap();
        }
        assert_eq!(&*values, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(values.pop(), Some(9));
        assert_eq!(unsafe { values.ptr.add(8).read() }, 0);
        values.clear();
        assert_eq!(values.pop(), None);
        values.push(42).unwrap();
        assert_eq!(values.into_vec(), [42]);
    }

    #[test]
    fn overaligned_elements_remain_aligned_after_reserve_and_clone() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                reset();
                let mut values = secure_vec::<OverAligned>(1).unwrap();
                values[0].0 = 37;
                assert_eq!(
                    (values.ptr as usize) % std::mem::align_of::<OverAligned>(),
                    0
                );
                values.reserve(1).unwrap();
                assert_eq!(
                    (values.ptr as usize) % std::mem::align_of::<OverAligned>(),
                    0
                );
                assert_eq!(values[0].0, 37);
                let cloned = values.clone();
                assert_eq!(
                    (cloned.ptr as usize) % std::mem::align_of::<OverAligned>(),
                    0
                );
                assert_eq!(cloned[0].0, 37);
                assert_eq!(values.into_vec()[0].0, 37);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn zst_elements_preserve_alignment_and_destructor_ownership() {
        reset();
        let values = secure_vec::<AlignedZst>(0).unwrap();
        assert_eq!(
            (values.ptr as usize) % std::mem::align_of::<AlignedZst>(),
            0
        );
        assert!(values._allocation.is_none());
        assert!(values.is_empty());
        assert!(values.into_vec().is_empty());

        let mut values = secure_vec::<AlignedZst>(3).unwrap();
        assert_eq!(std::mem::size_of::<AlignedZst>(), 0);
        assert_eq!(
            (values.ptr as usize) % std::mem::align_of::<AlignedZst>(),
            0
        );
        assert!(values._allocation.is_none());
        values.reserve(7).unwrap();
        let cloned = values.clone();
        assert_eq!(cloned.len(), 3);
        drop(cloned);
        assert_eq!((counts().zeroizes, counts().drops), (3, 3));
        drop(values.pop());
        assert_eq!(values.len(), 2);
        values.push(AlignedZst).unwrap();
        values.clear();
        drop(values);
        assert_eq!((counts().zeroizes, counts().drops), (6, 7));

        let values = secure_vec::<AlignedZst>(3).unwrap().into_vec();
        assert_eq!(values.len(), 3);
        assert_eq!((counts().zeroizes, counts().drops), (6, 7));
        drop(values);
        assert_eq!((counts().zeroizes, counts().drops), (6, 10));
    }

    #[test]
    fn allocation_sizes_beyond_layout_limits_are_rejected() {
        reset();
        assert_eq!(
            secure_vec::<u16>(usize::MAX / 2 + 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            secure_vec::<u8>(isize::MAX as usize + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        // The largest valid over-aligned layout still fits once alignment padding
        // is added, so it reaches the allocator and fails there instead.
        let count = isize::MAX as usize / std::mem::size_of::<OverAligned>();
        assert!(Layout::array::<OverAligned>(count).is_ok());
        assert_eq!(
            SecureVec::<OverAligned>::with_capacity(count + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            SecureVec::<OverAligned>::with_capacity(count)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn clear_zeroizes_elements_without_destructors() {
        reset();
        struct Borrowed<'a>(&'a mut [u8]);
        impl Zeroize for Borrowed<'_> {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        let mut referenced = [0x5au8; 8];
        let mut handles = SecureVec::<Borrowed>::with_capacity(1).unwrap();
        handles.push(Borrowed(&mut referenced)).unwrap();
        drop(handles);
        assert_eq!(referenced, [0; 8]);

        let mut bytes = secure_vec::<u8>(64).unwrap();
        bytes.fill(0x5a);
        let storage = bytes.ptr;
        bytes.clear();
        let wiped = unsafe { std::slice::from_raw_parts(storage, 64) };
        assert!(wiped.iter().all(|&byte| byte == 0));

        let mut words = secure_vec::<[u64; 3]>(5).unwrap();
        words.fill([u64::MAX; 3]);
        let storage = words.ptr.cast::<u8>();
        words.clear();
        let wiped = unsafe { std::slice::from_raw_parts(storage, 5 * 24) };
        assert!(wiped.iter().all(|&byte| byte == 0));
        assert_eq!(words.capacity, 5);
    }

    #[test]
    fn failed_push_zeroizes_rejected_value() {
        reset();
        let mut values = SecureVec::<Tracked>::with_capacity(0).unwrap();
        let full = isize::MAX as usize / std::mem::size_of::<Tracked>();
        values.len = full;
        values.capacity = full;
        let error = values.push(Tracked(String::from("secret"))).unwrap_err();
        values.len = 0;
        values.capacity = 0;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let counts = counts();
        assert_eq!((counts.zeroizes, counts.drops), (1, 1));
        assert_eq!(counts.unwiped_drops, 0);
    }

    #[test]
    fn push_needs_neither_default_nor_clone() {
        reset();
        struct Secret(u8);
        impl Zeroize for Secret {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        let mut values = SecureVec::<Secret>::with_capacity(1).unwrap();
        values.push(Secret(1)).unwrap();
        values.push(Secret(2)).unwrap();
        assert_eq!((values[0].0, values[1].0), (1, 2));
    }

    #[test]
    fn reserve_errors_preserve_live_values_and_capacity() {
        reset();
        let mut values = secure_vec::<u8>(1).unwrap();
        values[0] = 99;
        let storage = values.ptr;
        assert_eq!(
            values.reserve(usize::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            values.reserve(isize::MAX as usize).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(values.ptr, storage);
        assert_eq!(values.capacity, 1);
        assert_eq!(&*values, &[99]);
    }

    #[test]
    fn zst_push_checks_length_and_capacity_growth_overflow() {
        reset();
        let mut values = SecureVec::<()>::with_capacity(usize::MAX).unwrap();
        values.len = usize::MAX;
        let result = values.push(());
        values.len = 0;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);

        let capacity = usize::MAX / 2 + 1;
        let mut values = SecureVec::<()>::with_capacity(capacity).unwrap();
        values.len = capacity;
        values.push(()).unwrap();
        let len = values.len;
        values.len = 0;
        assert_eq!(len, capacity + 1);
        assert_eq!(values.capacity, capacity + 1);
    }

    #[test]
    fn equality_and_debug_use_only_live_values() {
        reset();
        let mut values = secure_vec::<u8>(2).unwrap();
        values.copy_from_slice(&[1, 2]);
        values.reserve(3).unwrap();
        assert_eq!(values, values.clone());
        assert!(values == [1, 2][..]);
        assert!([1, 2][..] == values);
        assert_eq!(values, vec![1, 2]);
        assert_eq!(vec![1, 2], values);
        assert_eq!(format!("{values:?}"), "[1, 2]");
    }

    #[cfg(unix)]
    #[test]
    fn byte_unlock_erases_live_bytes_even_if_unlock_fails() {
        reset();
        let mut bytes = vec![1u8, 2, 3, 4];
        let _ = mlock(&mut bytes);
        let _ = munlock(&mut bytes);
        assert_eq!(bytes, [0; 4]);
        assert!(munlock(&mut Vec::new()).is_ok());
        assert!(mlock(&mut Vec::new()).is_ok());
    }
}
