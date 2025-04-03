#[cfg(test)]
use crate::crypto_generichash::blake2b::{hash, hash_with_key, hash_with_salt_and_personal, State};
use crate::crypto_generichash::blake2b::{
    BYTES, BYTES_MAX, BYTES_MIN, KEYBYTES, KEYBYTES_MAX, PERSONALBYTES, SALTBYTES,
};
use ct_codecs::{Encoder, Hex};

#[test]
fn test_hash() {
    let data = b"test data";
    let hash = hash(data, BYTES);

    // Convert hash to hex string for comparison
    let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
    let encoded = Hex::encode(&mut encoded, &hash).unwrap();
    let hash_hex = std::str::from_utf8(encoded).unwrap();

    assert_eq!(
        hash_hex,
        "eab94977a17791d0c089fe9e393261b3ab667cf0e8456632a842d905c468cf65"
    );
}

#[test]
fn test_hash_with_key() {
    let data = b"test data";
    let key = vec![0u8; KEYBYTES]; // Use a properly sized key
    let hash = hash_with_key(data, &key, BYTES);

    // Convert hash to hex string for comparison
    let mut encoded = vec![0u8; hash.len() * 2]; // Hex encoding doubles the length
    let encoded = Hex::encode(&mut encoded, &hash).unwrap();
    let hash_hex = std::str::from_utf8(encoded).unwrap();

    assert_eq!(
        hash_hex,
        "9e34d14a3d2082187f56b14df4e9aaf36b0562e0f842b5b323555192b0c08c22"
    );
}

#[test]
fn test_hash_with_salt_and_personal() {
    let data = b"test data";
    let key = vec![0u8; KEYBYTES]; // Use a properly sized key
    let salt = vec![1u8; SALTBYTES]; // Use a properly sized salt
    let personal = vec![2u8; PERSONALBYTES]; // Use a properly sized personalization

    let result = hash_with_salt_and_personal(data, Some(&key), BYTES, Some(&salt), Some(&personal))
        .expect("Failed to compute hash");

    // Verify that the hash is different from the one without salt and personalization
    let result2 = hash_with_key(data, &key, BYTES);
    assert_ne!(result, result2);
}

#[test]
fn test_incremental_hash() {
    let mut state = State::new(None, BYTES).expect("Failed to create BLAKE2b state");
    state.update(b"test ");
    state.update(b"data");
    let result = state.finalize();

    // Convert hash to hex string for comparison
    let mut encoded = vec![0u8; result.len() * 2]; // Hex encoding doubles the length
    let encoded = Hex::encode(&mut encoded, &result).unwrap();
    let hash_hex = std::str::from_utf8(encoded).unwrap();

    assert_eq!(
        hash_hex,
        "eab94977a17791d0c089fe9e393261b3ab667cf0e8456632a842d905c468cf65"
    );

    // Compare with one-shot hash
    let one_shot_hash = hash(b"test data", BYTES);
    assert_eq!(result, one_shot_hash);
}

#[test]
#[should_panic(expected = "Invalid parameters for BLAKE2b hash")]
fn test_invalid_output_length_max() {
    hash(b"test", BYTES_MAX + 1);
}

#[test]
#[should_panic(expected = "Invalid parameters for BLAKE2b hash")]
fn test_invalid_output_length_min() {
    hash(b"test", BYTES_MIN - 1);
}

#[test]
#[should_panic(expected = "Invalid parameters for BLAKE2b hash")]
fn test_invalid_key_length() {
    let long_key = vec![0u8; KEYBYTES_MAX + 1];
    hash_with_key(b"test", &long_key, BYTES);
}

#[test]
#[should_panic(expected = "Salt length must be exactly 16 bytes")]
fn test_invalid_salt_length() {
    let key = vec![0u8; KEYBYTES];
    let invalid_salt = vec![1u8; SALTBYTES + 1];
    let personal = vec![2u8; PERSONALBYTES];

    hash_with_salt_and_personal(
        b"test",
        Some(&key),
        BYTES,
        Some(&invalid_salt),
        Some(&personal),
    )
    .expect("Should have failed");
}

#[test]
#[should_panic(expected = "Personalization length must be exactly 16 bytes")]
fn test_invalid_personal_length() {
    let key = vec![0u8; KEYBYTES];
    let salt = vec![1u8; SALTBYTES];
    let invalid_personal = vec![2u8; PERSONALBYTES + 1];

    hash_with_salt_and_personal(
        b"test",
        Some(&key),
        BYTES,
        Some(&salt),
        Some(&invalid_personal),
    )
    .expect("Should have failed");
}
