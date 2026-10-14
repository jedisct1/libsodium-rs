#[cfg(test)]
use crate::crypto_generichash::blake2b::{hash, hash_with_key, hash_with_salt_and_personal, State};
use crate::crypto_generichash::blake2b::{
    BYTES, BYTES_MAX, BYTES_MIN, KEYBYTES, KEYBYTES_MAX, KEYBYTES_MIN, PERSONALBYTES, SALTBYTES,
};
use ct_codecs::{Encoder, Hex};

#[test]
fn test_hash() {
    let data = b"test data";
    let hash = hash(data, BYTES).unwrap();

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
    let hash = hash_with_key(data, &key, BYTES).unwrap();

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
    let result2 = hash_with_key(data, &key, BYTES).unwrap();
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
    let one_shot_hash = hash(b"test data", BYTES).unwrap();
    assert_eq!(result, one_shot_hash);
}

#[test]
fn test_output_length_policy() {
    assert_eq!(BYTES_MIN, 16);
    assert_eq!(BYTES_MAX, 64);
    let key = [0x42; KEYBYTES];
    let salt = [0x43; SALTBYTES];
    let personal = [0x44; PERSONALBYTES];

    for output_len in [0, 1, 15, 16, 64, 65] {
        let accepted = (16..=64).contains(&output_len);
        let states = [
            State::new(None, output_len),
            State::new_with_salt_and_personal(Some(&key), output_len, Some(&salt), Some(&personal)),
        ];
        for result in states {
            assert_eq!(result.is_ok(), accepted, "output length {output_len}");
            if let Ok(mut state) = result {
                assert_eq!(state.finalize().len(), output_len);
            }
        }
    }
}

#[test]
fn test_accepted_key_lengths() {
    assert_eq!(KEYBYTES_MIN, 16);
    assert_eq!(KEYBYTES_MAX, 64);
    let salt = [0x43; SALTBYTES];
    let personal = [0x44; PERSONALBYTES];

    for key_len in 0..=64 {
        let key = vec![0x42; key_len];
        State::new(Some(&key), BYTES).unwrap();
        State::new_with_salt_and_personal(Some(&key), BYTES, Some(&salt), Some(&personal)).unwrap();
    }

    let key = [0x42; KEYBYTES];
    let mut state = State::new(Some(&key), BYTES).unwrap();
    state.update(b"te");
    state.update(b"st");
    assert_eq!(
        state.finalize(),
        hash_with_key(b"test", &key, BYTES).unwrap()
    );

    let mut state =
        State::new_with_salt_and_personal(Some(&key), BYTES, Some(&salt), Some(&personal)).unwrap();
    state.update(b"te");
    state.update(b"st");
    assert_eq!(
        state.finalize(),
        hash_with_salt_and_personal(b"test", Some(&key), BYTES, Some(&salt), Some(&personal))
            .unwrap(),
    );

    assert_eq!(
        hash_with_key(b"test", b"", BYTES).unwrap(),
        hash(b"test", BYTES).unwrap()
    );
    assert_eq!(
        hash_with_salt_and_personal(b"test", Some(b""), BYTES, Some(&salt), Some(&personal))
            .unwrap(),
        hash_with_salt_and_personal(b"test", None, BYTES, Some(&salt), Some(&personal)).unwrap(),
    );

    let long_key = [0x42; 65];
    assert!(State::new(Some(&long_key), BYTES).is_err());
    assert!(State::new_with_salt_and_personal(
        Some(&long_key),
        BYTES,
        Some(&salt),
        Some(&personal),
    )
    .is_err());
}

#[test]
fn test_invalid_output_length_max() {
    assert!(hash(b"test", BYTES_MAX + 1).is_err());
}

#[test]
fn test_invalid_output_length_min() {
    assert!(hash(b"test", BYTES_MIN - 1).is_err());
}

#[test]
fn test_invalid_key_length() {
    let long_key = vec![0u8; KEYBYTES_MAX + 1];
    assert!(hash_with_key(b"test", &long_key, BYTES).is_err());
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
