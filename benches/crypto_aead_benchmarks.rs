use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_aead, random};

// Explicitly ensure libsodium is initialized
fn init() {
    sodium::ensure_init().expect("Failed to initialize libsodium");
}

fn main() {
    // Ensure libsodium is initialized before running any benchmarks
    init();

    // Configure the benchmark with more iterations for accurate measurements
    let bench = Bench::new();
    let options = Options {
        iterations: 1000, // Perform 1000 operations per measurement
        ..Options::default()
    };
    let data_sizes = [64, 1024, 16384, 65536]; // bytes

    // XChaCha20-Poly1305 benchmarks
    println!("=== XChaCha20-Poly1305 AEAD Benchmarks ===");
    let key = crypto_aead::xchacha20poly1305::Key::generate();
    let nonce = &crypto_aead::xchacha20poly1305::Nonce::try_from_slice(
        &[0u8; crypto_aead::xchacha20poly1305::NPUBBYTES],
    )
    .unwrap();
    let additional_data = b"Additional authenticated data";

    for &size in &data_sizes {
        let data = random::bytes(size);

        let bench_name = format!("XChaCha20-Poly1305 encrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_aead::xchacha20poly1305::encrypt(&data, Some(additional_data), nonce, &key)
                .unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        let ciphertext =
            crypto_aead::xchacha20poly1305::encrypt(&data, Some(additional_data), nonce, &key)
                .unwrap();
        let bench_name = format!("XChaCha20-Poly1305 decrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_aead::xchacha20poly1305::decrypt(&ciphertext, Some(additional_data), nonce, &key)
                .unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // AES256-GCM benchmarks (only if supported)
    if crypto_aead::aes256gcm::is_available() {
        println!("\n=== AES256-GCM AEAD Benchmarks ===");
        let key = crypto_aead::aes256gcm::Key::generate();
        let nonce = &crypto_aead::aes256gcm::Nonce::try_from_slice(
            &[0u8; crypto_aead::aes256gcm::NPUBBYTES],
        )
        .unwrap();

        for &size in &data_sizes {
            let data = random::bytes(size);

            let bench_name = format!("AES256-GCM encrypt {size} bytes");
            let bench_result = bench.run(&options, || {
                crypto_aead::aes256gcm::encrypt(&data, Some(additional_data), nonce, &key).unwrap()
            });
            let ops_per_sec =
                1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
            println!("{bench_name}: {ops_per_sec:.2} ops/sec");

            let ciphertext =
                crypto_aead::aes256gcm::encrypt(&data, Some(additional_data), nonce, &key).unwrap();
            let bench_name = format!("AES256-GCM decrypt {size} bytes");
            let bench_result = bench.run(&options, || {
                crypto_aead::aes256gcm::decrypt(&ciphertext, Some(additional_data), nonce, &key)
                    .unwrap()
            });
            let ops_per_sec =
                1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
            println!("{bench_name}: {ops_per_sec:.2} ops/sec");
        }
    } else {
        println!("\nAES256-GCM not available on this CPU, skipping benchmarks");
    }

    // AEGIS-128L benchmarks
    println!("\n=== AEGIS-128L AEAD Benchmarks ===");
    let key = crypto_aead::aegis128l::Key::generate();
    let nonce =
        &crypto_aead::aegis128l::Nonce::try_from_slice(&[0u8; crypto_aead::aegis128l::NPUBBYTES])
            .unwrap();

    for &size in &data_sizes {
        let data = random::bytes(size);

        let bench_name = format!("AEGIS-128L encrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_aead::aegis128l::encrypt(&data, Some(additional_data), nonce, &key).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        let ciphertext =
            crypto_aead::aegis128l::encrypt(&data, Some(additional_data), nonce, &key).unwrap();
        let bench_name = format!("AEGIS-128L decrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_aead::aegis128l::decrypt(&ciphertext, Some(additional_data), nonce, &key)
                .unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // AEGIS-256 benchmarks
    println!("\n=== AEGIS-256 AEAD Benchmarks ===");
    let key = crypto_aead::aegis256::Key::generate();
    let nonce =
        &crypto_aead::aegis256::Nonce::try_from_slice(&[0u8; crypto_aead::aegis256::NPUBBYTES])
            .unwrap();

    for &size in &data_sizes {
        let data = random::bytes(size);

        let bench_name = format!("AEGIS-256 encrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_aead::aegis256::encrypt(&data, Some(additional_data), nonce, &key).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        let ciphertext =
            crypto_aead::aegis256::encrypt(&data, Some(additional_data), nonce, &key).unwrap();
        let bench_name = format!("AEGIS-256 decrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_aead::aegis256::decrypt(&ciphertext, Some(additional_data), nonce, &key).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }
}
