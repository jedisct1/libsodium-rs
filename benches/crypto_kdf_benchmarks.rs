use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::crypto_kdf;

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

    // Benchmark KDF operations
    println!("=== Key Derivation Function Benchmarks ===");

    // Blake2b KDF
    println!("\n=== Blake2b KDF Benchmarks ===");
    let master_key = crypto_kdf::blake2b::Key::generate().unwrap();
    let context = b"Examples";

    let bench_name = "Blake2b KDF derive_from_key";
    let bench_result = bench.run(&options, || {
        crypto_kdf::blake2b::derive_from_key(32, 1, context, &master_key).unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // HKDF-SHA256
    println!("\n=== HKDF-SHA256 Benchmarks ===");
    let ikm = vec![0u8; 32];
    let salt_bytes: &[u8] = b"salt";
    let salt = Some(salt_bytes);
    let info_bytes: &[u8] = b"info";
    let info = Some(info_bytes);

    let bench_name = "HKDF-SHA256 extract and expand";
    let bench_result = bench.run(&options, || {
        let prk = crypto_kdf::hkdf::sha256::extract(salt, &ikm).unwrap();
        crypto_kdf::hkdf::sha256::expand(32, info, &prk).unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // HKDF-SHA512
    println!("\n=== HKDF-SHA512 Benchmarks ===");
    let ikm = vec![0u8; 32];

    let bench_name = "HKDF-SHA512 extract and expand";
    let bench_result = bench.run(&options, || {
        let prk = crypto_kdf::hkdf::sha512::extract(salt, &ikm).unwrap();
        crypto_kdf::hkdf::sha512::expand(32, info, &prk).unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // Standard KDF
    println!("\n=== Standard KDF Benchmarks ===");
    let master_key = crypto_kdf::Key::generate().unwrap();

    let bench_name = "Standard KDF derive_from_key";
    let bench_result = bench.run(&options, || {
        crypto_kdf::derive_from_key(32, 1, context, &master_key).unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");
}
