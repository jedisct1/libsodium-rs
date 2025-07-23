use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_pwhash, random};

// Explicitly ensure libsodium is initialized
fn init() {
    sodium::ensure_init().expect("Failed to initialize libsodium");
}

fn main() {
    // Ensure libsodium is initialized before running any benchmarks
    init();

    // Configure the benchmark with fewer iterations since password hashing is slow
    let bench = Bench::new();
    let options = Options {
        min_samples: 3,
        max_samples: 5,
        // Use only 10 iterations for password hashing as it's intentionally slow
        iterations: 10,
        ..Options::default()
    };

    // Benchmark password hashing operations
    println!("=== Password Hashing Benchmarks ===");

    // Define test parameters
    let password = b"correct horse battery staple";

    // Argon2id (default)
    println!("\n=== Argon2id Benchmarks ===");

    let bench_name = "Argon2id Interactive";
    // Create a salt for Argon2id
    let mut salt = [0u8; crypto_pwhash::SALTBYTES];
    random::fill_bytes(&mut salt);

    let bench_result = bench.run(&options, || {
        crypto_pwhash::pwhash(
            32,
            password,
            &salt,
            crypto_pwhash::OPSLIMIT_INTERACTIVE,
            crypto_pwhash::MEMLIMIT_INTERACTIVE,
            crypto_pwhash::ALG_DEFAULT,
        )
        .unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // Argon2i
    println!("\n=== Argon2i Benchmarks ===");

    let bench_name = "Argon2i Interactive";
    // Create a salt for Argon2i
    let mut salt = [0u8; crypto_pwhash::argon2i::SALTBYTES];
    random::fill_bytes(&mut salt);

    let bench_result = bench.run(&options, || {
        crypto_pwhash::argon2i::pwhash(
            32,
            password,
            &salt,
            crypto_pwhash::argon2i::OPSLIMIT_INTERACTIVE,
            crypto_pwhash::argon2i::MEMLIMIT_INTERACTIVE,
        )
        .unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // Scrypt
    println!("\n=== Scrypt Benchmarks ===");

    let bench_name = "Scrypt Interactive";
    // Create a salt for Scrypt
    let mut salt = [0u8; crypto_pwhash::scryptsalsa208sha256::SALTBYTES];
    random::fill_bytes(&mut salt);

    let bench_result = bench.run(&options, || {
        crypto_pwhash::scryptsalsa208sha256::pwhash(
            32,
            password,
            &salt,
            crypto_pwhash::scryptsalsa208sha256::OPSLIMIT_INTERACTIVE,
            crypto_pwhash::scryptsalsa208sha256::MEMLIMIT_INTERACTIVE,
        )
        .unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");
}
