use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{
    crypto_auth::hmacsha256, crypto_auth::hmacsha512, crypto_box, crypto_generichash, crypto_hash,
    crypto_secretbox, crypto_sign, random,
};

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
    for &size in &data_sizes {
        let data = random::bytes(size);
        let bench_name = format!("SHA-256 hash {size} bytes");
        let bench_result = bench.run(&options, || crypto_hash::hash_sha256(&data));
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    println!("\n=== SHA-512 Hash Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let bench_name = format!("SHA-512 hash {size} bytes");
        let bench_result = bench.run(&options, || crypto_hash::hash_sha512(&data));
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // Benchmark HMAC operations
    println!("\n=== HMAC-SHA-256 Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let key = hmacsha256::Key::generate();
        let bench_name = format!("HMAC-SHA-256 {size} bytes");
        let bench_result = bench.run(&options, || hmacsha256::auth(&data, &key).unwrap());
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    println!("\n=== HMAC-SHA-512 Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let key = hmacsha512::Key::generate();
        let bench_name = format!("HMAC-SHA-512 {size} bytes");
        let bench_result = bench.run(&options, || hmacsha512::auth(&data, &key).unwrap());
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // Benchmark BLAKE2b hash operations
    println!("\n=== BLAKE2b Hash Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let bench_name = format!("BLAKE2b hash {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, None, crypto_generichash::BYTES).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // Benchmark symmetric encryption operations
    println!("\n=== SecretBox XSalsa20-Poly1305 Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let key = crypto_secretbox::Key::generate();
        let nonce =
            &crypto_secretbox::Nonce::try_from_slice(&[0u8; crypto_secretbox::NONCEBYTES]).unwrap();

        let bench_name = format!("SecretBox encrypt {size} bytes");
        let bench_result = bench.run(&options, || crypto_secretbox::seal(&data, nonce, &key));
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        let ciphertext = crypto_secretbox::seal(&data, nonce, &key);
        let bench_name = format!("SecretBox decrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_secretbox::open(&ciphertext, nonce, &key).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // Benchmark asymmetric encryption operations
    println!("\n=== Box Curve25519-XSalsa20-Poly1305 Benchmarks ===");
    let alice_keypair = crypto_box::KeyPair::generate();
    let alice_pk = alice_keypair.public_key;
    let alice_sk = alice_keypair.secret_key;
    let bob_keypair = crypto_box::KeyPair::generate();
    let bob_pk = bob_keypair.public_key;
    let bob_sk = bob_keypair.secret_key;
    let nonce_bytes = [0u8; crypto_box::NONCEBYTES];
    let nonce = &crypto_box::Nonce::try_from(&nonce_bytes[..]).unwrap();

    for &size in &data_sizes {
        let data = random::bytes(size);

        let bench_name = format!("Box encrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_box::seal(&data, nonce, &bob_pk, &alice_sk).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        let ciphertext = crypto_box::seal(&data, nonce, &bob_pk, &alice_sk).unwrap();
        let bench_name = format!("Box decrypt {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_box::open(&ciphertext, nonce, &alice_pk, &bob_sk).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // Benchmark digital signature operations
    println!("\n=== Ed25519 Signature Benchmarks ===");
    let keypair = crypto_sign::KeyPair::generate().unwrap();
    let pk = keypair.public_key;
    let sk = keypair.secret_key;

    for &size in &data_sizes {
        let data = random::bytes(size);

        let bench_name = format!("Ed25519 sign {size} bytes");
        let bench_result = bench.run(&options, || crypto_sign::sign(&data, &sk).unwrap());
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        let signed_msg = crypto_sign::sign(&data, &sk).unwrap();
        let bench_name = format!("Ed25519 verify {size} bytes");
        let bench_result = bench.run(&options, || crypto_sign::verify(&signed_msg, &pk).unwrap());
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }
}
