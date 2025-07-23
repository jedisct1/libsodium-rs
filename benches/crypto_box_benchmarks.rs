use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_box, random};

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

    // Benchmark asymmetric encryption operations
    println!("=== Box Curve25519-XSalsa20-Poly1305 Benchmarks ===");
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
}
