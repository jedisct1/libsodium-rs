use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_secretbox, random};

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

    // Benchmark symmetric encryption operations
    println!("=== SecretBox XSalsa20-Poly1305 Benchmarks ===");
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
}
