use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_sign, random};

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

    // Benchmark digital signature operations
    println!("=== Ed25519 Signature Benchmarks ===");
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
