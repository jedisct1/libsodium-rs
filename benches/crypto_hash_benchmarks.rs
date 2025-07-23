use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_hash, random};

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

    println!("=== SHA-256 Hash Benchmarks ===");
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
}
