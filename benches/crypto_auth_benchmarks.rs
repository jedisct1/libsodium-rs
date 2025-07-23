use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_auth::hmacsha256, crypto_auth::hmacsha512, random};

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

    // Benchmark HMAC operations
    println!("=== HMAC-SHA-256 Benchmarks ===");
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
}
