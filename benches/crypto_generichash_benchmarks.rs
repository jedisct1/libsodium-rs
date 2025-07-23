use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_generichash, random};

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

    // BLAKE2b hash without key
    println!("=== BLAKE2b Hash Benchmarks (No Key) ===");
    for &size in &data_sizes {
        let data = random::bytes(size);

        // Default output size (32 bytes)
        let bench_name = format!("BLAKE2b hash {size} bytes (default size)");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, None, crypto_generichash::BYTES).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        // Minimum output size (16 bytes)
        let bench_name = format!("BLAKE2b hash {size} bytes (min size)");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, None, crypto_generichash::BYTES_MIN).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        // Maximum output size (64 bytes)
        let bench_name = format!("BLAKE2b hash {size} bytes (max size)");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, None, crypto_generichash::BYTES_MAX).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // BLAKE2b hash with key
    println!("\n=== BLAKE2b Hash Benchmarks (With Key) ===");
    let key = random::bytes(crypto_generichash::KEYBYTES);

    for &size in &data_sizes {
        let data = random::bytes(size);

        // Default output size (32 bytes)
        let bench_name = format!("BLAKE2b keyed hash {size} bytes (default size)");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, Some(&key), crypto_generichash::BYTES).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        // Maximum output size (64 bytes)
        let bench_name = format!("BLAKE2b keyed hash {size} bytes (max size)");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, Some(&key), crypto_generichash::BYTES_MAX)
                .unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }

    // BLAKE2b incremental hashing
    println!("\n=== BLAKE2b Incremental Hash Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let half_size = size / 2;
        let first_half = &data[..half_size];
        let second_half = &data[half_size..];

        // Single-pass hashing (for comparison)
        let bench_name = format!("BLAKE2b single-pass hash {size} bytes");
        let bench_result = bench.run(&options, || {
            crypto_generichash::generichash(&data, None, crypto_generichash::BYTES).unwrap()
        });
        let single_pass_ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {single_pass_ops_per_sec:.2} ops/sec");

        // Incremental hashing
        let bench_name = format!("BLAKE2b incremental hash {size} bytes (2 parts)");
        let bench_result = bench.run(&options, || {
            let mut state =
                crypto_generichash::State::new(None, crypto_generichash::BYTES).unwrap();
            state.update(first_half);
            state.update(second_half);
            state.finalize()
        });
        let incremental_ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {incremental_ops_per_sec:.2} ops/sec");

        // Calculate overhead percentage
        let overhead_percent =
            ((single_pass_ops_per_sec - incremental_ops_per_sec) / single_pass_ops_per_sec) * 100.0;
        println!("Incremental overhead: {overhead_percent:.2}%");
    }
}
