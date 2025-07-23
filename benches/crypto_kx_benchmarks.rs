use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::crypto_kx;

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

    println!("=== Key Exchange Benchmarks ===");

    // Benchmark keypair generation
    let bench_name = "KX keypair generation";
    let bench_result = bench.run(&options, || crypto_kx::KeyPair::generate().unwrap());
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // Generate keypairs for client and server
    let client_keypair = crypto_kx::KeyPair::generate().unwrap();
    let client_pk = client_keypair.public_key;
    let client_sk = client_keypair.secret_key;
    let server_keypair = crypto_kx::KeyPair::generate().unwrap();
    let server_pk = server_keypair.public_key;
    let server_sk = server_keypair.secret_key;

    // Benchmark client session key computation
    let bench_name = "KX client session keys";
    let bench_result = bench.run(&options, || {
        crypto_kx::client_session_keys(&client_pk, &client_sk, &server_pk).unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");

    // Benchmark server session key computation
    let bench_name = "KX server session keys";
    let bench_result = bench.run(&options, || {
        crypto_kx::server_session_keys(&server_pk, &server_sk, &client_pk).unwrap()
    });
    let ops_per_sec = 1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
    println!("{bench_name}: {ops_per_sec:.2} ops/sec");
}
