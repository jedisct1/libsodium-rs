use benchmark_simple::{Bench, Options};
use libsodium_rs as sodium;
use sodium::{crypto_secretstream::xchacha20poly1305, random};

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

    println!("=== XChaCha20-Poly1305 SecretStream Benchmarks ===");
    for &size in &data_sizes {
        let data = random::bytes(size);
        let key = xchacha20poly1305::Key::generate();

        // Benchmark initialization
        let bench_name = format!("SecretStream init_push {size} bytes");
        let bench_result = bench.run(&options, || {
            xchacha20poly1305::PushState::init_push(&key).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        // Create a push state for encryption benchmarks
        let (mut push_state, _header) = xchacha20poly1305::PushState::init_push(&key).unwrap();

        // Benchmark encryption
        let bench_name = format!("SecretStream push {size} bytes");
        let bench_result = bench.run(&options, || {
            push_state
                .push(&data, None, xchacha20poly1305::TAG_MESSAGE)
                .unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        // For decryption benchmarks, we need a fresh push state and header for each test
        // to ensure proper synchronization between encryption and decryption
        let (mut fresh_push_state, header) = xchacha20poly1305::PushState::init_push(&key).unwrap();
        let ciphertext = fresh_push_state
            .push(&data, None, xchacha20poly1305::TAG_MESSAGE)
            .unwrap();

        // Benchmark pull state initialization
        let bench_name = format!("SecretStream init_pull {size} bytes");
        let bench_result = bench.run(&options, || {
            xchacha20poly1305::PullState::init_pull(&header, &key).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");

        // For the decryption benchmark, we need to create a new pull state for each iteration
        // since the pull operation modifies the state
        let bench_name = format!("SecretStream pull {size} bytes");
        let bench_result = bench.run(&options, || {
            let mut pull_state = xchacha20poly1305::PullState::init_pull(&header, &key).unwrap();
            pull_state.pull(&ciphertext, None).unwrap()
        });
        let ops_per_sec =
            1_000_000_000.0 / (bench_result.as_ns() as f64 / options.iterations as f64);
        println!("{bench_name}: {ops_per_sec:.2} ops/sec");
    }
}
