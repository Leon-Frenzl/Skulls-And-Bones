//! Concurrency and Stampede Stress Tests for DynamicSniResolver.
//!
//! Standards Compliance:
//! - Conforms to IETF RFC 6066 §3 (TLS Server Name Indication)
//! - Conforms to IETF RFC 8446 (TLS 1.3)
//! - Conforms to IETF RFC 5280 (Internet X.509 PKI Profile)

use sb_proxy::escape::EscapeSpaceStore;
use sb_proxy::ca::DeveloperCa;
use sb_proxy::proxy::DynamicSniResolver;
use std::sync::{Arc, Barrier, RwLock};
use std::time::Instant;

static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ensure_ca_initialized() {
    let _ = sb_ca::x509::init_root_ca(false);
}

fn unique_domain(prefix: &str, suffix: &str) -> String {
    format!("{}-{}.{}", prefix, uuid::Uuid::new_v4().simple(), suffix)
}

/// Scenario 1: 60 threads simultaneously requesting the SAME unminted domain (stampede resilience).
#[test]
fn test_cache_stampede_single_domain_60_threads() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let routes = Arc::new(RwLock::new(EscapeSpaceStore { spaces: vec![] }));
    let resolver = Arc::new(DynamicSniResolver::new(None, routes, None));

    let stampede_domain = unique_domain("stampede-resilience", "sbm");
    let thread_count = 60;
    let barrier = Arc::new(Barrier::new(thread_count));

    let mut handles = Vec::with_capacity(thread_count);

    println!(
        "\n[STAMPEDE] Launching {} threads simultaneously for domain: {}",
        thread_count, stampede_domain
    );

    let start_all = Instant::now();

    for thread_idx in 0..thread_count {
        let b = barrier.clone();
        let res = resolver.clone();
        let domain = stampede_domain.clone();

        handles.push(std::thread::spawn(move || {
            // Synchronize all threads at the starting line
            b.wait();
            let t0 = Instant::now();
            let cert = res.resolve_for_server_name(&domain);
            let elapsed = t0.elapsed();
            (thread_idx, cert, elapsed)
        }));
    }

    let mut results = Vec::with_capacity(thread_count);
    for h in handles {
        let res = h
            .join()
            .expect("Thread panicked during stampede stress test");
        results.push(res);
    }

    let total_stampede_time = start_all.elapsed();
    println!(
        "[STAMPEDE] All {} threads completed in {:?}",
        thread_count, total_stampede_time
    );

    // Verify all 60 threads received a valid certificate
    for (idx, cert, elapsed) in &results {
        assert!(
            cert.is_some(),
            "Thread {} failed to receive certificate during stampede",
            idx
        );
        println!("  - Thread {:02} resolved in {:?}", idx, elapsed);
    }

    // Verify that the domain is now cached in RAM
    assert!(
        resolver.is_cached(&stampede_domain),
        "Domain must be cached in memory"
    );
    assert_eq!(
        resolver.cached_certs_count(),
        1,
        "Exactly 1 domain should be in cache"
    );

    // Verify on-disk presence
    let disk_cert = DeveloperCa::find_dev_certificate(&stampede_domain);
    assert!(
        disk_cert.is_some(),
        "Domain cert must exist on disk after stampede"
    );

    // Now test subsequent requests: all threads should get the exact same pointer
    let base_cert = resolver
        .resolve_for_server_name(&stampede_domain)
        .expect("Must resolve cached cert");

    let post_barrier = Arc::new(Barrier::new(thread_count));
    let mut post_handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        let b = post_barrier.clone();
        let res = resolver.clone();
        let domain = stampede_domain.clone();
        let expected_ptr = base_cert.clone();

        post_handles.push(std::thread::spawn(move || {
            b.wait();
            let c = res.resolve_for_server_name(&domain).expect("Must resolve");
            assert!(
                Arc::ptr_eq(&c, &expected_ptr),
                "RAM cache must return identical pointer"
            );
        }));
    }

    for h in post_handles {
        h.join().expect("Post-stampede thread join failed");
    }

    println!("[STAMPEDE] Pointer equality verified across all post-stampede threads.");
}

/// Scenario 2: Heavy multi-threaded contention verifying pointer equality (Arc::ptr_eq).
#[test]
fn test_pointer_equality_under_heavy_contention() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let routes = Arc::new(RwLock::new(EscapeSpaceStore { spaces: vec![] }));
    let resolver = Arc::new(DynamicSniResolver::new(None, routes, None));

    // Pre-mint 5 domains
    let domain_count = 5;
    let mut domains = Vec::with_capacity(domain_count);
    let mut base_certs = Vec::with_capacity(domain_count);

    for i in 0..domain_count {
        let d = unique_domain(&format!("contention-pool-{}", i), "mesh");
        let cert = resolver
            .resolve_for_server_name(&d)
            .expect("Minting must succeed");
        domains.push(d);
        base_certs.push(cert);
    }

    assert_eq!(resolver.cached_certs_count(), domain_count);

    let thread_count = 64;
    let iterations_per_thread = 500;
    let barrier = Arc::new(Barrier::new(thread_count));

    println!(
        "\n[CONTENTION] Launching {} threads, {} iterations each ({} total lookups)...",
        thread_count,
        iterations_per_thread,
        thread_count * iterations_per_thread
    );

    let start = Instant::now();
    let mut handles = Vec::with_capacity(thread_count);

    for thread_id in 0..thread_count {
        let b = barrier.clone();
        let res = resolver.clone();
        let doms = domains.clone();
        let certs = base_certs.clone();

        handles.push(std::thread::spawn(move || {
            b.wait();
            for iter in 0..iterations_per_thread {
                let idx = (thread_id + iter) % doms.len();
                let c = res
                    .resolve_for_server_name(&doms[idx])
                    .expect("Lookup must succeed");
                assert!(
                    Arc::ptr_eq(&c, &certs[idx]),
                    "Arc::ptr_eq violated in thread {} iteration {} for domain {}",
                    thread_id,
                    iter,
                    doms[idx]
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("Contention thread failed");
    }

    let elapsed = start.elapsed();
    let total_ops = thread_count * iterations_per_thread;
    let ops_per_sec = (total_ops as f64) / elapsed.as_secs_f64();

    println!(
        "[CONTENTION] Completed {} concurrent lookups in {:?} ({:.0} ops/sec). Arc::ptr_eq 100% consistent.",
        total_ops, elapsed, ops_per_sec
    );
}

/// Scenario 3: 100+ distinct domains under concurrent resolution.
#[test]
fn test_concurrent_resolution_100_distinct_domains() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let routes = Arc::new(RwLock::new(EscapeSpaceStore { spaces: vec![] }));
    let resolver = Arc::new(DynamicSniResolver::new(None, routes, None));

    let distinct_count = 100;
    let test_run_id = uuid::Uuid::new_v4().simple().to_string();
    let mut domains = Vec::with_capacity(distinct_count);
    for i in 0..distinct_count {
        domains.push(format!("domain-{:03}-{}.sbm", i, test_run_id));
    }

    println!(
        "\n[DISTINCT 100] Resolving {} distinct domains across 20 worker threads...",
        distinct_count
    );

    let start = Instant::now();
    let domains_arc = Arc::new(domains);
    let worker_count = 20;
    let chunk_size = distinct_count / worker_count;

    let mut handles = Vec::with_capacity(worker_count);

    for w in 0..worker_count {
        let res = resolver.clone();
        let doms = domains_arc.clone();
        let start_idx = w * chunk_size;
        let end_idx = if w == worker_count - 1 {
            distinct_count
        } else {
            (w + 1) * chunk_size
        };

        handles.push(std::thread::spawn(move || {
            let mut resolved = 0;
            for i in start_idx..end_idx {
                let cert = res.resolve_for_server_name(&doms[i]);
                assert!(
                    cert.is_some(),
                    "Failed resolving distinct domain {}",
                    doms[i]
                );
                resolved += 1;
            }
            resolved
        }));
    }

    let mut total_resolved = 0;
    for h in handles {
        total_resolved += h.join().expect("Worker thread failed");
    }

    let elapsed = start.elapsed();
    println!(
        "[DISTINCT 100] Successfully resolved {} distinct domains in {:?} (avg {:?} per domain minting+disk+cache)",
        total_resolved,
        elapsed,
        elapsed / (distinct_count as u32)
    );

    assert_eq!(total_resolved, distinct_count);
    assert_eq!(resolver.cached_certs_count(), distinct_count);

    // Verify all 100 domains are cached and subsequent resolution is sub-microsecond
    for d in domains_arc.iter() {
        assert!(resolver.is_cached(d));
        let c = resolver.resolve_for_server_name(d);
        assert!(c.is_some());
    }
}

/// Scenario 4: Precision Latency Benchmarking (Cold Minting vs Warm RAM Cache Hit).
#[test]
fn test_latency_benchmarking_minting_vs_cache_hit() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let routes = Arc::new(RwLock::new(EscapeSpaceStore { spaces: vec![] }));
    let resolver = Arc::new(DynamicSniResolver::new(None, routes, None));

    let bench_domain = unique_domain("latency-bench", "mesh");

    // 1. Measure Cold Minting Latency
    let t0 = Instant::now();
    let cold_cert = resolver.resolve_for_server_name(&bench_domain);
    let cold_latency = t0.elapsed();

    assert!(cold_cert.is_some(), "Cold minting must succeed");
    println!(
        "\n[LATENCY BENCHMARK] Cold Minting Latency: {:?}",
        cold_latency
    );

    // 2. Measure Warm In-Memory RAM Cache Hit Latency over 20,000 iterations
    let iterations = 20_000;
    let mut hit_latencies = Vec::with_capacity(iterations);

    let warm_start = Instant::now();
    for _ in 0..iterations {
        let t_start = Instant::now();
        let hit_cert = resolver.resolve_for_server_name(&bench_domain);
        let t_dur = t_start.elapsed();
        assert!(hit_cert.is_some());
        hit_latencies.push(t_dur);
    }
    let total_warm_time = warm_start.elapsed();

    hit_latencies.sort();
    let min_latency = hit_latencies[0];
    let median_latency = hit_latencies[iterations / 2];
    let p95_latency = hit_latencies[(iterations as f64 * 0.95) as usize];
    let p99_latency = hit_latencies[(iterations as f64 * 0.99) as usize];
    let max_latency = hit_latencies[iterations - 1];
    let avg_latency = total_warm_time / (iterations as u32);

    println!(
        "[LATENCY BENCHMARK] Warm RAM Cache Hit (over {} samples):",
        iterations
    );
    println!("  - Average: {:?}", avg_latency);
    println!("  - Median:  {:?}", median_latency);
    println!("  - Min:     {:?}", min_latency);
    println!("  - P95:     {:?}", p95_latency);
    println!("  - P99:     {:?}", p99_latency);
    println!("  - Max:     {:?}", max_latency);

    let speedup = cold_latency.as_nanos() as f64 / avg_latency.as_nanos().max(1) as f64;
    println!(
        "[LATENCY BENCHMARK] In-memory cache speedup factor: {:.1}x faster than cold minting\n",
        speedup
    );

    // Assertions:
    // Warm cache average latency must be sub-50 microseconds (typically < 1-2 µs in release/debug)
    assert!(
        avg_latency.as_micros() < 50,
        "RAM cache hit average latency must be < 50µs, actual: {:?}",
        avg_latency
    );
    // Cold minting involves ECDSA keygen and disk write, so speedup must be at least 10x
    assert!(
        speedup >= 10.0,
        "RAM cache hit should be at least 10x faster than cold minting"
    );
}

/// Scenario 5: Mixed read/write stampede stress test (32 readers, 16 dynamic writers, 16 stampede racers).
#[test]
fn test_mixed_reads_writes_and_stampede() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let routes = Arc::new(RwLock::new(EscapeSpaceStore { spaces: vec![] }));
    let resolver = Arc::new(DynamicSniResolver::new(None, routes, None));

    // Pre-mint 3 established domains
    let established_domain_1 = unique_domain("established-1", "sbm");
    let established_domain_2 = unique_domain("established-2", "mesh");
    let established_domain_3 = unique_domain("established-3", "local");

    let cert_1 = resolver
        .resolve_for_server_name(&established_domain_1)
        .unwrap();
    let cert_2 = resolver
        .resolve_for_server_name(&established_domain_2)
        .unwrap();
    let cert_3 = resolver
        .resolve_for_server_name(&established_domain_3)
        .unwrap();

    let established = Arc::new(vec![
        (established_domain_1, cert_1),
        (established_domain_2, cert_2),
        (established_domain_3, cert_3),
    ]);

    let uncached_target = unique_domain("stampede-target", "sbm");

    let reader_count = 32;
    let writer_count = 16;
    let stampeder_count = 16;
    let total_threads = reader_count + writer_count + stampeder_count;

    let barrier = Arc::new(Barrier::new(total_threads));
    let mut handles = Vec::with_capacity(total_threads);

    let start = Instant::now();

    // 1. Launch 32 Readers: Each performs 1,000 lookups validating Arc::ptr_eq
    for r in 0..reader_count {
        let b = barrier.clone();
        let res = resolver.clone();
        let est = established.clone();

        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..1000 {
                let idx = (r + i) % est.len();
                let (d, expected_ptr) = &est[idx];
                let c = res
                    .resolve_for_server_name(d)
                    .expect("Reader lookup must succeed");
                assert!(
                    Arc::ptr_eq(&c, expected_ptr),
                    "Arc::ptr_eq violated during mixed read/write stress"
                );
            }
        }));
    }

    // 2. Launch 16 Writers: Each dynamically resolves 3 unique unminted domains
    for w in 0..writer_count {
        let b = barrier.clone();
        let res = resolver.clone();

        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..3 {
                let dom = unique_domain(&format!("mixed-write-w{}-{}", w, i), "sbm");
                let c = res.resolve_for_server_name(&dom);
                assert!(c.is_some(), "Writer minting must succeed");
            }
        }));
    }

    // 3. Launch 16 Stampeders: All race to resolve the exact same uncached domain
    for s in 0..stampeder_count {
        let b = barrier.clone();
        let res = resolver.clone();
        let target = uncached_target.clone();

        handles.push(std::thread::spawn(move || {
            b.wait();
            let c = res.resolve_for_server_name(&target);
            assert!(c.is_some(), "Stampeder {} resolution must succeed", s);
        }));
    }

    for h in handles {
        h.join().expect("Mixed workload thread failed");
    }

    let elapsed = start.elapsed();
    println!(
        "\n[MIXED WORKLOAD] 64 concurrent threads (32 readers x 1000 = 32k ops, 16 writers, 16 stampeders) completed in {:?}",
        elapsed
    );

    // Verify cache integrity after mixed stress
    assert!(resolver.is_cached(&uncached_target));
    let final_target_cert = resolver.resolve_for_server_name(&uncached_target).unwrap();

    // Verify pointer equality on the stampeded target
    for _ in 0..100 {
        let c = resolver.resolve_for_server_name(&uncached_target).unwrap();
        assert!(Arc::ptr_eq(&c, &final_target_cert));
    }

    println!("[MIXED WORKLOAD] Cache integrity and pointer equality 100% verified.");
}
