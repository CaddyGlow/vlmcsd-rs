use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use vlmcsd_protocol::{ActivationRequest, HostConfig, PreparedHost, Version, respond_into};

fn measure(name: &str, mut operation: impl FnMut()) {
    for _ in 0..1000 {
        operation();
    }
    let start = Instant::now();
    let mut iterations = 0u64;
    while start.elapsed() < Duration::from_secs(1) {
        for _ in 0..100 {
            operation();
        }
        iterations += 100;
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "{name}: {:.0} ns/op ({iterations} iterations)",
        elapsed * 1e9 / iterations as f64
    );
}

fn main() {
    let host = PreparedHost::new(&HostConfig::default()).unwrap();
    for version in [Version::V4, Version::V5, Version::V6] {
        let mut request =
            ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133_000_000_000_000_000);
        request.version = version;
        let encoded = request.encode([5; 16]).unwrap();
        let mut response = Vec::with_capacity(512);
        respond_into(encoded.as_bytes(), &host, &mut response, [6; 16], [7; 16]).unwrap();
        encoded.verify_response(&response).unwrap();
        measure(&format!("{version:?} encode"), || {
            black_box(black_box(&request).encode(black_box([5; 16])).unwrap());
        });
        measure(&format!("{version:?} respond (reused output)"), || {
            response.clear();
            respond_into(
                black_box(encoded.as_bytes()),
                black_box(&host),
                &mut response,
                black_box([6; 16]),
                black_box([7; 16]),
            )
            .unwrap();
            black_box(&response);
        });
        measure(&format!("{version:?} verify"), || {
            black_box(encoded.verify_response(black_box(&response)).unwrap());
        });
    }
}
