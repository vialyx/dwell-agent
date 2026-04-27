use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use dwell_agent::events::{EventType, KeystrokeEvent};
use dwell_agent::features::FeatureExtractor;
use uuid::Uuid;

fn synthetic_events(n_keys: usize) -> Vec<KeystrokeEvent> {
    let mut events = Vec::with_capacity(n_keys * 2);
    let mut ts = 0u64;
    let session_id = Uuid::nil();

    for i in 0..n_keys {
        let key_code = 30 + (i as u32 % 20);
        events.push(KeystrokeEvent {
            key_code,
            event_type: EventType::KeyDown,
            timestamp_ns: ts,
            session_id,
        });
        ts += 35_000_000;
        events.push(KeystrokeEvent {
            key_code,
            event_type: EventType::KeyUp,
            timestamp_ns: ts,
            session_id,
        });
        ts += 45_000_000;
    }

    events
}

fn bench_feature_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("feature_extraction");

    for n in [50usize, 100, 250, 500] {
        group.bench_function(format!("window_{n}"), |b| {
            b.iter_batched(
                || synthetic_events(n),
                |events| {
                    let fv = FeatureExtractor::extract(&events);
                    criterion::black_box(fv.to_vec());
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_feature_extraction);
criterion_main!(benches);
