use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dwell_agent::baseline::BaselineProfile;
use dwell_agent::events::{EventType, KeystrokeEvent};
use dwell_agent::features::FeatureExtractor;
use dwell_agent::keystore::PLACEHOLDER_KEY;
use dwell_agent::risk::RiskScorer;
use dwell_agent::webhook::WebhookSpool;
use std::fs;
use uuid::Uuid;

// ─── Memory & Throughput Tests ──────────────────────────────────────────────

fn synthetic_keystroke_stream(n_keystrokes: usize, start_ns: u64) -> Vec<KeystrokeEvent> {
    let mut events = Vec::with_capacity(n_keystrokes * 2);
    let mut ts = start_ns;
    let session_id = Uuid::new_v4();

    for i in 0..n_keystrokes {
        let key_code = 30 + (i as u32 % 20);
        events.push(KeystrokeEvent {
            key_code,
            event_type: EventType::KeyDown,
            timestamp_ns: ts,
            session_id,
        });
        ts += 35_000_000; // 35 ms dwell
        events.push(KeystrokeEvent {
            key_code,
            event_type: EventType::KeyUp,
            timestamp_ns: ts,
            session_id,
        });
        ts += 45_000_000; // 45 ms flight
    }

    events
}

fn bench_sustained_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("sustained_load");
    group.sample_size(10); // Reduced sample size for long-running tests

    for n_keys in [1000, 5000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}k_keystrokes", n_keys / 1000)),
            n_keys,
            |b, &n_keys| {
                b.iter(|| {
                    let events = synthetic_keystroke_stream(n_keys, 0);
                    let mut profile = BaselineProfile::new(9, 0.05);
                    let scorer = RiskScorer::new(5.0, 1.0);
                    let session_id = Uuid::new_v4();

                    // Simulate continuous processing: extract → update → score
                    let window_size = 50;
                    let mut start = 0;
                    while start + window_size <= events.len() {
                        let window = &events[start..start + window_size];
                        let kd = window
                            .iter()
                            .filter(|e| e.event_type == EventType::KeyDown)
                            .count();
                        let fv = FeatureExtractor::extract(window);
                        profile.update(&fv.to_vec(), kd);
                        criterion::black_box(scorer.score(
                            session_id,
                            &fv.to_vec(),
                            &profile,
                            kd as u32,
                        ));
                        start += window_size;
                    }

                    criterion::black_box(profile)
                });
            },
        );
    }

    group.finish();
}

fn bench_profile_persistence_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("profile_persistence");
    let key = PLACEHOLDER_KEY;

    for n_updates in [100, 500, 1000].iter() {
        let mut profile = BaselineProfile::new(9, 0.05);
        let fv = [100.0f64, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2];
        for _ in 0..*n_updates {
            profile.update(&fv, 50);
        }

        let encrypted = profile.to_encrypted_bytes(&key).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_updates", n_updates)),
            &encrypted,
            |b, data| {
                b.iter(|| {
                    dwell_agent::baseline::BaselineProfile::from_encrypted_bytes(
                        criterion::black_box(data),
                        criterion::black_box(&key),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_webhook_spool_operations(c: &mut Criterion) {
    let temp_dir = "/tmp/dwell_bench_spool";
    let _ = fs::remove_dir_all(temp_dir);

    let mut group = c.benchmark_group("webhook_spool");
    group.sample_size(10);

    for n_events in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_events", n_events)),
            n_events,
            |b, &n_events| {
                let spool = WebhookSpool::new(temp_dir).unwrap();
                let events: Vec<_> = (0..n_events)
                    .map(|i| dwell_agent::risk::RiskEvent {
                        session_id: Uuid::new_v4(),
                        timestamp_utc: chrono::Utc::now().to_rfc3339(),
                        risk_score: (i as u8) % 100,
                        confidence: 0.85,
                        anomalous_features: vec![],
                        window_keystrokes: 50,
                        model_version: "0.1.0".to_string(),
                    })
                    .collect();

                b.iter(|| {
                    for event in &events {
                        criterion::black_box(spool.enqueue(criterion::black_box(event))).ok();
                    }
                });
            },
        );
    }

    group.finish();
    let _ = fs::remove_dir_all(temp_dir);
}

criterion_group!(
    benches,
    bench_sustained_load,
    bench_profile_persistence_throughput,
    bench_webhook_spool_operations
);
criterion_main!(benches);
