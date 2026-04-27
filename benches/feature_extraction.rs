use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use dwell_agent::baseline::BaselineProfile;
use dwell_agent::events::{EventType, KeystrokeEvent};
use dwell_agent::features::FeatureExtractor;
use dwell_agent::keystore::PLACEHOLDER_KEY;
use dwell_agent::risk::RiskScorer;
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

// ─── helpers ──────────────────────────────────────────────────────────────────

/// Build a warm baseline profile with `n_updates` identical feature vectors.
fn warmed_profile(n_updates: usize) -> BaselineProfile {
    let mut p = BaselineProfile::new(9, 0.05);
    let fv = [100.0f64, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2];
    for _ in 0..n_updates {
        p.update(&fv, 50);
    }
    p
}

// ─── baseline update ──────────────────────────────────────────────────────────

fn bench_baseline_update(c: &mut Criterion) {
    let fv = [100.0f64, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2];
    let mut profile = BaselineProfile::new(9, 0.05);
    c.bench_function("baseline_update/9d", |b| {
        b.iter(|| profile.update(criterion::black_box(&fv), 50));
    });
}

// ─── risk scoring ─────────────────────────────────────────────────────────────

fn bench_risk_scoring(c: &mut Criterion) {
    let profile = warmed_profile(200);
    let scorer = RiskScorer::new(5.0, 1.0);
    let fv = [100.0f64, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2];
    let session_id = Uuid::nil();

    c.bench_function("risk_scoring/9d", |b| {
        b.iter(|| {
            criterion::black_box(scorer.score(
                criterion::black_box(session_id),
                criterion::black_box(&fv),
                criterion::black_box(&profile),
                50,
            ))
        });
    });
}

// ─── profile AES-256-GCM encrypt/decrypt ─────────────────────────────────────

fn bench_profile_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("profile_crypto");
    let profile = warmed_profile(100);
    let key = PLACEHOLDER_KEY;

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            criterion::black_box(
                profile
                    .to_encrypted_bytes(criterion::black_box(&key))
                    .unwrap(),
            )
        });
    });

    group.bench_function("decrypt", |b| {
        let ct = profile.to_encrypted_bytes(&key).unwrap();
        b.iter(|| {
            criterion::black_box(
                BaselineProfile::from_encrypted_bytes(
                    criterion::black_box(&ct),
                    criterion::black_box(&key),
                )
                .unwrap(),
            )
        });
    });

    group.finish();
}

// ─── full pipeline (extract → update → score) ────────────────────────────────

fn bench_full_pipeline(c: &mut Criterion) {
    let scorer = RiskScorer::new(5.0, 1.0);
    let session_id = Uuid::nil();
    let mut profile = warmed_profile(100);

    c.bench_function("full_pipeline/window50", |b| {
        b.iter_batched(
            || synthetic_events(50),
            |events| {
                let kd = events
                    .iter()
                    .filter(|e| e.event_type == EventType::KeyDown)
                    .count();
                let fv = FeatureExtractor::extract(&events);
                let vec = fv.to_vec();
                profile.update(&vec, kd);
                criterion::black_box(scorer.score(session_id, &vec, &profile, kd as u32))
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_feature_extraction,
    bench_baseline_update,
    bench_risk_scoring,
    bench_profile_crypto,
    bench_full_pipeline,
);
criterion_main!(benches);
