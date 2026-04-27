# dwell-agent

[![CI](https://github.com/your_actual_org/dwell-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/your_actual_org/dwell-agent/actions/workflows/ci.yml)

A production-grade **keystroke-dynamics continuous authentication agent** that builds a behavioural baseline of each user's typing rhythm and emits a real-time risk score.  
The score can drive policy actions (SIEM tagging, step-up MFA, session termination) without ever logging the keys themselves.

---

## Table of Contents

1. [How it works](#how-it-works)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Platform support](#platform-support)
5. [Quick start](#quick-start)
6. [Configuration](#configuration)
7. [Policy](#policy)
8. [IPC / streaming API](#ipc--streaming-api)
9. [Security notes](#security-notes)
10. [Development](#development)
11. [Testing](#testing)
12. [Contributing](#contributing)
13. [License](#license)

---

## How it works

```
Keyboard HW
    │  raw key-down / key-up events (timestamps in ns)
    ▼
[capture layer]          per-OS module (Linux evdev, macOS stub, Windows stub)
    │
    ▼  crossbeam channel
[feature extractor]      sliding window → 9-dimensional feature vector
    │                    mean/std dwell, mean/std flight, WPM, speed variance,
    │                    error rate, immediate- & deliberate-correction rates
    ▼
[baseline / EMA model]   encrypted profile (AES-256-GCM) on disk
    │  Mahalanobis distance → sigmoid → risk score 0-100
    ▼
[risk event]  ──broadcast──▶  [policy engine]  →  actions (log / SIEM / step-up / terminate)
                          └──▶  [IPC server]   →  UNIX socket, one JSON line per event
```

### Enrollment

The model is **self-enrolling**: the first `min_enrollment_keystrokes` (default 2 000) keystrokes are used purely to warm up the EMA baseline.  
No risk scores are emitted until enrollment is complete.

---

## Architecture

| Module | File | Responsibility |
|---|---|---|
| `capture` | `src/capture/` | OS-specific raw key event collection |
| `events` | `src/events.rs` | `KeystrokeEvent` data type |
| `features` | `src/features.rs` | Sliding-window feature extraction |
| `baseline` | `src/baseline.rs` | EMA model, AES-256-GCM persistence |
| `risk` | `src/risk.rs` | Mahalanobis distance, sigmoid scoring |
| `policy` | `src/policy.rs` | TOML-driven policy with hot-reload (inotify/FSEvents) |
| `ipc` | `src/ipc.rs` | UNIX socket server, newline-delimited JSON stream |
| `config` | `src/config.rs` | Layered config (defaults → TOML → env vars) |
| `main` | `src/main.rs` | Tokio runtime wiring, graceful shutdown |

---

## Features

- **Zero key-logging** – only timing metadata is recorded; keycodes are used solely for correction detection.
- **Encrypted profile** – the behavioural baseline is stored as AES-256-GCM ciphertext.
- **Continuous scoring** – configurable emit interval (default 30 s) with a sliding window.
- **Hot-reloadable policy** – edit `policy.toml` in place; changes apply within seconds via filesystem watching.
- **Structured JSON logging** – `tracing` with `tracing-subscriber` JSON output, ready for log shippers.
- **Graceful shutdown** – SIGTERM / SIGINT flush the encrypted profile to disk.
- **CI-friendly** – capture failures are non-fatal warnings (expected in headless environments).

---

## Platform support

| OS | Keystroke capture | Status |
|---|---|---|
| **Linux** | `evdev` (`/dev/input/event*`) | ✅ Production |
| **macOS** | Accessibility `CGEventTap` | ✅ Implemented (requires Accessibility permission) |
| **Windows** | Raw Input (`WM_INPUT`) | ✅ Implemented |

On macOS/Windows the agent starts and scores can be injected via the IPC socket for testing.

---

## Quick start

### Prerequisites

- Rust ≥ 1.75 (stable)
- Linux: read access to `/dev/input/event*` (usually requires the `input` group or `root`)

### Build

```bash
cargo build --release
```

### Run

```bash
# copy default configs
cp dwell-agent.toml.example dwell-agent.toml   # optional, defaults are built-in
cp policy.toml.example policy.toml             # optional

./target/release/dwell-agent
```

The agent writes structured JSON logs to stdout:

```json
{"timestamp":"2026-04-25T10:00:00Z","level":"INFO","fields":{"message":"Risk assessment","risk_score":12,"confidence":0.87}}
```

---

## Configuration

Configuration is loaded in order (later sources override earlier):

1. Built-in defaults
2. `dwell-agent.toml` in the working directory
3. Environment variables prefixed with `DWELL_`

| Key | Default | Description |
|---|---|---|
| `window_size` | `50` | Max keystroke events in the sliding window |
| `emit_interval_secs` | `30` | How often a risk score is emitted (seconds) |
| `min_enrollment_keystrokes` | `2000` | Keystrokes before scoring begins |
| `ema_alpha` | `0.05` | EMA learning rate (0–1, smaller = slower adaptation) |
| `risk_threshold` | `5.0` | Mahalanobis distance centred in sigmoid |
| `risk_k` | `1.0` | Sigmoid steepness |
| `policy_file` | `policy.toml` | Path to the policy configuration |
| `profile_path` | `profile.enc` | Path to the encrypted baseline profile |
| `log_level` | `info` | Logging verbosity: `debug`, `info`, `warn`, `error` |
| `ipc_socket` | `/tmp/dwell-agent.sock` | UNIX domain socket path |
| `webhook_url` | _(none)_ | Optional HTTP endpoint that receives each `RiskEvent` as JSON |
| `webhook_min_risk_score` | `0` | Only send webhook events at/above this risk score |
| `webhook_timeout_secs` | `5` | HTTP timeout for webhook delivery attempts |
| `metrics_log_interval_secs` | `60` | Interval for periodic runtime health logs |

**Environment variable example:**

```bash
DWELL_RISK_THRESHOLD=3.0 DWELL_LOG_LEVEL=debug ./dwell-agent
```

---

## Policy

`policy.toml` defines risk tiers and the actions triggered per tier.  
The file is watched for changes at runtime; no restart is needed.

```toml
[tiers]
low_max = 40   # risk score 0-40 → Low
med_max = 70   # risk score 41-70 → Medium
               # risk score 71-100 → High

[actions]
low  = ["log"]
med  = ["log", "emit_siem_tag", "trigger_re_verification"]
high = ["log", "emit_siem_tag", "trigger_step_up", "terminate_session"]
```

### Available actions

| Action string | Meaning |
|---|---|
| `log` | Emit a structured log line |
| `emit_siem_tag` | Placeholder for SIEM integration |
| `trigger_re_verification` | Prompt user for passive re-auth |
| `trigger_step_up` | Require MFA step-up |
| `terminate_session` | Force session termination |

---

## IPC / streaming API

Connect to the UNIX socket to receive a **newline-delimited JSON stream** of `RiskEvent` objects:

```bash
nc -U /tmp/dwell-agent.sock
```

### RiskEvent schema

```jsonc
{
  "session_id": "uuid-v4",
  "timestamp_utc": "2026-04-25T10:00:00+00:00",
  "risk_score": 12,          // 0-100
  "confidence": 0.87,        // 0.0-1.0
  "anomalous_features": [],  // list of feature names exceeding 2σ
  "window_keystrokes": 47,
  "model_version": "1.0.0"
}
```

### Management commands

Send commands over the same socket (newline-delimited text):

| Command | Effect |
|---|---|
| `status` | Logs runtime counters (uptime, keystrokes, emitted risks, webhook stats) |
| `reload-policy` | Re-reads `policy_file` from disk |

### Webhook payload

If `webhook_url` is configured, the agent sends `POST` requests with the exact `RiskEvent` JSON schema shown above.
Delivery behavior:

- up to 3 attempts per event
- exponential backoff (`250ms`, `500ms`)
- send only events with `risk_score >= webhook_min_risk_score`

---

## Security notes

- **Key management**: the default key (`0x42` × 32) is a placeholder for CI.  
  In production, derive the profile key from the OS keychain (e.g. macOS Keychain, Linux kernel keyring, or a TPM-backed secret). Ensure that the key is stored securely and not hard-coded in the source code.
- **Privilege separation**: run as a dedicated low-privilege user; grant only `/dev/input` group membership on Linux.
- **Profile integrity**: AES-256-GCM provides both confidentiality and authentication. A corrupted or tampered profile will fail to load and be replaced by a fresh one.

---

## Development

```bash
# check with clippy
cargo clippy -- -D warnings

# format
cargo fmt

# run tests
cargo test

# run with verbose logging
DWELL_LOG_LEVEL=debug cargo run
```

### Adding a new platform

1. Create `src/capture/<os>.rs` implementing `KeystrokeCapture`.
2. Add the conditional compilation guard in `src/capture/mod.rs`.
3. Add target-specific dependencies to `Cargo.toml` if needed.

---

## Testing

The test suite lives alongside each module (`#[cfg(test)]`):

| Module | Tests |
|---|---|
| `baseline` | EMA update, enrollment threshold, encrypt/decrypt round-trip |
| `features` | Dwell/flight extraction, correction-rate logic, outlier filtering, `to_vec`, proptest no-panic |
| `risk` | Identical-feature low risk, extreme anomaly high risk, anomalous-feature detection, sigmoid/Mahalanobis checks |
| `policy` | Tier mapping, boundary checks, action parsing, reload from TOML |
| `monitoring` | Atomic counter increments and snapshot sanity |
| `config` | Default configuration sanity and serde round-trip |

Run:

```bash
cargo test
```

For coverage (requires `cargo-llvm-cov`):

```bash
cargo install cargo-llvm-cov
cargo llvm-cov --html
open target/llvm-cov/html/index.html
```

For a line coverage report in CI-compatible format:

```bash
cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info
```

Performance benchmark (Criterion):

```bash
# run full benchmark suite
cargo bench --bench feature_extraction

# CI smoke check (compile benches only)
cargo bench --bench feature_extraction --no-run
```

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Ensure `cargo clippy -- -D warnings` and `cargo test` pass.
4. Open a pull request against `main`.

---

## License

Licensed under the [MIT License](LICENSE).

