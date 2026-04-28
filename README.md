# dwell-agent

CI: see [.github/workflows/ci.yml](.github/workflows/ci.yml)

A Rust **keystroke-dynamics continuous authentication agent** that builds a behavioural baseline of each user's typing rhythm and emits a periodic risk score.  
The score can drive policy actions (SIEM tagging, step-up MFA, session termination) without ever storing typed characters.

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
10. [Deployment](#deployment)
11. [Operations](#operations)
12. [Development](#development)
13. [Testing](#testing)
14. [Contributing](#contributing)
15. [License](#license)

---

## How it works

```
Keyboard HW
  │  raw key-down / key-up events (timestamps in ns)
    ▼
[capture layer]          per-OS module (Linux evdev, macOS CGEventTap, Windows Raw Input backend)
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
                          └──▶  [IPC server]   →  newline-delimited JSON stream (Unix socket or loopback TCP)
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
| `ipc` | `src/ipc.rs` | Cross-platform IPC stream (`AF_UNIX` on Unix, loopback TCP on non-Unix) |
| `config` | `src/config.rs` | Layered config (defaults → TOML → env vars) |
| `main` | `src/main.rs` | Tokio runtime wiring, graceful shutdown |

---

## Features

- **Zero key-logging** – only timing metadata is recorded; keycodes are used solely for correction detection.
- **Encrypted profile** – the behavioural baseline is stored as AES-256-GCM ciphertext.
- **Crash-tolerant persistence** – the profile is autosaved periodically, backed up alongside the main file, and recovered automatically when the primary copy is unreadable.
- **Continuous scoring** – configurable emit interval (default 30 s) over a sliding event window.
- **Hot-reloadable policy** – `policy.toml` changes are watched automatically when the file exists at startup, and can also be reloaded manually over IPC.
- **Executable policy hooks** – risk tiers can trigger external commands for SIEM tagging, re-verification, step-up MFA, or session termination.
- **Durable webhook delivery** – optional HTTP `POST` of each `RiskEvent`, with retries, exponential backoff, and an on-disk replay spool.
- **Management API** – local `/healthz`, `/readyz`, and `/metrics` endpoints for liveness, readiness, and Prometheus scraping.
- **Structured JSON logging** – `tracing` with `tracing-subscriber` JSON output, ready for log shippers.
- **Runtime health metrics** – counters for keystrokes, emitted risks, commands, action hooks, profile saves/recovery, and webhook queue depth.
- **Graceful shutdown** – SIGTERM / SIGINT flush the encrypted profile to disk on Unix builds.
- **CI-friendly** – capture failures are non-fatal warnings (expected in headless environments).

---

## Platform support

| OS | Capture backend | Full agent runtime | Notes |
|---|---|---|---|
| **Linux** | `evdev` (`/dev/input/event*`) | ✅ Supported | Recommended production target; see `deploy/systemd/dwell-agent.service` |
| **macOS** | Accessibility `CGEventTap` | ✅ Supported | Requires Accessibility permission; see `deploy/launchd/com.dwell-agent.plist` |
| **Windows** | Raw Input (`WM_INPUT`) backend in `src/capture/windows.rs` | ✅ Supported | Uses loopback TCP IPC (`ipc_tcp_bind`) instead of Unix sockets; `ipc_require_same_user` cannot be enforced with peer UID on this platform |

---

## Quick start

### Prerequisites

- Stable Rust toolchain
- Linux: read access to `/dev/input/event*` (usually requires the `input` group or `root`)
- macOS: grant Accessibility access to the built binary or `cargo run` host process

### Configure

The repository already includes sample config files in place:

- `dwell-agent.toml`
- `policy.toml`

You can edit them directly, or rely on built-in defaults and only override selected values.

For encrypted profile storage, set `DWELL_PROFILE_KEY` to a 64-character hex string:

```bash
export DWELL_PROFILE_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

For **local smoke tests only**, you can instead set `allow_insecure_placeholder_key = true` in `dwell-agent.toml`. That uses the hard-coded placeholder key `[0x42; 32]` and must never be used in production.

### Build

```bash
cargo build --release
```

### Run

```bash
./target/release/dwell-agent
```

Or run from source:

```bash
cargo run --release
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

The encryption key is handled separately by `DWELL_PROFILE_KEY`; it is **not** part of the TOML config loader.

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
| `profile_autosave_secs` | `300` | Periodic autosave interval for the encrypted profile |
| `log_level` | `info` | Logging verbosity: `debug`, `info`, `warn`, `error` |
| `ipc_socket` | `/tmp/dwell-agent/dwell-agent.sock` | UNIX domain socket path |
| `ipc_tcp_bind` | `127.0.0.1:9465` | Non-Unix IPC bind address for newline-delimited JSON stream + commands |
| `ipc_require_same_user` | `true` | Reject IPC clients with a different OS user ID |
| `management_bind` | `127.0.0.1:9464` | Local management API bind address for `/healthz`, `/readyz`, `/metrics` |
| `allow_insecure_placeholder_key` | `false` | Allow `[0x42;32]` profile key only for CI/dev (never production) |
| `webhook_url` | _(none)_ | Optional HTTP endpoint that receives each `RiskEvent` as JSON |
| `webhook_spool_dir` | `webhook-spool` | Durable spool directory for queued webhook events |
| `webhook_min_risk_score` | `0` | Only send webhook events at/above this risk score |
| `webhook_timeout_secs` | `5` | HTTP timeout for webhook delivery attempts |
| `metrics_log_interval_secs` | `60` | Interval for periodic runtime health logs |
| `action_hook_timeout_secs` | `15` | Max runtime for each policy action hook before forced termination |

`webhook_url = ""` in the checked-in `dwell-agent.toml` effectively disables webhook delivery.

**Environment variable example:**

```bash
DWELL_RISK_THRESHOLD=3.0 DWELL_LOG_LEVEL=debug cargo run --release
```

### Action hooks

The checked-in `dwell-agent.toml` also supports an optional `[action_hooks]` section. Each configured value is an argv-style command array executed when the matching policy action is selected.

```toml
[action_hooks]
emit_siem_tag = ["/usr/local/bin/siem-tag", "--source", "dwell-agent"]
trigger_re_verification = ["/usr/local/bin/reverify-session"]
trigger_step_up = ["/usr/local/bin/step-up-mfa"]
terminate_session = ["/usr/local/bin/terminate-session"]
```

Each hook receives these environment variables:

- `DWELL_ACTION`
- `DWELL_SESSION_ID`
- `DWELL_RISK_SCORE`
- `DWELL_CONFIDENCE`
- `DWELL_RISK_EVENT`

Hooks are bounded by `action_hook_timeout_secs`; long-running hooks are terminated and counted as failures.

---

## Policy

`policy.toml` defines risk tiers and the actions triggered per tier.  
If the file exists when the agent starts, it is watched for changes at runtime; no restart is needed.  
You can also trigger a reload manually with the IPC `reload-policy` command.

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
| `emit_siem_tag` | Run the configured SIEM tagging command hook |
| `trigger_re_verification` | Run the configured passive re-verification command hook |
| `trigger_step_up` | Run the configured MFA step-up command hook |
| `terminate_session` | Run the configured session termination command hook |

---

## IPC / streaming API

Connect to the IPC endpoint to receive a **newline-delimited JSON stream** of `RiskEvent` objects:

```bash
# Unix
nc -U /tmp/dwell-agent/dwell-agent.sock

# Non-Unix (for example Windows)
nc 127.0.0.1 9465
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

Command results are written to the agent logs; the socket itself remains a stream of `RiskEvent` JSON lines.

### Management HTTP endpoints

The agent also exposes a loopback-only management API on `management_bind`:

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness + current runtime counters in JSON |
| `GET /readyz` | Readiness status in JSON (`200` when ready, `503` when not ready) |
| `GET /metrics` | Prometheus-compatible text metrics |

### Webhook payload

If `webhook_url` is configured, the agent sends `POST` requests with the exact `RiskEvent` JSON schema shown above.
Delivery behavior:

- up to 3 attempts per event
- exponential backoff (`250ms`, `500ms`)
- send only events with `risk_score >= webhook_min_risk_score`
- queue each event on disk in `webhook_spool_dir` before durable delivery
- replay queued events automatically after restart

---

## Security notes

- **Key management**: production is fail-closed. `DWELL_PROFILE_KEY` is required by default.  
  The placeholder key (`0x42` × 32) is only available if `allow_insecure_placeholder_key=true`.
- **Loopback-only management surface**: `management_bind` is validated to a loopback address so health and metrics endpoints are not exposed remotely by accident.
- **Privilege separation**: run as a dedicated low-privilege user; grant only `/dev/input` group membership on Linux.
- **Profile integrity**: AES-256-GCM provides both confidentiality and authentication. A corrupted or tampered profile will be quarantined and recovered from backup when possible.
- **Webhook durability**: outbound events remain on disk until they are acknowledged by the remote endpoint.

---

## Deployment

Sample service assets are included for common production targets:

- Linux `systemd`: `deploy/systemd/dwell-agent.service`
- macOS `launchd`: `deploy/launchd/com.dwell-agent.plist`
- Windows PowerShell installers: `deploy/windows/install-service.ps1`, `deploy/windows/uninstall-service.ps1`

### Windows service install

Run from an elevated PowerShell prompt:

```powershell
pwsh -File deploy/windows/install-service.ps1 -ExePath C:\path\to\dwell-agent.exe -ConfigPath C:\path\to\dwell-agent.toml -ProfileKey <64-char-hex> -StartAfterInstall
```

Remove later with:

```powershell
pwsh -File deploy/windows/uninstall-service.ps1 -RemoveStateDir
```

Recommended production state layout:

- profile and spool under a persistent state directory such as `/var/lib/dwell-agent`
- service-scoped secret injection for `DWELL_PROFILE_KEY` (avoid machine-wide env vars)
- loopback-only management endpoint scraped by a local collector or reverse proxy sidecar

---

## Operations

- Production runbook: [docs/production-runbook.md](docs/production-runbook.md)
- Monitor `dwell_agent_webhook_queue_depth` for sustained webhook outages.
- Monitor `dwell_agent_profile_save_failures_total` and `dwell_agent_profile_recoveries_total` for persistence issues.
- Monitor `dwell_agent_action_failures_total` for broken policy hooks.

---

## Development

```bash
# check with clippy
cargo clippy --all-targets --all-features -- -D warnings

# format
cargo fmt --all

# run tests
cargo test --all-targets --all-features

# audit dependencies
cargo audit

# generate an SBOM
cargo cyclonedx --format json --output-file sbom.json

# run with verbose logging
DWELL_LOG_LEVEL=debug cargo run
```

### Adding a new platform

1. Create `src/capture/<os>.rs` implementing `KeystrokeCapture`.
2. Add the conditional compilation guard in `src/capture/mod.rs`.
3. Add target-specific dependencies to `Cargo.toml` if needed.

---

## Testing

The test suite includes both module-local unit tests and end-to-end integration coverage in `tests/integration.rs`.

| Area | Coverage |
|---|---|
| `baseline` | EMA update, enrollment threshold, encrypt/decrypt round-trip, backup creation, recovery fallback |
| `features` | Dwell/flight extraction, correction-rate logic, outlier filtering, `to_vec`, proptest no-panic |
| `risk` | Identical-feature low risk, extreme anomaly high risk, anomalous-feature detection, sigmoid/Mahalanobis checks |
| `policy` | Tier mapping, boundary checks, action parsing, reload from TOML |
| `actions` | Hook success/failure/skip accounting |
| `monitoring` | Atomic counter increments, queue depth saturation, snapshot sanity |
| `config` | Default configuration sanity, serde round-trip, management bind validation |
| `management` | Prometheus rendering and health response generation |
| `webhook` | Durable queueing, failure accounting, replay after restart |
| `ipc` / integration | Command delivery, streamed `RiskEvent`s, runtime pipeline wiring |

Run:

```bash
cargo test --all-targets --all-features
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
cargo bench --all-features --bench feature_extraction --no-run
```

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Ensure `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features` pass.
4. Open a pull request against `main`.

---

## License

Licensed under the [MIT License](LICENSE).

