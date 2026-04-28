# Production runbook

## Secrets

- Set `DWELL_PROFILE_KEY` from a secret store.
- Do not enable `allow_insecure_placeholder_key` outside local development.

## Recommended runtime paths

- Linux state directory: `/var/lib/dwell-agent`
- Linux env file: `/etc/dwell-agent/dwell-agent.env`
- macOS working directory: `/usr/local/var/dwell-agent`
- Windows state directory: `C:\ProgramData\dwell-agent`
- Webhook spool: keep on persistent storage, not `/tmp`

## Windows service operations

- Install: `deploy/windows/install-service.ps1`
- Uninstall: `deploy/windows/uninstall-service.ps1`

Example install (elevated PowerShell):

```powershell
pwsh -File deploy/windows/install-service.ps1 -ExePath C:\path\to\dwell-agent.exe -ConfigPath C:\path\to\dwell-agent.toml -ProfileKey <64-char-hex> -StartAfterInstall
```

The installer stores `DWELL_PROFILE_KEY` as a service-scoped environment value (not machine-wide) when `-ProfileKey` is provided.

Example removal:

```powershell
pwsh -File deploy/windows/uninstall-service.ps1 -RemoveStateDir
```

## Startup checks

1. Confirm the profile key is present.
2. Confirm the policy file is readable.
3. Confirm the profile path parent directory is writable.
4. Confirm the management endpoint is bound only to loopback.
5. Confirm webhook spool storage has free space.
6. Confirm Linux input-device permissions or macOS Accessibility access.

## Health endpoints

- `GET /healthz` returns JSON status plus current counters.
- `GET /readyz` returns readiness status (`200` when ready, `503` when not ready).
- `GET /metrics` returns Prometheus-compatible metrics.

Default bind address: `127.0.0.1:9464`

## IPC transport

- Unix platforms use `ipc_socket` (default `/tmp/dwell-agent/dwell-agent.sock`).
- Non-Unix platforms use `ipc_tcp_bind` (default `127.0.0.1:9465`).
- Keep IPC on loopback-only addresses. On non-Unix, peer UID checks are not available, so `ipc_require_same_user` cannot be enforced by kernel peer credentials.

## Important metrics

- `dwell_agent_profile_save_failures_total`
- `dwell_agent_profile_load_failures_total`
- `dwell_agent_profile_recoveries_total`
- `dwell_agent_webhook_failures_total`
- `dwell_agent_webhook_queue_depth`
- `dwell_agent_action_failures_total`
- `dwell_agent_capture_start_failures_total`
- `dwell_agent_policy_reload_failures_total`

## Recovery behavior

- The agent writes an encrypted profile backup alongside the main profile as `<profile>.bak`.
- If the primary profile is unreadable, it is quarantined and the backup is restored automatically.
- If both primary and backup fail, the agent creates a new baseline profile.

## Webhook outage handling

- Risk events are written to the durable webhook spool before delivery.
- Failed deliveries remain queued and are replayed after restart.
- Alert if queue depth grows continuously.

## Incident response

### Profile corruption

1. Inspect quarantine files near the profile path.
2. Verify disk health and permissions.
3. Confirm the correct `DWELL_PROFILE_KEY` is injected.
4. Restore from backup if automatic recovery was not possible.

### Webhook failures

1. Check `dwell_agent_webhook_failures_total` and queue depth.
2. Verify remote endpoint health and TLS trust.
3. Drain the spool after the destination recovers.

### Policy hook failures

1. Inspect `dwell_agent_action_failures_total`.
2. Validate configured command hooks in `dwell-agent.toml`.
3. Run hooks manually with the same environment if needed.

## Restore flow

1. Stop the agent.
2. Backup the current state directory.
3. Restore `profile.enc` or `profile.enc.bak`.
4. Start the agent and validate `/healthz` and `/metrics`.
