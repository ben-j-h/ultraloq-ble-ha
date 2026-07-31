# chaseflick4 fork merge — research and current status

Working notes for `merge/chaseflick4-hardening`. Written to pick this up cleanly in a
fresh session — read this before re-deriving anything below by re-reading the diff.

## What this branch is

Merges `chaseflick4/ultraloq-ble-ha` (a hardened fork, diverged at `81a79ee`) into our
own fork, then fixes three additional defects found by testing the merged code against
real hardware. See `git log main..HEAD` for the full commit list.

## Part 1 — what came from the fork (commit `9acc202`, cleanup `998f12b`)

Verified by reading the actual diffs, not just commit messages, before porting:

- **Command mutex** (`utecio/ble/device.py`, `execute()`): `is_busy` was set but never
  checked. A 30s autolock poll racing a user command drained the shared `_requests`
  list and both failed. Fixed with `asyncio.Lock` + `execute(queue_closure,
  skip_if_busy=)`.
- **Notification handler leak**: every request re-subscribed to the same DATA
  characteristic; completed responses stayed attached and re-parsed later
  notifications. Fixed with one subscription per connection, dispatched via
  `_active_response`.
- **Credential-logging fix**: the cleartext ADMIN_LOGIN packet (uid + PIN) was being
  logged via `plain=%s`, defeating the adjacent password redaction. Removed.
- **Credential-storage rework**: stopped persisting Xthings email/password. Added
  `enrollment.py` (minimizes cloud data to just what BLE needs), config entry
  `VERSION = 2` with `async_migrate_entry`, and a native HA **Reconfigure** flow
  replacing the old `refresh_locks` service.
- **Test suite**: ~900 lines added (golden protocol vectors, asyncio interleaving
  tests for the mutex, a static AST guard against sensitive values entering log
  calls).

**Adjusted from the fork's version, not taken as-is:**
- The fork's log-scrubbing AST guard (`tests/test_no_sensitive_logging.py`) banned
  lock names and MAC addresses from all logs, not just secrets. Relaxed to keep
  `mac_uuid`/`address`/`sn`/`wurx_uuid` visible — needed for multi-lock debugging —
  while still banning `uid`/`password`/`admin_pin`/`aes_key`/`token`/packet bytes.
- Kept our own `select.py` (lock-mode entity) and de-forked all branding
  (manifest, hacs.json, README, issue templates point at our repo, not
  chaseflick4's).
- **Did not** revert the fork's stricter `InvalidResponse`/decode-error handling in
  `api.py`/`util.py` as originally planned — its own tests
  (`test_cloud_error_text_is_not_propagated`,
  `test_cloud_decode_exception_does_not_log_remote_text`) exist because the Xthings
  cloud API is untrusted input; a compromised server or MITM could inject arbitrary
  text into exceptions/logs. Different threat model from the lock-name scrubbing,
  correctly left as the fork wrote it.
- Found and fixed a gap the fork's port introduced: `select.py` predates the fork and
  didn't know about the new `UtecBleDeviceBusyError` — it would have propagated
  unhandled from `async_select_option`. Wired up like `button.py`/`lock.py`.
- `hacs.json` minimum HA version set to `2024.10.0` (when the reconfigure-flow APIs
  shipped — [HA blog post](https://developers.home-assistant.io/blog/2024/10/21/reauth-reconfigure-helpers/)),
  not the fork's arbitrary `2026.7.2` pin.

## Part 2 — bugs found by testing on real hardware (commit `0395b10`)

Tested against a disposable HA OS test instance (not the live household system) with
two real Ultraloq locks (Utility Room Door, Shed Door) over ESPHome Bluetooth proxies.

### Bug 1: real error causes were being discarded

`_get_response()` already raised a specific, secret-free error (timed out / rejected
by lock / transport failure). But `send_requests()`'s loop caught it and replaced it
with a generic `"Command X failed"`, discarding which one it was. Every BLE failure
looked identical in logs. Fixed by letting the specific error propagate, only wrapping
exceptions outside our `Utec*` hierarchy (e.g. raw `BleakError`) so callers that only
catch `Utec*` exceptions don't see them escape unhandled and 500 the API.

### Bug 2 (the important one): lock state could desync from physical reality

Fixing bug 1 surfaced this: `write_gatt_char()`'s write-acknowledgement can fail
*after* the lock already executed the command and sent back a valid, successful
notification response — the notify callback runs concurrently with the write await,
not nested inside it. Confirmed directly: issued `unlock`, HA reported failure and
kept showing `locked`, physically checked the door — **it was unlocked**. HA's
displayed state was wrong in the dangerous direction (implying secured when it
wasn't).

Fix: `_get_response()` only treats a write exception as real if no response has
arrived yet (`self.response.completed`). If a valid response already came in, the
write error is stale/spurious and gets debug-logged, not raised.

Because a command can still fail for real (no response arrives), `async_lock`/
`async_unlock` now call `_resync_after_failed_command()` on failure: re-query real
status via a fresh connection before giving up, so HA shows true state instead of
stale cached state. Retries up to `RESYNC_ATTEMPTS = 3` times (1.5s apart) since the
resync is itself a fresh connection that can hit the same transient failure it's
trying to recover from — confirmed necessary on hardware: a single resync attempt
failed once (hit the same GATT error), and state stayed stale until a manual rescan.

All three fixes are covered by new/updated tests in `tests/test_lock_state.py`
(`test_unlock_failure_resyncs_real_state`,
`test_unlock_failure_resync_retries_before_succeeding`) — real-hardware behavior
reproduced as regression tests. 32/32 tests pass.

## Part 3 — root cause investigation: the recurring GATT error

Both locks hit the same failure signature repeatedly:
`bleak.exc.BleakError: Bluetooth GATT Error ... error=14 description=Unlikely error`
— an ATT-layer catch-all, thrown by the write-acknowledgement transaction specifically
(not connection failure, not the lock rejecting the command).

**Tried, partial improvement:**
1. Lowered `esp32_ble_tracker.scan_parameters.window` on lock-adjacent proxies
   (800ms → 250ms on an 1100ms interval). Utility Room Door: **no measurable
   improvement** (~50% rescan success before and after).
2. Switched `scan_parameters.active: false` (passive scanning) on those same
   proxies — Bermuda only needs RSSI from the advertisement itself, not
   scan-response data, so this has no presence-detection downside. Utility Room
   Door: **50% → 75% rescan success**. Real improvement, not fully sufficient.

**Conclusion:** the error is not purely scan-radio contention. Most likely a
timing-sensitive interaction inherent to relaying a write-with-response GATT
transaction through an ESPHome proxy's network round-trip (WiFi → ESP32 → BLE →
lock → back), versus a directly-attached adapter. The code-side fix (Bug 2 above) is
the correct layer to handle this — proxy tuning reduces the *frequency*, the
resync-retry makes the *consequence* safe regardless of frequency.

**Unrelated ESPHome finding, fixed along the way:** `<<: !include base.yaml` (bare
YAML merge key) does a *shallow* merge — a device file's own `substitutions:` block
entirely replaces the base file's `substitutions:` rather than merging into it, so a
default defined in the base (`ble_scan_window: "800ms"`) silently disappeared on
every device that also set its own `node_name`/`friendly_node_name`/`api_key`. Fixed
by switching to ESPHome's `packages:` mechanism, which deep-merges substitutions
key-by-key. Applied to the 3 lock-adjacent proxies.

## Current state per lock

| Lock | Status | Notes |
|---|---|---|
| Utility Room Door | **Validated working** | Lock, unlock, rescan, and the resync-on-failure path all confirmed against real hardware. ~75% first-try success, resync-retry recovers the rest. |
| Shed Door | **Still unreliable** | Failure signature is stronger than Utility Room Door's — `ADMIN_LOGIN` fails with *zero* response chunks received (not "got a response, ack glitched"). Battery replacement didn't change this. Looks like proxy distance/signal, not a lock or code issue. |

## Not yet done

- **Shed Door retest** — user is relocating the BBQ proxy into the shed tomorrow to
  reduce distance to the lock; retest reliability after that.
- **August lock proxy** — user asked whether the same scan-tuning logic applies to
  the proxy controlling their (unrelated, non-Ultraloq) August lock. Answer given:
  yes, same radio-contention principle applies to any proxy that's the primary path
  to a lock. Not yet applied/tested.
- **Real v1→v2 config entry migration** — `test_migration.py` covers this
  synthetically. Not yet tested against a real v1 entry (this test instance was
  enrolled fresh, so it never exercised the migration path). Worth doing before
  merging to `main` if any real installs are still on v1.
- **PR not yet reviewed/merged** — opened as a draft-quality PR; Shed Door follow-up
  and the migration test are called out as known open items, not blockers to
  discussion.

## Test instance reference

Disposable HA OS test LXC, not the live household system:
- HA: `192.168.2.6:8123`, HA OS 2026.7.4
- SSH: `root@192.168.2.6:8593`
- Config samba mount: `/mnt/test_homeassistant_config` (this session only — path is
  local to the session that set up the mount, reconnect it fresh next time)
- Two locks enrolled: `lock.utility_room_door`, `lock.shed_door`
- Debug logging enabled for `custom_components.ultraloq_ble` and
  `custom_components.ultraloq_ble.utecio` in its `configuration.yaml`
