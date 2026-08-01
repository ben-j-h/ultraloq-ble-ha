# On-device (ble_client) lock control — research and current status

Working notes from the 2026-07-31/08-01 session. Read this before re-deriving anything
below — it covers a full pivot away from `bluetooth_proxy`-based control, real hardware
findings, a wrong diagnosis that cost real time (documented so it isn't repeated), and
exactly where things were left off.

Builds on [`chaseflick4-merge-status.md`](chaseflick4-merge-status.md) (the PR-facing
Python integration work). This doc covers a *separate, exploratory* track: whether
running the whole Ultraloq BLE protocol directly on an ESP32 (no Home Assistant Python
integration, no `bluetooth_proxy` relay) is more reliable than anything proxy-based.

## Why this track exists

After merging the fork and fixing the write-ack/state-desync bugs (see the other doc),
extensive real-hardware testing on Utility Room Door still had a real failure ceiling —
roughly 75% first-try success even after passive-scan tuning on a dedicated proxy board,
with the residual failures tracing to a `bluetooth_proxy`-relayed GATT write-ack race
(`BleakError: Bluetooth GATT Error ... error=14 description=Unlikely error`). Working
theory: relaying every GATT operation over WiFi between the ESP32 and HA's own `bleak`
client adds latency that a directly-attached adapter wouldn't have, and that latency is
what the write-ack race depends on.

**The insight that started this track:** since each proxy is already dedicated to one
lock (not shared infrastructure), there's no reason it has to be a generic
`bluetooth_proxy` relay at all — it can run the *entire* lock protocol itself and expose
a plain `lock:` entity to Home Assistant via ESPHome's native API. No relay, no
`custom_components/ultraloq_ble` Python code in the loop for these locks at all.

**Cost of that approach:** the whole protocol (AES-CBC, the ECC/SECP128r1 key exchange
this lock model needs, CRC8 framing, command set) has to be reimplemented in C++ against
ESPHome's `ble_client`, and everything the Python integration's UI/UX layer gives you
(config flow, diagnostics, HACS shareability) is lost — this becomes bespoke firmware
per lock, not a general-purpose HA integration. See conversation for the full tradeoff
discussion; the call made was that greenfield reliability matters more than production
continuity here, since **nothing about this project is in production** — there was no
existing working deployment being protected by staying conservative.

## Hardware track before the pivot (same session, worth recording)

- Migrated Utility Room Door and Shed Door off the original ESP32/WROOM-32 boards onto
  dedicated ESP32-C6 proxies (`bluetooth_proxy`-only, no `esp32_ble_tracker`) — C6 chosen
  for BLE 5.3 vs. the original boards' BLE 4.2 (corrected mid-session: they are original
  ESP32/WROOM-32, *not* S3 as earlier assumed — `board: esp32dev` in the YAML confirms
  this; ESP32-S3 is BLE 5.0).
- Found and fixed a real ESPHome YAML gotcha: `<<: !include base.yaml` (bare YAML merge
  key) does a *shallow* merge — a device file's own `substitutions:` block entirely
  replaces the base file's rather than merging into it, silently dropping a shared
  default (`ble_scan_window`) on every device that also set `node_name`/`api_key`.
  Fixed by switching to ESPHome's `packages:` mechanism, which deep-merges substitutions.
- Discovered `bluetooth_proxy` requires `esp32_ble_tracker` for actual device discovery
  — it's not self-sufficient. An early dedicated-proxy config omitted the tracker
  entirely; fixed by adding it back with a tuned scan config.
- Empirically found **passive scanning beats active** for this lock's GATT reliability
  (50% → 75% first-try success on Utility Room Door) — active scanning's extra
  SCAN_REQ/SCAN_RSP round-trip contends with the lock connection's write-ack timing on
  the same radio. This finding carried into the `ble_client` POC's scan config too.
- Hit `BleakOutOfConnectionSlotsError` broadly during this phase; root-caused partly to
  old proxies still running `bluetooth_proxy`-enabled firmware even after their HA config
  entries were removed (HA's bluetooth manager treats all live proxies as a shared pool,
  not scoped to a specific config entry) — fixed by reflashing all non-lock-adjacent
  boards to tracker-only firmware.
- Found the specific, most-likely-terminal issue with the C6 approach *for
  `bluetooth_proxy` specifically*: an HCI-level failure during connection establishment —
  `ESP_GATTC_OPEN_EVT in DISCONNECTING state (status=133)` followed by
  `BT_HCI: opcode=0x2043 ... status=0c: Cmd Disallowed` — opcode `0x2043` is *LE Extended
  Create Connection*, a BLE 5.0-only command the C6 auto-selects because it's BLE 5.0+
  capable; the controller rejects it. Matches community reports that ESP32-C6's ESPHome
  BLE proxy support (added ~mid-2025) is measurably less mature than S3's. This is very
  likely a platform/firmware-maturity issue, not something fixable in our config or code.

## The ble_client component

**Location:** `/opt/docker/esphome/config/components/ultraloq_lock/` — **not** in the
`ultraloq-ble-ha` git repo. This is a separate git repo (the ESPHome dashboard's own
config directory, `/opt/docker/esphome/config`, which auto-commits on every file save via
its own mechanism — confirmed via `git log` showing commits neither of us triggered
manually). `components/` itself was still untracked as of this write-up; nothing has been
manually committed there.

Structure (ESPHome external-component convention — the platform's C++ files must live
inside the `lock/` subdirectory alongside its own `__init__.py`, not the parent package
directory, or ESPHome's build-time source-file gathering silently skips them — this cost
one full debugging cycle to discover, traced through `esphome/config.py`'s
`iter_components()` and `esphome/loader.py`'s `ComponentManifest.resources`):

```
components/ultraloq_lock/
  __init__.py              # shared UltraloqLock class declaration (ultraloq_lock_ns)
  lock/
    __init__.py             # CONFIG_SCHEMA / to_code for `lock: - platform: ultraloq_lock`
    ultraloq_lock.h
    ultraloq_lock.cpp
```

**Scope:** Utility Room Door (Latch-5-F) only. ADMIN_LOGIN, UNLOCK, BOLT_LOCK,
LOCK_STATUS. The ECC key exchange path only (confirmed via today's logs that this lock
uses ECC, not the simpler STATIC/MD5 paths `device.py` also supports). No battery/
autolock/mode reporting, no other lock models. Deliberately minimal proof of concept.

**Protocol correctness — validated offline before ever touching hardware:**
SECP128r1 isn't one of the curves esp-idf's mbedtls exposes as a named preset (checked
against the actual `esp-idf/components/mbedtls/Kconfig` source — smallest available is
SECP256R1). Rather than hand-roll elliptic-curve point arithmetic (a notorious source of
silent, hard-to-debug crypto bugs), the group is populated manually with SECP128r1's own
standard domain parameters and used with mbedtls's *generic* `mbedtls_ecp_mul()`. This
was verified correct **before writing any ESPHome code**: a standalone C++ program
(`/tmp/.../mbedtls-validation/validate_ecdh.cpp`, built against a locally-cloned
`mbedtls` v3.6.2) reproduced bit-exact public keys and shared secret against a fixed,
deterministic Python `ecdsa` reference (the same library `device.py` uses). Packet
framing, the CRC8 table, and AES-CBC-per-16-byte-chunk-with-zero-IV were ported directly
from `custom_components/ultraloq_ble/utecio/ble/device.py` and checked against its own
golden vectors in `tests/test_protocol.py`.

Two real device-specific assumptions, **neither confirmed against hardware yet**:
- The DATA and ECC characteristics both live under service `00007200-...` — inferred
  from `utecio/enums.py`'s `DeviceServiceUUID` enum grouping LOCK and DATA together,
  since bleak (used by the Python side) finds characteristics by UUID directly and never
  states a parent service. If wrong, service discovery would fail to find them.
- Write type `ESP_GATT_WRITE_TYPE_RSP` — matches bleak's default behavior on real
  hardware all session, so should be safe, but is new code exercising it for the first
  time.

**Builds clean:** 81.6-81.8% flash, ~40.5% RAM on the ESP32-C6. Successfully OTA-flashed
multiple times to the `utility-lock-proxy` board (same physical board used for the
`bluetooth_proxy` dedicated-proxy testing earlier the same session — repurposed, not a
new device).

## What's still unconfirmed, and the debugging trail

**A wrong diagnosis, corrected mid-session — read this first if picking this back up.**
Early testing showed a repeating "Successfully connected" → "EOF received
(SocketClosedAPIError)" pattern in the WiFi log stream and was initially read as a
device crash/reboot loop, leading to two rounds of speculative C++ fixes (moving mbedtls
calls out of the BLE callback context into `loop()`; adding checkpoint logging and
`App.feed_wdt()` calls). **Neither fix changed the symptom**, and the actual cause was
identified from the device's own log: `safe_mode: Boot seems successful; resetting boot
loop counter` fired cleanly at the 60s mark — the device never crashed at all. The real
cause: repeatedly running `timeout N docker exec esphome esphome logs ...` opens a new
API client connection each time; `timeout` SIGKILLs the process without a clean ESPHome
API disconnect, so the device-side connection slot doesn't get released. The device's API
server has `Max connections: 5`; repeated short-lived log-watching invocations exhausted
it, and everything (including the next watch attempt) got `Max connections (5),
rejecting`. **Lesson for next session: never spawn a second `esphome logs` process while
one is already running (Monitor or otherwise) against the same device.** One persistent
connection at a time; let it end cleanly (or via `TaskStop`) before starting another.

**The real, still-open question: has this ESP32 ever actually discovered the lock's BLE
advertisement at all?** Across every test — idle, after asking for a physical
thumbprint wake, after a physical thumbprint *unlock* — `esp32_ble_tracker`'s own
`discovered: 0` counter never moved, and none of the checkpoint logs added throughout
this session (`gattc_event_handler: event=...`, `ECC: ...`, `on_connect fired`) ever
appeared, even once. That's consistent across enough independent attempts that it's very
unlikely to be sparse-advertisement bad luck against the passive scan's ~22% duty cycle.

**Found what's very likely the actual reason:** this lock has a configured wake-up
receiver (WURX) companion device at `A4:C1:38:B1:73:92` (confirmed via
`enrolled_devices` in `.storage/core.config_entries` on the test HA instance) — and that
exact address matches the target of the earlier `Cmd Disallowed`/`DISCONNECTING state`
crash log from the `bluetooth_proxy` testing phase. `device.py`'s
`async_wakeup_device()` shows the wake mechanism is trivial: connect to the WURX device
(no data exchange, no auth), then disconnect — the mere act of connecting is what
signals the main lock to wake its BLE radio. A physical thumbprint interaction wakes the
mechanical/fingerprint functions but evidently not the BLE radio's advertising state,
which is exactly the problem this companion device exists to solve.

**Added WURX support, pure YAML, no new C++:**
```yaml
ble_client:
  - mac_address: "EC:DA:3B:22:47:79"
    id: utility_room_door_ble
    on_connect: [...]      # diagnostic logging only
    on_disconnect: [...]
  - mac_address: "A4:C1:38:B1:73:92"
    id: utility_room_door_wurx_ble
    auto_connect: false

button:
  - platform: template
    name: "Utility Room Door Wake Receiver"
    on_press:
      - ble_client.connect: utility_room_door_wurx_ble
      - delay: 1s
      - ble_client.disconnect: utility_room_door_wurx_ble
```
This compiled clean and flashed successfully. The button entity appeared correctly in HA
via ESPHome's native integration (`button.utility_room_lock_proxy_utility_room_door_wake_receiver`)
and was pressed successfully (HTTP 200, state updated).

**Where it was left:** immediately after pressing the wake button, the log stream
dropped again (`EOF received`) — but this time from what should have been a single clean
connection (the prior watcher had already timed out and ended before this one started),
so it isn't the same connection-exhaustion artifact as before. Genuinely unclear whether
this is: the WURX connect attempt itself hitting the same C6 HCI-level issue found
earlier tonight; some other real device-side event; or still an artifact of WiFi/API log
streaming being an unreliable way to observe fast, low-level BLE state changes. No
conclusive signal either way was obtained remotely.

## Next step

**Get a real serial (USB) log from right next to the lock.** This has been the
recommended next step for a while and was deferred twice for practical reasons (board
physically near the lock, laptop/dev setup on the desktop). Given how much time
ambiguous remote signals have cost across this session (two wrong-diagnosis fix cycles,
several rounds of inconclusive log-stream results), a real crash/connection log —
whether it shows the WURX connect succeeding, the same `Cmd Disallowed` HCI rejection, or
something else — would very likely resolve in minutes what remote diagnosis hasn't
resolved across a full session.

Once serial access is available: `docker exec -it esphome esphome logs
/config/utility-lock-bt-proxy.yaml --device /dev/ttyUSBx` (matches the flashing pattern
already established this session), press the WURX wake button from HA, and watch for
either a `gattc_event_handler` checkpoint firing or a hard fault/panic trace.

If the WURX wake does get the lock discovered and connectable: the two unconfirmed
assumptions above (service UUID grouping, write type) become the next things to verify,
in that order — service UUID first, since `ESP_GATTC_SEARCH_CMPL_EVT` failing to find the
characteristics would produce a clear, specific log line (`Required characteristic(s)
not found`) that immediately confirms or rules that out.

If it turns out the C6's BLE 5.0 extended-connection HCI rejection is *also* blocking
`ble_client` (not just `bluetooth_proxy`), that would mean the platform-level ESP32-C6
ESPHome maturity issue is the actual blocker regardless of architecture (relay vs.
on-device), and reverting this specific board to original ESP32/WROOM-32 hardware (BLE
4.2, but with years of mature ESPHome support behind it) becomes the more likely path
forward for Utility Room Door specifically — mirroring the recommendation already made
for the `bluetooth_proxy` track.
