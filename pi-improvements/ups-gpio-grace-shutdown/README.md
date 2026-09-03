# Raspberry Pi UPS graceful-shutdown package

Version: **2026.09.03-2**

This package replaces the legacy `gpoi_shutdown.service` / `gpoi_shutdown.py`
installation with a native systemd UPS monitor that is deliberately kept outside
Docker. It monitors the UPS/mains indication on BCM GPIO12, waits for a continuous
configured outage interval, requests a normal systemd poweroff, and leaves BCM
GPIO26 under the kernel `gpio-poweroff` driver so the relay is released only during
the host power-off sequence.

## Known hardware contract

The package defaults reproduce the existing known-good installation:

- UPS input: BCM GPIO12
- GPIO12 pull: internal pull-up
- raw GPIO12 LOW: mains healthy
- raw GPIO12 HIGH: mains lost
- graceful shutdown delay: 300 seconds
- relay/power-control output: BCM GPIO26
- required boot overlay:

```ini
dtoverlay=gpio-poweroff,gpiopin=26,active_low=1,active_delay_ms=1000,inactive_delay_ms=1000
```

GPIO26 must remain kernel-owned (`power_ctrl`). The Python monitor never requests or
writes GPIO26.

## Installed layout

```text
/etc/default/ups-shutdown                         configuration
/etc/systemd/system/ups-shutdown.service          GPIO12 monitor
/etc/systemd/system/ups-shutdown-clean-marker.service
/usr/local/sbin/ups-shutdown.py                   hardened monitor
/usr/local/sbin/ups-shutdown-status               status/post-mortem command
/usr/local/sbin/ups-shutdown-host-setup           GPIO26 boot-config helper
/usr/local/sbin/ups-shutdown-smoke-test           pre-production tests
/var/lib/ups-shutdown/                            persistent flight recorder
/etc/logrotate.d/ups-shutdown                       ~1-year service-history retention
```

When run with `sudo` from a desktop user, the installer also creates an obvious
`~/Desktop/UPS Shutdown/` reference folder containing links to the configuration,
state/history, and service definition.

## Why the host shutdown call is safe/narrow

The monitor runs as a native root systemd service, so no container privilege bridge
is necessary. After the outage timer has actually reached its configured threshold,
it persists and fsyncs `UPS_SHUTDOWN_REQUESTED`, then executes:

```text
/usr/bin/systemctl --no-block --ignore-inhibitors poweroff
```

`--no-block` avoids waiting for the same shutdown transaction that is about to stop
the monitor. `--ignore-inhibitors` prevents a desktop/application inhibitor from
vetoing a UPS emergency poweroff. The package intentionally does **not** use
`--force`; the ordinary systemd shutdown/service-stop/filesystem-unmount sequence is
preserved.

If systemctl returns non-zero, the error/return code is persisted and the monitor
retries. If systemctl returns success but the monitor is still alive after the
watchdog interval, it records that unusual condition and retries.

The systemd unit also gives this small safety service `OOMScoreAdjust=-900`, while
constraining it to `MemoryMax=128M` and `TasksMax=32`. This makes it an unattractive
OOM-killer victim under host memory pressure while still bounding an abnormal monitor
process.

## Flight recorder / post-mortem behaviour

Critical state changes are atomically persisted and fsynced. Before replacing the live snapshot on a new boot, the exact terminal state of the prior boot is also copied to `previous-boot.json`. The monitor records:

- service start/restart, script SHA-256, config SHA-256, and kernel release
- raw GPIO12 changes
- mains-loss detection and monotonic timer start
- stable mains restoration and cancelled timer
- threshold reached
- UPS shutdown request **before** systemctl is called
- systemctl return code/stdout/stderr
- unexpected exceptions
- SIGTERM/service stop

A separate `ups-shutdown-clean-marker.service` is pulled in by `shutdown.target` and
writes an independent orderly-shutdown witness. It is not started by the monitor.

On the next boot, the monitor classifies the previous boot as one of:

- UPS-triggered graceful shutdown
- graceful shutdown/reboot through another path
- abrupt system loss during a recorded mains outage before this monitor requested shutdown
- UPS shutdown requested but no independent clean-shutdown witness
- abrupt system loss with no UPS shutdown request
- same-boot monitor restart, including recovery of an active outage countdown

The active outage timer is stored using boot ID + monotonic time. If the service
crashes/restarts during an outage on the same host boot, it continues the original
countdown instead of granting a new 300 seconds.

## Dedicated persistent history (journald left alone)

The package does **not** change the host-wide journald retention policy. Normal
stdout/stderr still goes to `journalctl -u ups-shutdown.service` for convenience,
but the authoritative post-mortem evidence is stored under `/var/lib/ups-shutdown`.

`history.log` and `history.jsonl` are handled by the standard
`/etc/logrotate.d/ups-shutdown` policy: monthly rotation, 13 rotated generations,
`maxage 365`, compression, and an additional 5 MiB `maxsize` trigger to bound an
unusually noisy failure mode. The monitor opens, appends, fsyncs and closes each
history file per event, so rotation needs no `copytruncate`, service restart, or
custom cleanup code. `current.json`, `previous-boot.json`, `clean-shutdown.json`,
and `last-report.txt` are small current-state/witness files and are not rotated.

## GPIO26 host setup helper

Check only:

```bash
sudo ups-shutdown-host-setup --check
```

Install the expected line if no gpio-poweroff line exists:

```bash
sudo ups-shutdown-host-setup --apply
```

If a *different* gpio-poweroff line already exists, the tool refuses to alter it.
After manual review, intentional replacement requires:

```bash
sudo ups-shutdown-host-setup --replace-existing
```

Any boot-config edit is backed up next to `config.txt`. A changed device-tree overlay
requires a reboot before the monitor will arm.

The monitor validates the **live** device tree and expects:

- compatible = `gpio-poweroff`
- BCM GPIO26
- active-low flag
- `active-delay-ms = 1000`
- `inactive-delay-ms = 1000`
- `gpioinfo` consumer `power_ctrl`, output, active-low, used
- GPIO26 HIGH in the running state when `pinctrl`/`raspi-gpio` is available

If this prerequisite is wrong or absent, the service refuses to arm and tells the
operator to run `ups-shutdown-host-setup --apply`. Exit status 78 prevents a restart
storm for a configuration problem.

### Important active-low boot behaviour

Raspberry Pi's official `gpio-poweroff` documentation notes that `active_low` has
boot/reboot electrical-state implications and may require board-specific handling to
avoid an unwanted low during boot. This package intentionally reproduces the
existing, already-proven configuration rather than attempting to redesign that
hardware contract. A cold-boot/reboot observation of GPIO26/relay behaviour remains
part of the pre-production acceptance test for any new hardware image/unit.

Reference:
https://github.com/raspberrypi/firmware/blob/master/boot/overlays/README

## Installation / migration

Do **not** run the old and new GPIO12 monitors simultaneously.

### 1. Remove the legacy monitor

From this package directory:

```bash
sudo ./remove-legacy-gpoi-service.sh
```

The helper:

1. if the old monitor is running, first verifies raw GPIO12 is LOW (known healthy
   mains state) and **refuses migration during an asserted power failure**;
2. backs up the legacy service and Python script under
   `/var/backups/ups-shutdown-legacy/<timestamp>/`;
3. stops and disables `gpoi_shutdown.service`;
4. verifies GPIO12 is no longer claimed;
5. removes `/etc/systemd/system/gpoi_shutdown.service` and
   `/usr/local/sbin/gpoi_shutdown.py`;
6. **does not touch GPIO26 or the gpio-poweroff overlay**.

If GPIO12 remains claimed, the helper stops and requires the remaining owner to be
identified before continuing.

### 2. Install

```bash
sudo ./install-ups-shutdown.sh
```

The installer is idempotent for the new package and preserves an existing
`/etc/default/ups-shutdown` on upgrades. It refuses to install while legacy
`gpoi_shutdown` files still exist.

If the host overlay had to be added/changed, reboot when instructed. Otherwise the
installer starts the new monitor immediately and verifies GPIO12 became used again.

### 3. Inspect

```bash
sudo ups-shutdown-status
```

Useful direct commands:

```bash
systemctl status ups-shutdown.service
sudo journalctl -u ups-shutdown.service
sudo journalctl -u ups-shutdown.service -f
sudo ups-shutdown-host-setup --check
```

## Configuration

Edit:

```bash
sudo nano /etc/default/ups-shutdown
```

Then reload the monitor:

```bash
sudo systemctl restart ups-shutdown.service
```

Default configuration:

```text
GPIO_INPUT=12
GPIO_PULL=UP
POWER_FAIL_LEVEL=HIGH
SHUTDOWN_AFTER=300
RESTORE_DEBOUNCE=3
POLL_INTERVAL=1
SHUTDOWN_RETRY_SECONDS=5
SHUTDOWN_ACCEPTED_WATCHDOG=30
GPIO_POWEROFF_PIN=26
GPIO_POWEROFF_ACTIVE_DELAY_MS=1000
GPIO_POWEROFF_INACTIVE_DELAY_MS=1000
```

The monitor reads the low-level gpiozero `Pin.state`, which is the raw electrical
HIGH/LOW state and is not inverted by gpiozero's pull-up active-state abstraction.
The forensic state directory is intentionally fixed at `/var/lib/ups-shutdown` so
the systemd write sandbox, clean-shutdown witness, status tool and rotation policy
all refer to one canonical location.

As an additional guard against an accidentally dangerous edit, normal production
configuration refuses `SHUTDOWN_AFTER` values below 60 seconds. The smoke-test tool
can temporarily authorize a shorter threshold using a current-boot token under
`/run`; that token disappears automatically on reboot.

GPIO Zero reference:
https://gpiozero.readthedocs.io/en/stable/api_pins.html

## Pre-production smoke test

### Stage A — non-destructive preflight

```bash
sudo ups-shutdown-smoke-test --preflight
```

This checks:

- internal monitor/state-classification tests
- exact boot overlay and live device-tree configuration
- main service enabled + active
- clean-shutdown witness enabled
- legacy service absent
- GPIO12 claimed by the new monitor
- GPIO26 claimed by `power_ctrl`
- current raw GPIO12 state when `pinctrl` is available
- dedicated logrotate policy for the service history
- current flight-recorder state

Do not continue to a power-cut test unless this passes.

### Stage B — short live mains-loss test

For example, arm a **15-second** one-boot test:

```bash
sudo ups-shutdown-smoke-test --arm-live-test 15
```

The helper only arms while GPIO12 currently indicates healthy mains. It creates a
current-boot-only authorization token under `/run`, temporarily starts the running
monitor with a 15-second threshold, then immediately restores the **on-disk**
configuration to the production value and removes the token without restarting the
process. Therefore, after the test shutdown/reboot, the production 300-second value
is loaded automatically. If power is lost in the very small setup window before the
production config is restored, `/run` is cleared on reboot and the service refuses
to arm a sub-60-second configuration rather than risking an unexpectedly short
shutdown timer.

Then perform the controlled mains cut. Expected behaviour:

1. router/network may disappear immediately;
2. Pi/relay stays powered with GPIO26 HIGH;
3. after ~15 seconds the Pi begins an orderly shutdown;
4. gpio-poweroff ultimately drives GPIO26 to the relay-release state;
5. after mains returns and the Pi boots, the production timeout is 300 again.

Verify after reboot:

```bash
sudo ups-shutdown-smoke-test --verify-last-live-test
sudo ups-shutdown-status
```

Expected previous-boot classification:

```text
Previous boot: UPS-triggered graceful shutdown completed through systemd.
```

If the physical power-cut test is aborted after arming, immediately reload the
production configuration with:

```bash
sudo ups-shutdown-smoke-test --cancel-live-test
```

### Stage C — production-value acceptance test

After the short test succeeds, run one final controlled power cut with the normal
`SHUTDOWN_AFTER=300` value. Independently observe the relay/GPIO26 or Pi 5 V rail if
possible. Confirm the Pi remains powered for the five-minute hold-up and is only
removed after the orderly shutdown sequence.

Also verify one ordinary manual reboot/poweroff. On the following boot the report
should classify it as an orderly **non-UPS** shutdown/reboot.

## Uninstall

```bash
sudo ./uninstall-ups-shutdown.sh
```

By default the uninstaller deliberately preserves:

- `/var/lib/ups-shutdown` forensic evidence;
- **the GPIO26 gpio-poweroff boot overlay**.

Use `--remove-state` only when the retained post-mortem evidence is no longer wanted.
The service-specific logrotate policy is removed automatically. The GPIO26 overlay is
never removed automatically because changing it changes the external relay/power
contract.
