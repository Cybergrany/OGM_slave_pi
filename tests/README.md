# OGM_slave_pi Pi Integration Tests

This folder contains a deploy-loadable GUI-emulation app that validates new
`OGM_slave_pi` app/runtime hooks on a real Pi.

## Contents

- `tests/slave_pi_apps/gui_hook_test/gui_hook_test_app.py`
  - Child app that runs startup checks using IPC + env bindings.
- `tests/slave_pi_apps/gui_hook_test/run_gui_hook_test.py`
  - Pi-side runner that validates startup report and app reload behavior.
- `tests/slave_pi_apps/gui_hook_test/ipc_ndjson.py`
  - Shared IPC helper for the test app and runner.

## What It Verifies

When loaded as a child app, `gui_hook_test_app.py` verifies:

- app env injection (`OGM_PI_SOCKET_PATH`, binding env vars, board/hash metadata)
- `list` + `schema`
- `resolve` name-to-handle mapping
- `get_many`
- `set_many` idempotent write on a safe writable pin
- `gpio_read` + `gpio_write` on app-claimed lines
- `board_reset` subscription event after triggering `BOARD_RESET`

`run_gui_hook_test.py` additionally verifies:

- app started and wrote a passing report
- `app_reload` restarts the child app (`start_count` increments)
- post-reload report still passes

## Install / Deploy

1. Deploy runtime and include test app payloads:

```bash
cd /path/to/OGM_The_Core
export OGM_INCLUDE_SLAVE_PI_TEST_APPS=1
python3 scripts/deploy_slave_pi.py
```

Use action `install` (first deploy) or `sync app` (hotload updates).

2. Configure app block on Pi (`/home/<ssh-user>/Desktop/OGM_slave_pi/config/ogm_pi.yaml`):

```yaml
apps_dir: /home/<ssh-user>/Desktop/OGM_slave_pi/runtime/apps
app:
  enabled: true
  name: gui_hook_test
  command: "python3 gui_hook_test_app.py"
  cwd: ""
  restart_policy: always
  restart_backoff_ms: 1000
  startup_timeout_ms: 10000
  shutdown_timeout_ms: 5000
  pin_bindings:
    - <writable_non_admin_pin_name>
  gpio_bindings:
    - <app_claimable_gpio_pin_name>
  env: {}
```

Binding details (using `pi_pizza_right` as an example):

- `pin_bindings`:
  - pin names resolved once at app startup and injected as `OGM_PI_PIN_BINDINGS`
    (`[{name,handle}, ...]`).
  - use for IPC `resolve`, `get_many`, and `set_many`.
  - can include both read and write pins, but avoid admin/safety pins unless
    you explicitly want to exercise them.
- `gpio_bindings`:
  - subset of pin names that map to real GPIO lines and are injected as
    `OGM_PI_GPIO_BINDINGS` (`[{name,handle,line}, ...]`).
  - only app-claimed lines are allowed for IPC `gpio_read`/`gpio_write`.
  - line claims hard-fail if the runtime already owns that line.

`pi_pizza_right` safe baseline (current sample as defined in `ExternalIODefines.yaml`):

```yaml
app:
  pin_bindings:
    - button_lts
    - led_outer_R
    - led_inner_B
    - RESET
  gpio_bindings: []
```

Why `gpio_bindings` is empty in this baseline:

- `pi_pizza_right` GPIO-numbered pins are runtime-owned by
  `INPUT_DIGITAL`/`OUTPUT_DIGITAL` handlers, so they cannot be app-claimed.
- `com_seg` has no concrete GPIO `pin` in the exported pinmap.

If you want to explicitly test GPIO hooks (`--require-gpio`), add a dedicated
app-owned GPIO pin to the child definition first (example):

```yaml
- { name: app_gpio_probe, type: PLAIN_COIL, pin: 18, args: [0] }
```

Then bind it:

```yaml
app:
  pin_bindings:
    - button_lts
    - app_gpio_probe
    - RESET
  gpio_bindings:
    - app_gpio_probe
```

General notes:

- Keep `cwd: ""` to exercise daemon fallback to `<apps_dir>/<app.name>`.
- The board-reset test triggers `BOARD_RESET`; run during a safe maintenance
  window because outputs may briefly reset.

3. Apply config and start/reload service:

```bash
sudo systemctl restart ogm_pi.socket ogm_pi.service
```

## Run Tests On Pi

```bash
cd /home/<ssh-user>/Desktop/OGM_slave_pi/runtime/apps/gui_hook_test
python3 run_gui_hook_test.py --socket-path /run/ogm_pi.sock
```

If you configured `gpio_bindings` (for example `app_gpio_probe` above), run:

```bash
cd /home/<ssh-user>/Desktop/OGM_slave_pi/runtime/apps/gui_hook_test
python3 run_gui_hook_test.py --socket-path /run/ogm_pi.sock --require-gpio
```

Expected result: runner prints `PASS`.

Artifacts are written to:

- `test_output/latest_startup_report.json`
- `test_output/startup_history.ndjson`
- `test_output/heartbeat.json`

## Troubleshooting (App Restart Loop / rc=1)

If `journalctl -fu ogm_pi.service` shows repeated:

- `Starting app process ...`
- `App exited (rc=1); restarting ...`

then the child app is crashing before it can write `test_output`.

On the Pi, check the deployed payload and permissions:

```bash
APP_DIR=/home/<ssh-user>/Desktop/OGM_slave_pi/runtime/apps/gui_hook_test
ls -la "$APP_DIR"
sudo -u ogm_pi test -f "$APP_DIR/gui_hook_test_app.py"
sudo -u ogm_pi test -f "$APP_DIR/ipc_ndjson.py"
sudo -u ogm_pi mkdir -p "$APP_DIR/test_output"
sudo -u ogm_pi touch "$APP_DIR/test_output/.write_probe"
```

If write checks fail, fix ownership:

```bash
sudo chown -R ogm_pi:ogm "$APP_DIR"
sudo chmod -R u+rwX "$APP_DIR"
```

To see the exact Python error directly as the service user:

```bash
sudo -u ogm_pi bash -lc '
  cd /home/<ssh-user>/Desktop/OGM_slave_pi/runtime/apps/gui_hook_test &&
  OGM_PI_SOCKET_PATH=/run/ogm_pi.sock \
  OGM_PI_PIN_BINDINGS="[]" \
  OGM_PI_GPIO_BINDINGS="[]" \
  python3 gui_hook_test_app.py --once
'
```

## Uninstall / Cleanup

1. Disable test app in config:

```yaml
app:
  enabled: false
```

2. Restart service:

```bash
sudo systemctl restart ogm_pi.socket ogm_pi.service
```

3. Remove deployed test app files (optional):

```bash
sudo rm -rf /home/<ssh-user>/Desktop/OGM_slave_pi/runtime/apps/gui_hook_test
```

4. Stop bundling test apps in future deploys:

```bash
unset OGM_INCLUDE_SLAVE_PI_TEST_APPS
```
