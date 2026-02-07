# OGM_slave_pi

Raspberry Pi Modbus RTU slave + IPC gateway for OpenGameMaster pin layouts.
This repo reads the same `ExternalIODefines.yaml` used by `OGM_The_Core`,
exports a per-board pinmap JSON (register layout + hash), and exposes
registers over a local Unix socket for other programs on the Pi.

## What lives here

- `config/ExternalIODefines.yaml`: manual copy of the master pin list.
- `config/PinTraits.yaml`: master register footprint definitions.
- `config/CustomSlaveDefines/PinTraits.yaml`: custom pin footprints.
- `scripts/export_pinmap.py`: YAML -> pinmap JSON exporter.
- `scripts/install_pi.sh`: installer/update script with UART preflight/fix support.
- `ogm_pi/`: daemon + IPC client modules.
- `ogm_pi/custom_loader.py`: dynamic loader for custom runtime pin handlers.
- `systemd/`: example units for a root-owned socket and user-owned service.

## Recommended deploy flow (from OGM_The_Core)

For production deployments, use:

```bash
cd /path/to/OGM_The_Core
python3 scripts/deploy_slave_pi.py
```

That helper exports pinmaps from master source-of-truth files, bundles custom
Pi pin handlers from `OGM_The_Core/Defines/CustomSlaveDefines/slave_pi`,
uploads the runtime/config payload to the Pi, and runs install or sync actions.

In Desktop deploy layout (`/home/<user>/Desktop/OGM_slave_pi`), daemon runtime
logs and crash dumps are persisted under:
- `runtime_failures.log`
- `crash_dumps/` (timestamped dumps + `latest.log`)

## Installation (Pi)

1) **Install system dependencies** (libmodbus runtime + libgpiod bindings):
```bash
sudo apt-get update
sudo apt-get install -y libmodbus5 python3-libgpiod \
  || sudo apt-get install -y libmodbus python3-gpiod
```

2) **Create a virtualenv and install Python deps**:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) **Copy/refresh config files** (manual workflow):
- Update `config/ExternalIODefines.yaml` from `OGM_The_Core/Defines/ExternalIODefines.yaml`.
- Update `config/PinTraits.yaml` from `OGM_Portable/Defines/PinTraits.yaml`.
- Update `config/CustomSlaveDefines/PinTraits.yaml` from `OGM_The_Core/Defines/CustomSlaveDefines/PinTraits.yaml`.

4) **Export a pinmap for the board address**:
```bash
python3 scripts/export_pinmap.py --address 99 --output out/pinmap_99.json
```
Notes:
- Use `--name <board_name>` instead of `--address` if you prefer names.
- Use `--skip-external` to ignore boards marked `external_management: true`.
- For bridge children, use `--child-name`/`--child-address` and optionally `--bridge-name`:
  `python3 scripts/export_pinmap.py --child-name slave_pi --bridge-name bridge_console --output out/pinmap_slave_pi.json`

5) **Configure the daemon**:

Edit `config/ogm_pi.yaml` (or `/etc/ogm_pi/ogm_pi.yaml` if using systemd) to set the
pinmap path and serial settings.

Example:
```yaml
pinmap: /etc/ogm_pi/pinmap.json
custom_types_dir: /opt/OGM_slave_pi/custom_types
serial: /dev/serial0
baud: 250000
slave_address: 99
gpio_chip: /dev/gpiochip0
modbus_log_every_failure: false
```
For USB adapters instead of GPIO14/15 UART, use `serial: /dev/ttyUSB0` (or your adapter path).

For runtime deploy layouts, you can toggle per-failure Modbus logging in
`<target-dir>/config/debug.yaml` (for example
`/home/<user>/Desktop/OGM_slave_pi/runtime/config/debug.yaml`):
```yaml
DEBUG:
  modbus_log_every_failure: true
```

6) **Run the daemon**:
```bash
python3 -m ogm_pi.daemon --config config/ogm_pi.yaml
```
If you only want IPC (no Modbus backend), add `--no-modbus`.
Optional serial settings: `--parity`, `--data-bits`, `--stop-bits`.
GPIO example (BCM numbering via libgpiod):
```bash
python3 -m ogm_pi.daemon --config config/ogm_pi.yaml
```

## IPC usage (Unix socket)

The daemon exposes a line-delimited JSON protocol over `/run/ogm_pi.sock`.
Each request is a single JSON line, and each response is a JSON line.
If you are not using the systemd socket unit, set `--socket-path` to a
user-writable path (for example `/tmp/ogm_pi.sock`) or run the daemon with
privileges that can create `/run/ogm_pi.sock`.

Supported commands:
- `list` (list pins + spans)
- `get` (read all registers associated with a pin)
- `set` (write registers; IPC allows all types)
- `schema` (return the full pinmap JSON)
- `subscribe` (stream master-originated changes for coils/holding regs)

Examples:
```bash
python3 -m ogm_pi.cli list
python3 -m ogm_pi.cli get DoorSensor
python3 -m ogm_pi.cli set LightRelay --type coils --value 1
python3 -m ogm_pi.cli schema
```

Subscribe example (NDJSON stream):
```bash
printf '{"id":1,"cmd":"subscribe","types":["coils","holding_regs"]}\n' | socat - UNIX-CONNECT:/run/ogm_pi.sock
```
Helper script:
```bash
./scripts/subscribe.py --socket /run/ogm_pi.sock --types coils,holding_regs
```
`subscribe` only emits events for Modbus master writes (IPC writes do not trigger events).

`get` can include `since` to check for master-originated changes:
```bash
printf '{"id":2,"cmd":"get","name":"LightRelay","since":40}\n' | socat - UNIX-CONNECT:/run/ogm_pi.sock
```

## Python example (direct socket)

```python
import json
import socket

SOCK_PATH = "/run/ogm_pi.sock"

def request(payload):
    msg = json.dumps(payload).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCK_PATH)
        sock.sendall(msg)
        data = sock.makefile("rb").readline()
    return json.loads(data.decode("utf-8"))

# Read a pin
resp = request({"id": 1, "cmd": "get", "name": "DoorSensor"})
print(resp)

# Write a pin (coils/holding_regs are writable by Modbus; IPC can write any type)
resp = request({
    "id": 2,
    "cmd": "set",
    "name": "LightRelay",
    "values": {"coils": [1]}
})
print(resp)
```

## Systemd integration (optional)

This repo ships example units that create the socket as root and run the
daemon as a non-root user. Adjust `User`, `Group`, and `ExecStart` to fit
your system.

```bash
sudo cp systemd/ogm_pi.socket /etc/systemd/system/
sudo cp systemd/ogm_pi.service /etc/systemd/system/

# Edit /etc/ogm_pi/ogm_pi.yaml to point at your pinmap and serial device.
sudo systemctl daemon-reload
sudo systemctl enable --now ogm_pi.socket
```

The socket unit controls permissions via `SocketMode` and `SocketGroup`.
Add your client user to that group to allow IPC access.

## Install script (Pi)

```bash
sudo ./scripts/install_pi.sh --board-name slave_pi --slave-address 99
```

This installs OS deps, creates the service user, copies the repo to `/opt/OGM_slave_pi`,
installs the venv, writes `/etc/ogm_pi/ogm_pi.yaml`, exports a pinmap to
`/etc/ogm_pi/pinmap.json`, writes `<target-dir>/config/debug.yaml`, and enables systemd units.

By default, the installer now prompts:
- `Use default install config for GPIO14/15 RS485 [Y/n]`
- `Disable Bluetooth and dedicate serial0 to GPIO14/15 (recommended) [Y/n]`

If accepted (default), it uses `/dev/serial0` and applies UART compatibility
checks/fixes (`--uart-fix`) for better Modbus RTU reliability on Pi UART pins.
Use `--no-default-install-config` and/or `--no-uart-fix` to opt out.

UART preflight/fix behavior (for `/dev/serial*`, `/dev/ttyAMA*`, `/dev/ttyS*`):
- Reports resolved UART mapping (`readlink -f`), serial-getty status, and cmdline serial console state.
- With `--uart-fix` (default), applies compatibility updates (enable UART, disable serial console/getty; optionally disable bt UART service when dedicated serial0 mode is accepted).
- If UART boot settings are changed, installer marks reboot required, enables units, and skips immediate service restart.
- Hard-fails if parity `E/O` is requested while selected UART resolves to `ttyS*` (mini UART).

Common variations:

```bash
# Bridge child pinmap (under bridge_console)
sudo ./scripts/install_pi.sh --child-name slave_pi --bridge-name bridge_console --slave-address 99

# Use a prebuilt pinmap
sudo ./scripts/install_pi.sh --pinmap-src /path/to/pinmap.json --write-pinmap

# Update install in place (preserve config/pinmap)
sudo ./scripts/install_pi.sh --update

# Non-interactive install using default GPIO14/15 profile
sudo ./scripts/install_pi.sh --default-install-config --board-name slave_pi --slave-address 99

# USB RS485 adapter install (skip default GPIO14/15 profile prompt/settings)
sudo ./scripts/install_pi.sh --no-default-install-config --serial /dev/ttyUSB0 --board-name slave_pi --slave-address 99

# Remove units (keep config + install)
sudo ./scripts/install_pi.sh --uninstall

# Remove units and purge install/config dirs
sudo ./scripts/install_pi.sh --uninstall --purge

# Desktop deploy-layout cleanup (service + runtime/config/incoming/staging)
sudo ./scripts/uninstall.sh

# Also remove deploy/runtime failure logs under Desktop/OGM_slave_pi
sudo ./scripts/uninstall.sh --delete-logs
```

`--write-config` (or any config override flag) rewrites `ogm_pi.yaml` using defaults.
Use `--skip-apt`/`--skip-pip` for offline installs and `--skip-systemd` to avoid
touching systemd. If you change `--target-dir`, `--config-dir`, or `--socket-path`,
the installer writes matching systemd units.
Custom handler modules default to `<target-dir>/custom_types`; override with
`--custom-types-dir` if needed.

## Pinmap JSON schema (v1)

Root fields (summary):
- `schema_version`: integer
- `generated_at`: ISO-8601 string
- `source`: file paths used for generation
- `network_baud`: from ExternalIODefines.yaml
- `hash`: 32-bit FNV-1a layout hash (master-compatible)
- `id`, `label`, `kind`, `address`, `zone`, `reset_on_init`, `has_stats`
- `totals`: register totals by type
- `pins`: ordered list, starting with injected `PIN_HASH`

Each pin record:
- `name`, `type`, `pin`, `args`
- `coils`, `discretes`, `input_regs`, `holding_regs` as `[start, count]`

`pin` may be an int or a string token (e.g., `A0`). `args` is always an
array (empty if none) and is passed through without interpretation so
future scripts can add semantics if needed.

## Custom pin handlers

`ogm_pi` can load custom runtime handlers from a directory of Python modules.

- Config key: `custom_types_dir` (CLI override: `--custom-types-dir`)
- Default when unset: `<install-root>/custom_types` (for example `/opt/OGM_slave_pi/custom_types`)
- Each module may export:
  - `HANDLER_TYPES = {"PIN_TYPE_NAME": HandlerClass, ...}`
  - `METRIC_INPUT_REGS = {"pin_name": MetricHandlerClass, ...}` (optional)

Handler classes should follow the built-in `PinHandler` interface
(`init`, `update`, `reset`, optional `force_safe`), and can import helpers
from `ogm_pi.pin_runtime`.

`ogm_pi` fails startup if:
- `custom_types_dir` is configured but missing
- a custom module fails to import
- custom handler/metric names collide with built-ins or each other

## Custom type workflow example (TM1637)

- Add/maintain trait footprint in `OGM_The_Core/Defines/CustomSlaveDefines/PinTraits.yaml`.
- Add runtime module in `OGM_The_Core/Defines/CustomSlaveDefines/slave_pi/` exporting `HANDLER_TYPES`.
- Use pin entries in `ExternalIODefines.yaml` with matching type and args.
  For `segmentDisplay_tm1637`: `args: [clk_gpio, dio_gpio, optional_boot_test_ms]`.
- Deploy using `OGM_The_Core/scripts/deploy_slave_pi.py` so custom handler files are synced to the Pi runtime.

## Notes / gotchas

- `PIN_HASH` uses two input registers: low word first, high word second. Bridge children use `child_hash_<child_name>` for the hash pin name.
- Pin order matters for register layout; do not reorder YAML entries.
- Modbus writes should only target coils/holding regs, but IPC can write all.
- Bridge child pinmaps are supported, but OGM_slave_pi itself remains a single Modbus slave (it does not act as a bridge).
- If a pin is named `pi_cpu_temp_c_x100` or `pi_cpu_load_1m_x100`, the daemon will populate it from system metrics.
- BOARD_STATS uptime uses the daemon service lifetime (resets on service restart).

## Example Raspberry Pi board entry

```yaml
- name: slave_pi
  address: 99
  zone: 0
  external_management: true
  has_stats: true
  reset_on_init: true
  pins:
    # Use Raspberry Pi BCM GPIO numbering.
    - { name: pi_input_1,  type: INPUT_DIGITAL,  pin: 17 }
    - { name: pi_input_2,  type: INPUT_DIGITAL,  pin: 27 }
    - { name: pi_output_1, type: OUTPUT_DIGITAL, pin: 22, args: [0] }
    - { name: pi_output_2, type: OUTPUT_DIGITAL, pin: 23, args: [0] }
    - { name: pi_cpu_temp_c_x100,  type: PLAIN_INPUT_REG, args: [0] }    # centigrade * 100
    - { name: pi_cpu_load_1m_x100, type: PLAIN_INPUT_REG, args: [0] }    # load avg * 100
    - { name: RESET, type: BOARD_RESET, pin: 0 }
```
