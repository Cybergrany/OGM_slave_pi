# TODO: SD-Card, Journal, Health, and Wi-Fi Client Work

Status: implementation backlog. This checklist is scoped to `OGM_slave_pi`.

Cross-repository source of truth:
`OpenGameMaster_pio/docs/rpi-observability-implementation-plan.md` on the
coordinated observability task branch.

## Refactor `sd_card_improvements.sh`

- [ ] Separate the requested operation from platform/zram checks so
      status/verify/OverlayFS maintenance commands do not fail on an unrelated
      zram prerequisite.
- [ ] Make SD baseline, final OverlayFS target, and central collection
      independent configuration axes.
- [ ] Stop removing the managed collection configuration merely because a later
      run omits a collector or disables OverlayFS.
- [ ] Add explicit enable/update/disable/leave collection behavior.
- [ ] Add noninteractive flags/config suitable for `deploy_slave_pi.py`.
- [ ] Add stable `--status-json` and `--verify-json` output with schema version.
- [ ] Report root/boot mount state, OverlayFS expected/active, maintenance marker,
      marker ownership/transaction, boot ID, journal mode/caps, collection
      target, queue state, and required reboot.
- [ ] Give maintenance enter/restart commands a transaction ID and owner so one
      deployer cannot close another operator's maintenance session.
- [ ] Preserve the current two-reboot Raspberry Pi `raspi-config` behavior and
      verify changed boot ID after each reboot.
- [ ] Keep `/boot` or `/boot/firmware` read-only in the final protected state.

## Structured central collection

- [ ] Replace the basic `ForwardToSyslog`/`imuxsock` projection with a reviewed
      rsyslog `imjournal` input and bounded TCP forward action.
- [ ] Whitelist stable device ID, hostname, device/receive time, boot ID,
      systemd unit, syslog identifier, PID, facility, priority, and message.
- [ ] Explicitly reject `_CMDLINE`, process environment, credentials, and
      unrestricted journal metadata.
- [ ] Keep cursor/queue state under `/run`; do not configure an SD-card spool.
- [ ] Bound message size, memory queue count/bytes, retry delay, and shutdown
      behavior.
- [ ] Make collector host, port (default TCP 514), and source filters
      noninteractive/configurable.
- [ ] Provide local syntax/service/queue verification and a central receipt
      challenge the deployer can confirm.
- [ ] Ensure collection failure cannot block `ogm_pi`, applications, shutdown,
      or boot.
- [ ] Add source identity/enrolment material without storing ThingsBoard
      credentials on the Pi.

## Lightweight health producer

- [ ] Add a versioned `ogm-health` command with bounded `--status-json` output.
- [ ] Add systemd service/timer units at a low configurable cadence.
- [ ] Emit through journald so health uses the same bounded forwarding path.
- [ ] Collect uptime/boot ID, OverlayFS/boot/maintenance state, service/socket/app
      health, CPU temperature, throttle/undervoltage state, memory/zram/swap,
      disk/free space, journal/forwarder drops, deployment version/result, and
      collector reachability.
- [ ] Treat missing platform-specific metrics as unavailable, not healthy zero.
- [ ] Avoid persistent writes per sample.
- [ ] Add fixture-root tests for Pi model/OS variants and missing interfaces.

## Harden `wifi-stability.sh`

- [ ] Complete all platform/preflight validation before writing any managed
      NetworkManager, Netplan, or module configuration.
- [ ] Add `--status-json`, `--verify`, noninteractive configuration, and
      `--defer-restart`.
- [ ] Back up each managed file and provide exact rollback/status output.
- [ ] Return whether a reboot or NetworkManager restart is required without
      performing it when invoked by the deployer.
- [ ] Preserve the Raspberry Pi OS Trixie fallback validation path.
- [ ] Verify power-save, roam-off, autoconnect, active profile, address, default
      route, DNS, and collector reachability after reboot.
- [ ] Add fixture tests proving a failed Trixie preflight leaves no partial
      changes.

## Canonical collector transition

- [ ] Document the Compose collector as the preferred deployment.
- [ ] Detect an existing host-native `setup-rpi-log-server.sh` listener before
      Compose binds the configured port.
- [ ] Provide explicit verify/export/disable guidance for the old file collector;
      never silently delete its logs or firewall rules.
- [ ] Correct the existing documentation mismatch where the host-native script
      promises per-device size/free-space enforcement it does not implement.
- [ ] Keep the legacy script usable for intentionally database-free sites or
      mark it clearly deprecated after an accepted migration path exists.

## Tests and documentation

- [ ] Shell syntax/static checks for every changed script.
- [ ] Fixture-root tests for maintenance ownership, writable/protected states,
      collection enable/disable/leave, config idempotence, and rollback.
- [ ] Rsyslog configuration syntax and local structured-message tests.
- [ ] Queue saturation, collector outage, malformed response, and power-loss
      recovery tests.
- [ ] Physical canary validation on writable-root and OverlayFS Pis.
- [ ] Measure ongoing SD writes before/after under normal runtime and outage.
- [ ] Update `tuning_sd_card_improvements.md` and the main README only after the
      tested commands and defaults are final.

## Explicitly out of scope

- No Modbus registers, pinmaps, IPC protocol, application behavior, or
  ThingsBoard credentials are changed by this client work.
- Future Modbus-network health is represented only through generic central
  registry/capability contracts in the PIO plan.
