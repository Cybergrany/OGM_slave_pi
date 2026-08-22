# Raspberry Pi SD-card hardening, OverlayFS maintenance, and logging guide

This guide accompanies the current hardening and logging scripts:

- `sd_card_improvements.sh` — client-side SD longevity, zram, tmpfs, OverlayFS, journald, and optional remote logging.
- `setup-rpi-log-server.sh` — lightweight central TCP syslog collector.
- `wifi-stability.sh` — separate Wi-Fi hardening/recovery protection; keep using this independently where applicable.

The target use case is a fixed-purpose Raspberry Pi appliance that may be power-cycled without a clean shutdown. The preferred deployment is a read-only Raspberry Pi OS root filesystem, tightly bounded RAM-backed temporary/log storage, and a central log server for cross-boot forensic history.

---

## 1. Recommended deployment model

For a standard Raspberry Pi OS appliance:

```text
Raspberry Pi client
├─ root filesystem        read-only OverlayFS
├─ boot filesystem        read-only
├─ zram swap              RAM only; no SD-backed swap file
├─ /tmp                    bounded tmpfs
├─ /var/tmp                bounded tmpfs
├─ journald                bounded volatile journal when root is overlaid
└─ rsyslog forwarding      bounded RAM queue → central log server

Central Raspberry Pi
└─ /srv/rpi-logs/<hostname>/<YYYY>/<MM>/<DD>.log
   └─ also exposed as ~/rpi-logs for the selected user
```

This separates two goals:

1. **Protect the client SD card and persistent OS state from arbitrary power removal.**
2. **Keep useful multi-boot logs somewhere persistent so intermittent failures remain diagnosable.**

A stock OverlayFS client without a remote collector only retains logs for the current boot. For headless units, a central collector is therefore strongly recommended.

---

## 2. Platform and safety behaviour

### Supported client platform

The hardening script is intentionally limited to **Raspberry Pi OS**. Unsupported/generic Linux installations fail before the script creates its run-log/backup directory or changes configuration, rather than receiving guessed Ubuntu/Debian-specific settings.

The OverlayFS path requires Raspberry Pi OS's `raspi-config` support. A generic `systemd-zram-generator` installation without Raspberry Pi's `rpi-swap` is also treated as unsupported and fails loudly; support can be added later if such a fleet member actually needs it.

### Existing OverlayFS and maintenance mode

Do not run the normal interactive/apply mode while root OverlayFS is active. Package installs and configuration changes can appear to work, but they land in the RAM-backed upper layer and disappear at reboot.

The script provides explicit maintenance controls:

```bash
sudo bash sd_card_improvements.sh --disable-overlayfs-next-boot
```

This schedules OverlayFS to be disabled starting with the next boot. It is **not** a one-boot exception: after reboot the Pi remains on the real writable root across as many further reboots as required.

A small helper installed by the normal setup keeps the boot partition writable on each maintenance boot as long as the maintenance marker exists. This allows kernel, firmware and initramfs/package work as well as ordinary root-filesystem changes.

When all maintenance is complete:

```bash
sudo bash sd_card_improvements.sh --restart-overlayfs
```

This removes the maintenance marker, rechecks unusual persistent mounts, refreshes the initramfs/overlay module configuration, and schedules root OverlayFS plus boot write-protection for the next boot. Reboot and validate with:

```bash
sudo bash sd_card_improvements.sh --verify
```

While protected, `--verify` reports **PROTECTED MODE**. During a writable maintenance period it reports **MAINTENANCE MODE ACTIVE** and reminds you how to restore protection.

If an older installation was hardened before the maintenance helper existed, `--disable-overlayfs-next-boot` deliberately refuses to pretend it can install the helper persistently while root is already overlaid. In that one case, disable OverlayFS manually, reboot writable, rerun the current script once, and use the maintenance flags thereafter.

### Extra persistent mounts / unusual layouts

The script checks for additional mounted persistent filesystems beyond the normal root and boot layout.

If extra storage such as a mounted `/data`, `/home`, `/var`, secondary ext4 filesystem, network storage, or another persistent mount is detected, it should warn prominently and default OverlayFS to **off** rather than assuming the layout is safe. Only override this deliberately after checking how the additional mounts should behave.

A genuinely separate writable `/var/log` is treated specially: it allows persistent local journald storage even when root OverlayFS is enabled.

---

## 3. Recommended client values

The script selects defaults from detected RAM. For most appliance deployments, start with the defaults and tune only when monitoring shows a reason.

| RAM | ZRAM | `/tmp` tmpfs | `/var/tmp` tmpfs | Persistent journal cap | Volatile journal cap | Remote queue |
|---|---:|---:|---:|---:|---:|---:|
| ≤768 MB, including Zero 2 W | 50% | 64 MB | 32 MB | 50 MB | 16 MB | 1,000 messages |
| ~1 GB | 50% | 128 MB | 64 MB | 100 MB | 24 MB | 1,500 messages |
| 2–4 GB | 50% | 256 MB | 128 MB | 200 MB | 64 MB | 3,000 messages |
| >4 GB | 25% | 512 MB | 256 MB | 300 MB | 128 MB | 5,000 messages |

### Recommended Zero 2 W starting point

For a 512 MB Zero 2 W, use the script defaults unless the workload is unusual:

- **ZRAM:** 50% of RAM.
- **`/tmp`:** 64 MB tmpfs.
- **`/var/tmp`:** 32 MB tmpfs.
- **Persistent journald cap:** 50 MB when persistent local logging is available.
- **OverlayFS volatile journald cap:** 16 MB RAM.
- **Remote syslog queue:** 1,000 messages.

The volatile journal cap is intentionally much smaller than an on-disk journal cap because it consumes real RAM.

---

## 4. What each client option does

### ZRAM

Zram provides compressed swap in RAM instead of writing swap pages to the SD card.

**Benefits**

- Reduces SD writes.
- Provides a soft landing for short memory spikes.
- Reduces the chance of an immediate OOM kill compared with no swap.

**Trade-offs**

- Compression/decompression consumes CPU.
- Heavy sustained swapping still indicates insufficient RAM or an oversized workload.

On Raspberry Pi OS systems using `rpi-swap`, the hardening configuration forces **pure zram** rather than file-backed swap/writeback.

Useful checks:

```bash
free -h
swapon --show
```

If the machine spends substantial time swapping and CPU rises noticeably, investigate the workload rather than simply increasing zram indefinitely.

### `/tmp` and `/var/tmp` tmpfs

These remove common temporary writes from the SD card.

**Benefits**

- Less SD write churn.
- Temporary data automatically disappears at reboot.

**Trade-offs**

- Files consume RAM/swap.
- A process can receive `No space left on device` if the configured tmpfs is too small.

Useful check:

```bash
df -h /tmp /var/tmp
```

For build machines, large archive extraction, video processing, or other temporary-file-heavy workloads, increase the limits or set a value to `0` so that mount is left unchanged.

### Journald caps

There are now two distinct journal limits:

- **Persistent cap** — used when `/var/log` really is persistent, such as a writable root without OverlayFS or a separate writable `/var/log` filesystem.
- **Runtime cap** — used for `Storage=volatile` when `/var/log` would otherwise live inside the RAM-backed OverlayFS upper layer.

Do not size the volatile cap like an SD-card journal. On a Zero 2 W, 16 MB is deliberately conservative.

---

## 5. OverlayFS and log retention

### Without OverlayFS

The script can keep journald persistent and capped on the SD card. This preserves cross-boot history but still produces ongoing SD writes.

### OverlayFS with a separate writable `/var/log`

Persistent journald can remain enabled because `/var/log` is outside the RAM overlay.

### OverlayFS on the normal two-partition Raspberry Pi layout

`/var/log` is part of root and therefore becomes temporary. The script uses:

```text
Storage=volatile
RuntimeMaxUse=<bounded RAM cap>
```

This protects RAM from unbounded journal growth, but **local journal history disappears at reboot or power loss**.

For headless appliances, configure the central log server described below.

---

# Central log server

## 6. When a log server is recommended

Set up the collector before enabling OverlayFS on clients if you want to retain the sort of cross-boot history required to diagnose intermittent failures.

A long-running central Raspberry Pi is suitable. The collector is intentionally lightweight:

- plain `rsyslog` TCP ingress;
- no database;
- no indexer;
- no Grafana/Loki/Elasticsearch dependency;
- maximum 64 TCP sessions;
- bounded 5,000-message server action queue;
- small asynchronous file-write buffer;
- one file per client per day;
- lightweight hourly maintenance.

---

## 7. Install the central collector

Copy `setup-rpi-log-server.sh` to the central Raspberry Pi and run:

```bash
sudo bash setup-rpi-log-server.sh
```

The script is interactive and validates the configuration before finishing.

### Recommended/default answers

For a normal LAN collector, the defaults are appropriate:

| Prompt | Recommended starting value |
|---|---|
| User with convenient read access | Your normal SSH user |
| Backing log directory | `/srv/rpi-logs` |
| User-facing log path | `~/rpi-logs` |
| TCP syslog port | `514` |
| Maximum log age | `180` days |
| Maximum logs per device | `250` MiB |
| Low-storage warning | `<15%` free |
| Low-storage warning | `<2048` MiB free |
| Allowed sender CIDR/IP | Detected local LAN subnet |

If UFW is active, the script offers to add the required TCP rule.

At completion it prints an endpoint similar to:

```text
Collector endpoint:  tcp://192.168.1.20:514
Client host/IP:      192.168.1.20
Client TCP port:     514
Log directory:       /home/dave/rpi-logs
```

Give the collector a DHCP reservation or otherwise stable LAN address.

### Validate later

```bash
sudo bash setup-rpi-log-server.sh --verify
```

Validation checks the rsyslog configuration, service, restart policy, TCP listener, writable log directory, retention/size-cap maintenance, free-space monitor, and current rsyslog resource footprint.

---

## 8. Server log layout

Remote logs are stored as:

```text
/srv/rpi-logs/<hostname>/<YYYY>/<MM>/<DD>.log
```

For example:

```text
/srv/rpi-logs/
├── right-pizza/
│   └── 2026/08/18.log
├── left-pizza/
│   └── 2026/08/18.log
└── kitchen-pi/
    └── 2026/08/18.log
```

The selected user also gets a convenient symlink such as:

```bash
cd ~/rpi-logs
```

Each line retains the timestamp reported by the client and also records collector receive time. The directory date is based on collector receive time so a client with a bad clock cannot create a misleading directory tree.

Useful searches:

```bash
grep -R "NetworkManager" ~/rpi-logs/right-pizza/

grep -R -Ei 'wlan0|netplan|brcmfmac' ~/rpi-logs/right-pizza/2026/08/
```

---

## 9. Server retention and storage bounds

The collector has three independent safeguards.

### Maximum age

Default:

```text
180 days
```

Older completed daily log files are deleted by the maintenance job.

### Maximum storage per device

Default:

```text
250 MiB per hostname
```

If one client exceeds its limit, the server removes that client's **oldest completed daily logs first** until usage falls below the cap.

The current day's active log is never deleted or truncated by size-cap maintenance. If today's log alone leaves the device over its cap, it is retained and a warning is emitted.

Set the per-device cap to `0` during setup if unlimited per-device storage is desired.

### Global filesystem free-space warning

Default warning thresholds:

```text
less than 15% free
OR
less than 2048 MiB free
```

This is an alarm rather than an emergency global deletion policy.

Useful checks:

```bash
journalctl -t rpi-fleet-log-maint
journalctl -t rpi-fleet-log-space

du -sh ~/rpi-logs/*
```

The maintenance and free-space checks are short systemd oneshots rather than continuously running monitoring daemons.

---

## 10. Configure each client to use the collector

Run the client hardening script while its root filesystem is writable:

```bash
sudo bash sd_card_improvements.sh
```

If OverlayFS is selected and `/var/log` is not on a separate writable filesystem, the script asks for:

```text
Remote syslog host/IP for cross-boot forensic logs
Remote syslog TCP port
Remote syslog in-RAM queue size
```

Using an endpoint printed by the server such as:

```text
tcp://192.168.1.20:514
```

enter:

```text
Host/IP: 192.168.1.20
Port:    514
```

Do **not** enter the `tcp://` prefix into the host field.

The client uses a bounded RAM-only forwarding queue with no disk spool. TCP keepalive is enabled and rsyslog is configured to restart after process failure.

### Collector unavailable / network disconnected

Temporary outages are handled automatically:

- rsyslog keeps retrying the collector;
- queued messages are held in bounded RAM;
- TCP keepalive detects dead/half-open sessions;
- forwarding failure does not block the appliance's normal logging path.

If the collector remains unavailable long enough to fill the client queue, new **remote copies** can be dropped rather than allowing RAM use to grow without bound.

If the client subsequently reboots while using volatile journald, any unsent current-boot history is also lost. The design deliberately favours appliance stability over unlimited store-and-forward buffering.

---

## 11. End-to-end test

After the collector and one client are configured, send a test from the client:

```bash
logger -p user.notice "CENTRAL SYSLOG TEST from $(hostname)"
```

On the server:

```bash
find ~/rpi-logs -type f -mmin -5 -print
```

Then inspect the relevant file, for example:

```bash
tail -50 ~/rpi-logs/right-pizza/$(date +%Y/%m/%d).log
```

Reboot the client and send another message. Both boots should remain visible on the server.

---

## 12. First client deployment sequence

For a new or freshly maintained appliance, the recommended order is:

1. Configure Raspberry Pi OS and application services normally.
2. Run/update `wifi-stability.sh` where applicable.
3. Reboot and verify Wi-Fi/SSH.
4. Set up the central log server if one is not already available.
5. Run `setup-rpi-log-server.sh --verify` on the collector.
6. Run `sd_card_improvements.sh` on the client while the real root filesystem is writable.
7. Accept the RAM-based defaults unless there is a workload-specific reason not to.
8. Review any extra-persistent-mount warning. On an unusual layout, OverlayFS defaults to **no** and requires an explicit second confirmation to override.
9. Enable OverlayFS on a conventional appliance layout.
10. Configure the central syslog host/IP and TCP port when prompted.
11. Review the script's planned changes and confirm. The run also installs the persistent maintenance-mode helper.
12. Reboot.
13. Run:

```bash
sudo bash sd_card_improvements.sh --verify
```

14. Send a `logger` test and confirm it appears under `~/rpi-logs/<hostname>/...` on the server.
15. Run the application normally and monitor memory/log usage during an initial soak.

---

## 13. Routine verification

### Client

```bash
sudo bash sd_card_improvements.sh --verify
```

Additional useful commands:

```bash
free -h
swapon --show
df -h /tmp /var/tmp
findmnt /
findmnt /boot/firmware 2>/dev/null || findmnt /boot
journalctl --disk-usage
```

Check for memory failures:

```bash
dmesg -T | egrep -i 'oom|killed process|out of memory' || true
```

Check for storage-related kernel errors:

```bash
dmesg -T | egrep -i 'mmc.*(timeout|crc|fail|error)|I/O error|EXT4-fs.*(error|warning)' || true
```

### Server

```bash
sudo bash setup-rpi-log-server.sh --verify
```

Useful operational checks:

```bash
systemctl status rsyslog --no-pager
ss -lntp | grep ':514'
du -sh ~/rpi-logs/*
journalctl -t rpi-fleet-log-maint
journalctl -t rpi-fleet-log-space
```

---

## 14. Tuning by workload

### Docker, databases, or memory-heavy services

- Keep `/tmp` and `/var/tmp` modest.
- If large temporary operations are common, set one or both to `0` rather than allowing tmpfs pressure to destabilise the service.
- Increase zram only if logs show genuine OOM pressure.
- Apply application/container-specific log limits; journald limits do not automatically bound every application's private log files.

### Frequent apt upgrades or builds

Maintenance should normally be done with OverlayFS disabled. If package operations require substantial temporary space, increase `/tmp` temporarily or leave it on disk while maintenance is being performed.

### Chatty clients

Do not simply increase every client-side RAM queue or journal cap. The preferred control points are:

1. Reduce unnecessary application verbosity.
2. Keep the client journal bounded.
3. Let the central server's per-device cap prevent one noisy unit monopolising storage.

### Need more forensic history

Increase the **server-side** retention days or per-device cap before substantially increasing volatile client journal memory. Central storage is a better place for historical logs than a Zero 2 W's RAM.

---

## 15. Signs a value needs adjustment

- **OOM kills / random service deaths** — reduce tmpfs usage, inspect processes, then consider more zram.
- **High CPU while swap is busy** — investigate sustained memory pressure; more zram is not necessarily the answer.
- **`No space left on device` under `/tmp` or `/var/tmp`** — increase that tmpfs or set it to `0`.
- **Client volatile journal reaches its cap very quickly** — investigate chatty services; avoid simply consuming more Zero 2 W RAM.
- **One server hostname repeatedly hits its 250 MiB cap** — inspect that device's logging volume before increasing the cap.
- **Server free-space warning fires** — inspect total fleet usage and retention before allowing the filesystem to fill.
- **Missing logs during a long collector outage** — expected once the bounded client queue is exhausted; use a more durable collector/network path if guaranteed delivery becomes a requirement.

---

## 16. OverlayFS maintenance workflow

Once OverlayFS is active, changes to the root filesystem are temporary. This includes package installs, service enable/disable operations, configuration edits, user/account changes, application files, and most local logs.

Do **not** perform an `apt upgrade`, package installation, or other persistent system change while protected and assume it will survive reboot.

### Enter writable maintenance mode

From a protected boot:

```bash
sudo bash sd_card_improvements.sh --disable-overlayfs-next-boot
sudo reboot
```

After reboot:

```bash
sudo bash sd_card_improvements.sh --verify
```

The expected state is:

```text
MAINTENANCE MODE ACTIVE
root: writable real filesystem
boot: writable
OverlayFS remains disabled until explicitly restarted
```

You can now perform normal system work and reboot as many times as needed:

```bash
sudo apt update
sudo apt full-upgrade
sudo apt install ...
sudoedit /etc/...
sudo reboot
```

The maintenance marker survives those reboots and the helper remounts the boot partition writable each time.

### Return to protected mode

After all work and any required maintenance reboots are complete:

```bash
sudo bash sd_card_improvements.sh --restart-overlayfs
```

The restart command:

- checks for additional persistent mounts and asks for explicit confirmation if any are present;
- ensures the overlay kernel module hint is present;
- refreshes initramfs where `update-initramfs` is available;
- clears the maintenance marker;
- configures Raspberry Pi OS OverlayFS and boot write-protection for the next boot.

You may finish work in the current writable boot after running `--restart-overlayfs`; protection becomes active only after the following reboot.

Then:

```bash
sudo reboot
sudo bash sd_card_improvements.sh --verify
```

The expected state is **PROTECTED MODE**, with root OverlayFS active and the boot partition read-only.

---

## 17. Important OverlayFS caveats

### Maintenance mode is intentionally less power-loss resistant

While the Pi is in writable maintenance mode, the real root filesystem is being modified. An arbitrary power cut has the same filesystem/write-interruption risk as a conventional writable Raspberry Pi installation. Finish maintenance and restore OverlayFS rather than leaving units writable indefinitely.

### Package operations while protected can create a misleading mixed runtime state

An `apt install` or upgrade can modify the live RAM upper layer, restart services, and make the current boot look updated. The update disappears on reboot. Always enter maintenance mode first.

### Kernel and firmware upgrades need the boot filesystem writable

The maintenance helper keeps `/boot/firmware` writable throughout the maintenance period specifically so kernel, firmware and initramfs updates can complete normally. `--restart-overlayfs` refreshes initramfs before protection is restored.

### Verify OverlayFS after kernel/initramfs changes

After returning to protected mode, always run:

```bash
sudo bash sd_card_improvements.sh --verify
```

Do not assume that the presence of an `overlayroot=tmpfs` setting proves the overlay actually mounted. The verification checks the live root filesystem type.

### RAM-backed writes are broader than journald

The script bounds journald, `/tmp`, `/var/tmp`, zram and the remote log queue, but an application can still write elsewhere in the OverlayFS upper layer, for example under `/home`, `/var/lib` or a private cache directory. Large or continuously growing application writes can therefore consume RAM even though the SD card is protected.

For fixed-purpose appliances, identify applications that persist large mutable data and either redesign that storage path or avoid OverlayFS on that unit.

### Docker and local databases need particular care

Docker state under `/var/lib/docker`, local databases, downloaded media, caches, spool directories and similar high-write workloads are poor candidates for an unconstrained RAM-backed upper layer. Use separate deliberately designed persistence or leave OverlayFS disabled where the workload requires it.

### Extra persistent mounts are deliberately treated conservatively

Current Raspberry Pi OS OverlayFS has had regressions involving additional partitions/mount layouts. The script detects additional persistent mounts, warns prominently, defaults initial OverlayFS enablement to **no**, and asks for explicit confirmation when `--restart-overlayfs` sees them.

### Local journal history under normal OverlayFS is current-boot only

On a normal two-partition client the local journal is volatile and RAM-capped. Cross-boot forensic history comes from the central rsyslog collector. During a network/collector outage, remote delivery is best-effort with a bounded RAM queue; a sufficiently long outage can lose remote copies rather than allowing client RAM use to grow without bound.

### The final writable state is the appliance master

Treat the fully updated, tested writable filesystem immediately before `--restart-overlayfs` as the master persistent state. Ordinary protected boots then start from that known-good base and discard runtime filesystem changes on reboot.
