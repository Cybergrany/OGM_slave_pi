### Recommended starting values (safe, SD-friendly, low operational risk)

These assume “typical Pi appliance” workloads (services + light Python/Node + occasional apt upgrades), with `/var/log` kept on disk and journald capped.

#### If you have 1 GB RAM

* **ZRAM_PCT:** 50%
* **/tmp tmpfs:** 128 MB
* **/var/tmp tmpfs:** 64 MB
* **journald cap (SystemMaxUse):** 100 MB

#### If you have 2–4 GB RAM

* **ZRAM_PCT:** 50%
* **/tmp tmpfs:** 256 MB
* **/var/tmp tmpfs:** 128 MB
* **journald cap:** 200 MB

#### If you have 8 GB+ RAM

* **ZRAM_PCT:** 25–33% (start at 25%)
* **/tmp tmpfs:** 512 MB
* **/var/tmp tmpfs:** 256 MB
* **journald cap:** 300 MB

If you want one universal “start here” set for most Pis (1–4 GB): **ZRAM_PCT=50, /tmp=256, /var/tmp=128, journald cap=200**.

For a Raspberry Pi Zero 2 W (512 MB RAM), start conservatively so tmpfs doesn’t steal too much memory from services.

### Recommended “safe default” preset

* **ZRAM_PCT:** **50**
  (≈256 MiB zram swap)
* **/tmp tmpfs (MB):** **64**
* **/var/tmp tmpfs (MB):** **32**
* **journald cap (MB):** **50** (persistent, capped)

### What these choices do (and why they fit a Zero 2 W)

**ZRAM_PCT (swap in compressed RAM)**

* **Pros:** reduces SD writes vs disk swap; reduces OOM kills vs no swap.
* **Cons:** costs CPU during compression/decompression; on a Zero 2 W this is noticeable under heavy swapping.
* **Why 50%:** enough headroom for short spikes without encouraging constant swap-thrashing.

**/tmp and /var/tmp as tmpfs**

* **Pros:** cuts SD writes from temporary files (apt, installers, small scratch files).
* **Cons:** uses RAM (and then zram) as it fills; large temp operations can fail with “No space left on device.”
* **Why 64/32 MB:** keeps the benefit but avoids eating a big chunk of a 512 MB system.

**journald cap (persistent + bounded)**

* **Pros:** keeps logs for debugging/recovery, but limits growth (and write churn).
* **Cons:** smaller cap = shorter history retained.
* **Why 50 MB:** enough to retain recent events without letting logs dominate disk usage on a small system.

### When to change these values

**If you run Docker, a database, or anything memory-hungry**

* Keep tmpfs modest or even disable it:

  * `/tmp = 32`, `/var/tmp = 16` or set both to **0** (leave on disk)
* Consider **ZRAM_PCT = 60** only if you see OOM kills.

**If you do apt upgrades often / unpack large archives**

* Increase `/tmp` to **96–128 MB**, but watch memory pressure.

**If you want more log history**

* journald cap **100 MB** (more writes + space, but still bounded).

### Quick “is it working / is it too tight” checks

* Memory/swap pressure:

  * `free -h`
  * `swapon --show`
* tmpfs filling:

  * `df -h /tmp /var/tmp`
* OOM evidence:

  * `dmesg -T | egrep -i 'oom|killed process|out of memory' || true`

If you tell me what you run on the Zero 2 W (e.g., MQTT/Node-RED, serial gateway, Docker, camera, database), I can give a single tuned preset.


---

### What each option does and its trade-offs

#### 1) `ZRAM_PCT` (zram swap size)

**Impact**

* Higher = more “soft landing” before OOM, fewer crashes under memory spikes.
* But higher also means: more RAM can be tied up in swap (compressed) and more CPU used compressing/decompressing under pressure.

**Guidance**

* 50% is a good reliability baseline on 1–4 GB.
* On 8 GB+, you rarely need that much swap; 25–33% is usually plenty.
* If you see OOM kills in logs, increase by 10–20 points.
* If you see sustained high CPU + heavy swapping (“swap thrash”), reduce it and/or reduce tmpfs sizes.

Notes:

* On newer Raspberry Pi OS builds using `rpi-swap`, the script sets an absolute zram size derived from this percent and applies it on reboot.

#### 2) `/tmp` tmpfs size

**Impact**

* Reduces SD writes from temporary files (package installs, compilers, apps).
* Risk: if a process needs more temp space than you allocate, it can fail with “No space left on device”.
* Also contributes to memory pressure (tmpfs uses RAM/swap as it fills).

**Guidance**

* Keep it modest unless you compile/build on the Pi.
* If you do builds, large downloads/unpacks, video processing, etc., increase it (or set to 0 to keep `/tmp` on disk for safety).

#### 3) `/var/tmp` tmpfs size

**Impact**

* Similar to `/tmp`, but fewer workloads use it heavily.
* Generally safe to keep smaller than `/tmp`.

**Guidance**

* Typically half of `/tmp` is a good starting point.

#### 4) `journald` persistent cap (`SystemMaxUse`)

**Impact**

* Keeps logs on disk (better supportability than RAM-only logging) but limits growth.
* Smaller cap reduces disk usage and long-term write volume, but you retain less history.
* It does not stop log writes; it mainly bounds retention.

**Guidance**

* 100–200 MB is a good default.
* If you’re actively debugging intermittent issues, 300–500 MB may be worth it.
* If the system is stable and you want minimal disk churn, 50–100 MB is fine.

---

### Adjustments by use case

#### “I want maximum reliability, don’t care about SD wear as much”

* Keep **zram at 50%**
* Set `/tmp` and `/var/tmp` **to 0** (don’t mount tmpfs)
* Keep journald capped at **200–300 MB**

#### “I want maximum SD longevity”

* zram **50%**
* `/tmp` **256–512 MB**, `/var/tmp` **128–256 MB**
* journald cap **100–200 MB**
* (Optional but high value outside this script: reduce chatty services / app log verbosity)

#### “I run Docker / chatty services”

* zram **50%**
* `/tmp` **256 MB**, `/var/tmp` **128 MB**
* journald cap **200–300 MB**
* Also consider Docker log limits (otherwise logs can dominate disk writes regardless of journald).

---

### Practical signs your values need tuning

* **OOM kills / random service deaths:** increase `ZRAM_PCT`, reduce tmpfs sizes, or reduce workload memory.
* **High CPU + slow system while swap used:** reduce `ZRAM_PCT` a bit; check for runaway process; reduce logging verbosity.
* **“No space left on device” errors in `/tmp` or `/var/tmp`:** increase those tmpfs sizes or set them to 0.

