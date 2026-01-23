## Evaluation: is reliable Modbus RTU possible on GPIO14/15?

Yes, but it depends on **which UART is actually routed to GPIO14/15** and how much interrupt latency your Pi is experiencing.

Key points:

* On Raspberry Pi, **GPIO14/15 are the “primary UART” pins** (TX/RX). Which underlying UART that “primary” maps to depends on model and configuration. Raspberry Pi OS exposes stable symlinks: **`/dev/serial0` = primary UART** and **`/dev/serial1` = secondary UART**; these symlinks can point to either **`/dev/ttyAMA0` (PL011)** or **`/dev/ttyS0` (mini UART)**. ([Raspberry Pi][1])
* **mini UART is a poor fit for Modbus RTU**: it has smaller FIFOs and is “more prone to losing characters at higher baudrates”; it also has multiple feature limitations (notably including **no parity bit** per the Raspberry Pi documentation), which can be a hard blocker for typical Modbus 8E1 configurations. ([Raspberry Pi][1])
* **PL011 is the UART you want** on GPIO14/15 for Modbus RTU. Even then, the **hardware FIFO is small (commonly discussed as 16 bytes)**, so if Linux is delayed servicing UART interrupts (system load, long IRQ-off sections, etc.), you can get **hardware FIFO overruns** that look like “dropped frames/bytes”. ([Raspberry Pi Forums][2])
* Model gotcha: on **Raspberry Pi 3 and 4, the default primary/console UART is often the mini UART** because PL011 is used for Bluetooth unless you change overlays; on **Raspberry Pi 5, the primary UART is on the debug header by default**, and `/dev/serial0` points to that debug UART. ([Raspberry Pi][1])

Practical conclusion: **Reliable Modbus RTU on GPIO14/15 is achievable** if you (1) ensure those pins use **PL011**, (2) remove console/login usage from that UART, and (3) confirm you’re not hitting **overrun/framing/parity** errors due to latency or physical-layer issues.

---

## Step-by-step: diagnose dropped frames

### 1) Confirm you’re using the right UART (PL011 vs mini UART)

Run:

```bash
ls -l /dev/serial0 /dev/serial1 2>/dev/null || true
readlink -f /dev/serial0
dmesg | egrep -i 'ttyAMA|ttyS|pl011|serial' | tail -n 50
```

Interpretation:

* If `readlink -f /dev/serial0` → **`/dev/ttyAMA0`**: that’s **PL011** (good). ([Raspberry Pi][1])
* If it → **`/dev/ttyS0`**: that’s **mini UART** (likely culprit). ([Raspberry Pi][1])
* If you’re on **Pi 5** and it → **`/dev/ttyAMA10`**: that’s the **debug UART** mapping for `/dev/serial0` by default (meaning GPIO14/15 may not be what you think). ([Raspberry Pi][1])

### 2) Ensure you are not accidentally running a console/login on the port

Use raspi-config (recommended by Raspberry Pi docs): ([Raspberry Pi][1])

```bash
sudo raspi-config
# Interface Options -> Serial Port
# “login shell over serial?” -> No
# “serial port hardware enabled?” -> Yes
sudo reboot
```

Also verify (common causes of interference):

```bash
systemctl status serial-getty@serial0.service --no-pager || true
```

If it’s enabled, disable it:

```bash
sudo systemctl disable --now serial-getty@serial0.service
```

And ensure boot cmdline is not claiming the serial console (Bookworm typically uses `/boot/firmware/cmdline.txt`):

```bash
grep -n 'console=serial0\|console=ttyAMA\|console=ttyS' /boot/firmware/cmdline.txt || true
```

If present, remove the `console=...` fragment (keep the line single-line), then reboot.

### 3) Determine whether you’re dropping bytes due to UART overruns vs physical-layer corruption

You want to distinguish:

* **Overrun** (UART FIFO overflow due to latency): bytes go missing.
* **Framing/parity** errors (noise/wiring/bias/termination/levels): bytes corrupt or framing breaks.

A very direct way is to read kernel serial counters via `TIOCGICOUNT` (example widely used on Pi for PL011 overrun diagnosis): ([Raspberry Pi Forums][2])

Minimal C snippet to print counters:

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/serial.h>

int main(int argc, char** argv){
    const char* dev = (argc > 1) ? argv[1] : "/dev/serial0";
    int fd = open(dev, O_RDONLY | O_NOCTTY);
    if(fd < 0){ perror("open"); return 1; }

    for(;;){
        struct serial_icounter_struct ic = {0};
        if(ioctl(fd, TIOCGICOUNT, &ic) == 0){
            printf("rx:%d tx:%d frame:%d parity:%d overrun:%d brk:%d buf_overrun:%d\n",
                ic.rx, ic.tx, ic.frame, ic.parity, ic.overrun, ic.brk, ic.buf_overrun);
            fflush(stdout);
        } else {
            perror("ioctl(TIOCGICOUNT)");
            return 2;
        }
        usleep(500000);
    }
}
```

How to interpret:

* `overrun` or `buf_overrun` increasing while traffic runs ⇒ **latency / FIFO overrun** problem.
* `frame` / `parity` increasing ⇒ **signal integrity / wiring / wrong UART features / wrong parity config**.

Also watch `dmesg -w` while traffic runs; overruns often log as “input overrun”.

### 4) Stress test to prove it’s latency-related

Run your Modbus traffic, then in another terminal:

```bash
sudo apt-get update && sudo apt-get install -y stress-ng
stress-ng --cpu 4 --io 2 --vm 2 --vm-bytes 128M --timeout 60s
```

If overruns/CRC errors spike only under load, you’re looking at **interrupt scheduling latency**, not “a small Linux buffer”.

---

## Step-by-step: ensure you’re not on mini UART (and fix it)

### Option A (most reliable): move PL011 to GPIO14/15 by disabling Bluetooth

Edit config (Bookworm path shown):

```bash
sudo nano /boot/firmware/config.txt
```

Add:

```ini
enable_uart=1
dtoverlay=disable-bt
```

Then disable the Bluetooth UART init service (per Raspberry Pi docs): ([Raspberry Pi][1])

```bash
sudo systemctl disable --now hciuart || true
sudo reboot
```

After reboot:

```bash
readlink -f /dev/serial0
# should now be /dev/ttyAMA0 on Pi 3/4 class devices
```

### Option B (keep Bluetooth): put Bluetooth on mini UART, keep PL011 on GPIO14/15

Per Raspberry Pi docs, use `miniuart-bt` and fix the VPU core clock (mini UART depends on it): ([Raspberry Pi][1])

In `/boot/firmware/config.txt`:

```ini
enable_uart=1
dtoverlay=miniuart-bt
core_freq=250
```

Reboot and confirm `/dev/serial0` resolves to `ttyAMA0`.

---

## Other steps that commonly make Modbus RTU reliable on Pi UART

### 1) Reduce the chance of FIFO overrun (latency mitigation)

* Run your Modbus process at higher priority:

  * `sudo chrt -f 50 <your_modbus_command>` (real-time FIFO scheduling)
* Pin it to a CPU core:

  * `taskset -c 2 <your_modbus_command>`
* Use performance governor (reduces wake/scheduling jitter):

  * `sudo raspi-config` → Performance options (if available), or use `cpufrequtils`.

### 2) Make sure your serial settings match Modbus RTU

Common Modbus RTU is **8E1**. If you were accidentally on mini UART, parity may be unavailable per Pi docs, making 8E1 impossible and causing framing/parity counters/errors. ([Raspberry Pi][1])
Verify current port settings:

```bash
stty -F /dev/serial0 -a
```

### 3) Avoid userspace patterns that create “gaps” inside a frame

* Write each frame in **one `write()`** call (don’t byte-stream from Python loops).
* Read in a dedicated thread/process using `poll()/select()` and drain the fd quickly.

### 4) Validate the RS485 physical layer (because it can mimic “dropped frames”)

Even if the UART is perfect, RS485 wiring issues create CRC errors and apparent truncation:

* Termination only at the two ends (typically 120Ω).
* Bias/failsafe at one location (so the bus doesn’t float idle).
* Common reference/ground strategy appropriate to your setup.
* Keep stubs short, twisted pair for A/B.

### 5) If you’re on Pi 4/5, consider using an additional PL011 instead of fighting the primary

Pi 4 and Pi 5 have **additional PL011 UARTs** (disabled by default) that can be enabled with overlays (e.g. `uart2`, `uart3`, etc.). ([Raspberry Pi][1])
This can let you keep Bluetooth/console arrangements while dedicating a PL011 to Modbus.

---

## What usually causes “missing frames” on Pi Modbus RTU

In practice, the top three are:

1. **Actually using mini UART** on GPIO14/15 (feature-limited + more character loss at higher baud). ([Raspberry Pi][1])
2. **Hardware FIFO overrun** on PL011 due to interrupt latency (shows up in `TIOCGICOUNT.overrun`). ([Raspberry Pi Forums][2])
3. **RS485 physical-layer problems** (shows up as framing/parity increments, CRC errors, or inconsistent packet lengths).

If you run the UART-identification steps + `TIOCGICOUNT` counter check, you can usually classify it decisively in minutes.

[1]: https://www.raspberrypi.com/documentation/computers/configuration.html "Configuration - Raspberry Pi Documentation"
[2]: https://forums.raspberrypi.com/viewtopic.php?t=248128&utm_source=chatgpt.com "PL011 UART overruns with RT-PREEMPT kernel"
