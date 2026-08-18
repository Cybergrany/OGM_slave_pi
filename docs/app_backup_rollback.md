# Desktop App Backup and Rollback

This procedure provides a quick rollback for visual and gameplay testing of a
child app deployed with `OGM_The_Core/scripts/deploy_slave_pi.py`.

It is suitable when all of the following are true:

- The Pi already has the multi-app runtime installed with
  `app_config_version: 2`.
- The deployer action will be **upload and run app**.
- The objective is to restore the previous app, configuration and Python
  environment, rather than to restore the complete Pi operating system.
- The service, configuration and app directories all resolve beneath the
  Desktop-level `OGM_slave_pi` directory.

A metadata-preserving copy of that entire directory is sufficient under these
conditions. It must include hidden files, especially `runtime/.venv`.

> [!WARNING]
> Do not use this procedure as the sole rollback for the deployer's full
> **install** action. A full install can change system packages, systemd units,
> boot configuration, pinmaps and other files outside the Desktop directory.

## 1. Set the paths

The examples below deliberately use `YOUR_PI_USER`. Replace it with the Pi's
actual login name before running any command.

```text
/home/YOUR_PI_USER/Desktop/OGM_slave_pi
/home/YOUR_PI_USER/Desktop/OGM_slave_pi.before-app-test
```

Keep the backup beside the deployed directory, not inside it.

## 2. Verify what the service uses

Check the installed service before making the backup:

```bash
sudo systemctl show ogm_pi.service \
  -p WorkingDirectory -p ExecStart --no-pager

sudo systemctl cat ogm_pi.service

sudo grep -E \
  '^(apps_dir|pinmap|custom_types_dir|app_config_version):' \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi/config/ogm_pi.yaml
```

Confirm that:

- `WorkingDirectory`, `ExecStart` and the service's `--config` argument use the
  Desktop-level `OGM_slave_pi` tree.
- `apps_dir`, `pinmap` and `custom_types_dir` also resolve inside that tree.
- `app_config_version` is `2`.

If any configured path or symlink resolves outside that tree, stop and include
the resolved external files in the backup. A directory copy cannot restore
files it does not contain.

## 3. Check space and stop the runtime

Estimate the required space:

```bash
sudo du -sh /home/YOUR_PI_USER/Desktop/OGM_slave_pi
df -h /home/YOUR_PI_USER/Desktop
```

Then stop both the service and its activation socket. Stopping only the service
is insufficient because socket activity could start it again.

```bash
sudo systemctl stop ogm_pi.service ogm_pi.socket

systemctl is-active ogm_pi.service ogm_pi.socket
pgrep -af 'ogm_pi.daemon|pizza_right_app.py'
```

Both units must report `inactive`, and `pgrep` must not show the daemon or app.
Do not copy or replace the directory while either process is still running.

## 4. Make and verify the backup

First ensure the proposed backup path does not already exist:

```bash
test ! -e /home/YOUR_PI_USER/Desktop/OGM_slave_pi.before-app-test
```

If that command reports failure, stop and choose a new backup name. Do not copy
over an earlier known-good backup.

Create a metadata-preserving copy:

```bash
sudo cp -a --reflink=auto \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi.before-app-test
```

`cp -a` preserves ownership, permissions, timestamps, symlinks and hidden
files. `--reflink=auto` uses a fast copy-on-write clone where supported and
falls back to a normal copy otherwise.

Verify the copied contents before deploying:

```bash
sudo diff -qr \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi.before-app-test

sudo test -x \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi.before-app-test/runtime/.venv/bin/python
```

`diff` should produce no output, and the virtualenv check should succeed.

## 5. Deploy the test app

From the matching `OGM_The_Core` checkout, run:

```bash
python3 scripts/deploy_slave_pi.py
```

Choose **upload and run app**. Do not choose **install** for this rollback
workflow.

The app-only action can replace the selected app payload, update its entry in
the runtime YAML and install or upgrade its Python requirements in the shared
`runtime/.venv`. The full-directory backup captures the previous versions of
all of these.

After deployment, check that the service is healthy:

```bash
sudo systemctl --no-pager -l status ogm_pi.service
sudo journalctl -u ogm_pi.service -n 100 --no-pager
```

## 6. Roll back

Stop the runtime and confirm that its processes have exited:

```bash
sudo systemctl stop ogm_pi.service ogm_pi.socket

systemctl is-active ogm_pi.service ogm_pi.socket
pgrep -af 'ogm_pi.daemon|pizza_right_app.py'
```

Preserve the failed test deployment for diagnosis. Before moving it, ensure the
destination does not already exist:

```bash
test ! -e /home/YOUR_PI_USER/Desktop/OGM_slave_pi.failed-app-test
```

If that command reports failure, stop and choose a different destination.

Move the test deployment aside and restore a fresh copy of the backup:

```bash
sudo mv \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi.failed-app-test

sudo cp -a \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi.before-app-test \
  /home/YOUR_PI_USER/Desktop/OGM_slave_pi
```

Restart and inspect the restored runtime:

```bash
sudo systemctl reset-failed ogm_pi.service ogm_pi.socket
sudo systemctl start ogm_pi.socket ogm_pi.service

sudo systemctl --no-pager -l status ogm_pi.service
sudo journalctl -u ogm_pi.service -n 100 --no-pager
```

An app-only folder restoration does not require `systemctl daemon-reload`
because it does not replace the installed unit files.

## What this does not roll back

The app-only deployer can refresh host-level DRM/kiosk policy outside the
Desktop directory, including systemd drop-ins, supplementary group membership,
display-manager state and `getty@tty1` state. Restoring the folder does not
revert those host settings.

This is normally acceptable when restoring an older version of the same app:
the old and new app manifests should request the same host policy. If their
`app.json` DRM, kiosk, audio or host-package requirements differ, compare those
manifests before testing and prepare a separate host-level rollback.

Stop and prepare a broader backup if the deployment will include any of the
following:

- The deployer's full **install** action.
- A runtime or operating-system upgrade.
- Different pinmaps or Modbus definitions that must also be restored.
- App files, configuration, assets or state stored outside the Desktop tree.
- Changed DRM, kiosk, audio or host-package requirements.
