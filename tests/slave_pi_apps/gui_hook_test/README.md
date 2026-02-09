# gui_hook_test app

Deploy-loadable child app used to validate new `OGM_slave_pi` GUI/app hooks.

Files:

- `gui_hook_test_app.py`: supervised child app startup checks + heartbeat.
- `run_gui_hook_test.py`: Pi-side runner that validates app reload and reports.
- `ipc_ndjson.py`: shared IPC utility.

Run full setup instructions from:

- `OGM_slave_pi/tests/README.md`
