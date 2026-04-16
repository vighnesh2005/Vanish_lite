# Vanish Admin Panel

A lightweight local admin dashboard for Project Vanish Lite.

## Features
- Start session by mode (`dev`, `secure`, `privacy`, `exam`, `online`)
- Optional custom username/password while creating session
- Full policy toggles (enable/disable) for exam, online, and privacy mode behavior
- Online-mode allowed/blocked sites configurable directly from panel
- Online-mode blocked commands configurable directly from panel (`curl`, `wget`, `git`, etc.)
- Privacy-mode RAM mount size configurable from panel (in MB)
- Mode-specific option groups are shown only for the currently selected mode
- Stop/cleanup all active vanish sessions
- Per-session actions: view config snapshot, extend one session, stop one session
- Per-session compliance report view
- `Persist Until Shutdown` option to avoid logout-based expiry
- Preset management (save/load/delete)
- Validate + Dry Run before start
- Live active session table (from `/var/vanish_sessions`)
- Live log tail (from `/var/log/vanish_exam.log`)

## Run
From project root:

```bash
make all
sudo make admin-panel
```

Then open:

```text
http://127.0.0.1:8080
```

## Test Script
Run complete project checks:

```bash
scripts/test_everything.sh
```

Run full mode + config integration tests (creates/cleans real sessions for every mode):

```bash
sudo scripts/test_modes_integration.sh
```

## Notes
- Run with `sudo` so the panel can execute the `vanish` binary and access system session/log files.
- If session creation fails, check the status line on the panel first; it now shows backend/root errors directly.
- Cloud backups now store archive files in Supabase Storage and metadata/auth in MongoDB Atlas.
- Set `VANISH_SUPABASE_URL`, `VANISH_SUPABASE_SERVICE_ROLE_KEY`, and `VANISH_SUPABASE_BUCKET` before starting the panel.
- Large cloud uploads are automatically chunked and merged during restore (`VANISH_STORAGE_CHUNK_MB`, default `20`), with automatic chunk downshift retries if the storage provider returns a size-limit error.
- Config deletion from the UI removes both the Atlas metadata record and the corresponding Supabase storage file(s).
- Host/port can be customized:

```bash
sudo VANISH_ADMIN_HOST=127.0.0.1 VANISH_ADMIN_PORT=9090 python3 admin_panel/server.py
```
