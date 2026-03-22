# Vanish Lite: Current Features

## 1) Session Lifecycle (Create / Stop / Status)
- Create disposable Linux users by mode.
- Stop and cleanup sessions from CLI and admin panel.
- Show active session status and runtime.
- Supports custom username/password.
- Supports `persist until shutdown` session behavior.

Implemented in:
- `engine/main.cpp`
- `engine/session.cpp`
- `engine/session.h`
- `engine/session_manager.cpp`
- `engine/session_manager.h`
- `admin_panel/server.py`
- `admin_panel/static/app.js`
- `admin_panel/static/index.html`

## 2) Policy Engine (Mode-Based)
- `dev`, `secure`, `privacy`, `exam`, `online` mode handling.
- Resource limit policy (`nproc`) with override support.
- Exam network restriction and persistence mount.
- Privacy RAM-home mount and per-session privacy DNS toggle.
- Online mode controls for network, DNS filtering, USB, persistence.

Implemented in:
- `engine/policy_enforcer.cpp`
- `engine/policy_enforcer.h`

## 3) Online Restriction Controls
- Allowed sites and blocked sites input from admin UI.
- URL/domain normalization (handles `https://...` style input).
- Strict allow-list behavior when allowed sites are provided.
- Block-list behavior when only blocked sites are provided.
- Per-user owner-scoped firewall enforcement (local to the session user).
- Command restriction via session shell guard.

Implemented in:
- `engine/policy_enforcer.cpp`
- `admin_panel/server.py`
- `admin_panel/static/index.html`
- `admin_panel/static/app.js`

## 4) Per-Session Snapshots and Reports
- Per-session policy snapshot file.
- Per-session generated config snapshots (`online.conf`, `monitor.conf`).
- Per-session compliance report JSON.
- Admin panel viewer for config snapshots and reports.

Implemented in:
- `engine/session.cpp`
- `admin_panel/server.py`
- `admin_panel/static/app.js`
- `admin_panel/static/index.html`

## 5) Cleanup Reliability Improvements
- Force cleanup for stop-all and stop-single:
  - `pkill -9`, `loginctl terminate-user`, `umount -l`, `userdel -f -r`
- Cleanup works for custom usernames (not only `vanish_*`).
- Managed-user registry and session-record based cleanup.
- Expired-session cleanup removes associated snapshot/report artifacts.

Implemented in:
- `engine/session.cpp`
- `engine/session_manager.cpp`
- `admin_panel/server.py`
- `engine/utils.cpp`

## 6) Admin Panel UX + Operations
- Mode-specific options visible only for selected mode.
- Mode description panel with default behavior summary.
- Full-width code-editor style inputs for online config fields.
- Toggle-based config editors (open only when button clicked).
- Per-session actions: `Config`, `Report`, `Extend`, `Stop`.
- Preset system: save/load/delete presets.
- Validate and Dry-Run before start.

Implemented in:
- `admin_panel/static/index.html`
- `admin_panel/static/styles.css`
- `admin_panel/static/app.js`
- `admin_panel/server.py`

## 7) Testing Tooling
- Unit-style backend checks for policy line generation, presets, session parsing.
- Project-level test runner.
- Root integration mode/config test script with cleanup trap.

Implemented in:
- `scripts/test_admin_panel.py`
- `scripts/test_everything.sh`
- `scripts/test_modes_integration.sh`

## Quick Reference: Important Paths
- CLI entry: `engine/main.cpp`
- Session create/cleanup: `engine/session.cpp`
- Session records/timeouts: `engine/session_manager.cpp`
- Policies/modes: `engine/policy_enforcer.cpp`
- Admin API: `admin_panel/server.py`
- Admin UI: `admin_panel/static/index.html`, `admin_panel/static/app.js`, `admin_panel/static/styles.css`
- Tests: `scripts/`
