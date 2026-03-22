# Vanish Lite: Future Roadmap

## A) Security Hardening
1. Per-session DNS isolation instead of system-wide DNS edits.
2. More robust command restrictions (kernel/audit based), not shell alias only.
3. Transaction-safe rollback inside engine (not only admin panel fallback).
4. Optional tamper-protection for session snapshot/report files.

Likely files to extend:
- `engine/policy_enforcer.cpp`
- `engine/session.cpp`
- `admin_panel/server.py`

## B) Stronger Online Controls
1. IPv6-aware allow/block enforcement.
2. SNI/TLS-aware domain restrictions for HTTPS edge cases.
3. Rule conflict detector for allowed + blocked overlap.
4. Real-time policy strategy indicator in UI (strict allow-list vs block-list).

Likely files to extend:
- `engine/policy_enforcer.cpp`
- `admin_panel/static/app.js`
- `admin_panel/static/index.html`

## C) Better Session Governance
1. Extend session with explicit absolute expiry timestamp.
2. Pause/resume session controls.
3. Per-session live policy state dashboard.
4. Automatic stale watcher cleanup service.

Likely files to extend:
- `engine/session_manager.cpp`
- `engine/session.cpp`
- `admin_panel/server.py`
- `admin_panel/static/app.js`

## D) Product/UX Enhancements
1. Toast notifications and inline field validation hints.
2. Import/export preset files.
3. Search/filter/sort in active sessions table.
4. One-click test button in admin panel.

Likely files to extend:
- `admin_panel/static/index.html`
- `admin_panel/static/styles.css`
- `admin_panel/static/app.js`
- `admin_panel/server.py`

## E) Course-Project Documentation
1. Threat model document.
2. Architecture and sequence diagrams.
3. Demo scripts and benchmark metrics.
4. Failure-mode and recovery matrix.

Suggested locations:
- `docs/threat_model.md`
- `docs/architecture.md`
- `docs/demo_steps.md`
- `docs/metrics.md`
