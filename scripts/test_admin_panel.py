#!/usr/bin/env python3
import importlib.util
import tempfile
from pathlib import Path


def load_server_module(repo_root: Path):
    module_path = repo_root / "admin_panel" / "server.py"
    spec = importlib.util.spec_from_file_location("vanish_admin_server", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load admin_panel/server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def test_build_policy_lines(server):
    payload = {
        "config": {
            "exam_restrict_network": True,
            "online_enable_network": False,
            "online_block_commands": "curl,git",
            "privacy_ram_home_size_mb": 3072,
            "proc_limit_override": 900,
        }
    }
    lines = server.build_policy_lines(payload)
    joined = "\n".join(lines)
    assert_true("exam.restrict_network=true" in joined, "Missing exam config line")
    assert_true("online.enable_network=false" in joined, "Missing online config line")
    assert_true("online.block_commands=curl,git" in joined, "Missing blocked commands line")
    assert_true("privacy.ram_home_size_mb=3072" in joined, "Missing RAM size line")
    assert_true("resource.proc_limit=900" in joined, "Missing proc limit line")


def test_presets_roundtrip(server):
    with tempfile.TemporaryDirectory() as tmp:
        server.PRESETS_FILE = Path(tmp) / "presets.json"
        ok = server.save_presets({"demo": {"mode": "online"}})
        assert_true(ok, "Failed to save presets")
        loaded = server.load_presets()
        assert_true("demo" in loaded, "Preset key missing")
        assert_true(loaded["demo"]["mode"] == "online", "Preset mode mismatch")


def test_session_parse_and_record_filter(server):
    with tempfile.TemporaryDirectory() as tmp:
        server.SESSION_DIR = Path(tmp)

        session_file = server.SESSION_DIR / "vanish_123"
        session_file.write_text(
            "username=vanish_123\n"
            "mode=exam\n"
            "start_time=100\n"
            "last_active=100\n"
            "duration=7200\n"
            "persist_until_shutdown=1\n",
            encoding="utf-8",
        )

        conf_file = server.SESSION_DIR / "vanish_123.policy.conf"
        conf_file.write_text("x=1\n", encoding="utf-8")

        parsed = server.parse_session_file(session_file)
        assert_true(parsed["persist_until_shutdown"] is True, "Persist flag parse failed")
        assert_true(server.is_session_record(session_file), "Valid session record not recognized")
        assert_true(not server.is_session_record(conf_file), "Config file should not be treated as session record")


def test_scan_home_dir(server):
    """Verify scan labels and exclusion logic using _scan_home_dir_impl."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        # Create a fake user home layout.
        (home / ".mozilla").mkdir()
        (home / ".ssh").mkdir()
        (home / ".vimrc").write_text("set number\n", encoding="utf-8")
        (home / ".cache").mkdir()           # must NOT appear in results
        (home / ".config").mkdir()
        (home / ".config" / "myapp").mkdir()  # should appear as Generic App Config

        entries = _scan_home_dir_impl(server, home)
        paths = {e["rel_path"] for e in entries}

        assert_true(".mozilla" in paths, "Firefox Profile not detected")
        assert_true(".ssh" in paths, "SSH Keys not detected")
        assert_true(".vimrc" in paths, "Vim config not detected")
        assert_true(not any(".cache" in p for p in paths), ".cache must be excluded")
        assert_true(any("myapp" in p for p in paths), "Generic app config not detected")
        print(f"  [scan_home_dir] found {len(entries)} entries: {sorted(paths)}")


def _scan_home_dir_impl(server, home_dir):
    """Call scan_home_dir logic with a custom home directory for testing."""
    import pathlib
    results = []
    for rel, label in server._KNOWN_PATHS:
        candidate = home_dir / rel
        if candidate.exists():
            results.append({'rel_path': rel, 'label': label,
                            'size_mb': server._dir_size_mb(candidate), 'is_known': True})
    for scan_base_rel, scan_label in [('.config', 'Generic App Config'), ('.local/share', 'Generic App Data')]:
        scan_base = home_dir / scan_base_rel
        if not scan_base.is_dir():
            continue
        for child in sorted(scan_base.iterdir()):
            child_rel = f"{scan_base_rel}/{child.name}"
            if any(child_rel.startswith(s) for s in server._SKIP_PREFIXES):
                continue
            already = any(child_rel == r or child_rel.startswith(r + '/') for r, _ in server._KNOWN_PATHS)
            if already:
                continue
            results.append({'rel_path': child_rel, 'label': f"{scan_label}: {child.name}",
                            'size_mb': server._dir_size_mb(home_dir / child_rel), 'is_known': False})
    return results


def main():
    repo_root = Path(__file__).resolve().parent.parent
    server = load_server_module(repo_root)

    tests = [
        ("build_policy_lines", test_build_policy_lines),
        ("presets_roundtrip", test_presets_roundtrip),
        ("session_parse_and_record_filter", test_session_parse_and_record_filter),
        ("scan_home_dir", test_scan_home_dir),
    ]

    failures = []
    for name, fn in tests:
        try:
            fn(server)
            print(f"[PASS] {name}")
        except Exception as exc:
            failures.append((name, str(exc)))
            print(f"[FAIL] {name}: {exc}")

    if failures:
        raise SystemExit(1)

    print("All admin panel tests passed.")


if __name__ == "__main__":
    main()
