#!/usr/bin/env python3
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import traceback
import sys
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# MongoDB Atlas + optional GridFS dependency
# The server starts normally even if pymongo is not installed or the URI is
# not set. All /api/cloud/* routes will return a descriptive error instead.
# ---------------------------------------------------------------------------
try:
    from bson import ObjectId
    from pymongo import MongoClient
    _PYMONGO_AVAILABLE = True
except ImportError:
    _PYMONGO_AVAILABLE = False

try:
    import gridfs
    _GRIDFS_AVAILABLE = True
except ImportError:
    _GRIDFS_AVAILABLE = False

ATLAS_DB_NAME: str = os.getenv("VANISH_ATLAS_DB", "vanish_cloud")

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
PROJECT_ROOT = ROOT.parent
VANISH_BIN = PROJECT_ROOT / "vanish"
SESSION_DIR = Path("/var/vanish_sessions")
LOG_FILE = Path("/var/log/vanish_exam.log")
PRESETS_FILE = ROOT / "presets.json"

ALLOWED_MODES = {"dev", "secure", "privacy", "exam", "online"}
SESSION_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")


def now_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def _read_env_var_from_file(path: Path, key: str) -> str:
    """Best-effort KEY=value parser for simple .env files."""
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() != key:
                continue
            val = v.strip().strip("'").strip('"')
            if val:
                return val
    except OSError:
        return ""
    return ""


def _get_env_var_and_source(key: str) -> tuple[str, str]:
    """Resolve an env var from process env first, then .env files."""
    value = os.getenv(key, "").strip()
    if value:
        return value, "environment"

    candidates = [ROOT / ".env", PROJECT_ROOT / ".env"]
    for env_path in candidates:
        file_val = _read_env_var_from_file(env_path, key)
        if file_val:
            return file_val, str(env_path)

    return "", ""


def _get_atlas_uri_and_source() -> tuple[str, str]:
    """
    Resolve Atlas URI from process env first, then from common .env files.
    Returns (uri, source_label).
    """
    return _get_env_var_and_source("VANISH_ATLAS_URI")


def _get_supabase_config() -> dict:
    url, url_source = _get_env_var_and_source("VANISH_SUPABASE_URL")
    service_key, key_source = _get_env_var_and_source("VANISH_SUPABASE_SERVICE_ROLE_KEY")
    bucket, bucket_source = _get_env_var_and_source("VANISH_SUPABASE_BUCKET")
    prefix, prefix_source = _get_env_var_and_source("VANISH_SUPABASE_PREFIX")
    if not bucket:
        bucket = "vanish_backups"
        bucket_source = "default"
    if not prefix:
        prefix = "archives"
        prefix_source = "default"
    if url:
        url = url.rstrip("/")

    return {
        "url": url,
        "service_key": service_key,
        "bucket": bucket,
        "prefix": prefix.strip("/"),
        "url_source": url_source,
        "key_source": key_source,
        "bucket_source": bucket_source,
        "prefix_source": prefix_source,
    }


def _get_cloudinary_config() -> dict:
    cloud_name, cloud_source = _get_env_var_and_source("VANISH_CLOUDINARY_CLOUD_NAME")
    api_key, key_source = _get_env_var_and_source("VANISH_CLOUDINARY_API_KEY")
    api_secret, secret_source = _get_env_var_and_source("VANISH_CLOUDINARY_API_SECRET")
    folder, folder_source = _get_env_var_and_source("VANISH_CLOUDINARY_FOLDER")
    if not folder:
        folder = "vanish_backups"
        folder_source = "default"

    return {
        "cloud_name": cloud_name,
        "api_key": api_key,
        "api_secret": api_secret,
        "folder": folder,
        "cloud_source": cloud_source,
        "key_source": key_source,
        "secret_source": secret_source,
        "folder_source": folder_source,
    }


def parse_session_file(path: Path) -> dict:
    data = {
        "username": "",
        "mode": "unknown",
        "start_time": 0,
        "last_active": 0,
        "duration": 0,
        "persist_until_shutdown": False,
    }

    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            if "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            if key in {"username", "mode"}:
                data[key] = value
            elif key in {"start_time", "last_active", "duration"}:
                try:
                    data[key] = int(value)
                except ValueError:
                    data[key] = 0
            elif key == "persist_until_shutdown":
                data["persist_until_shutdown"] = (value == "1" or value.lower() == "true")
    except OSError:
        return data

    current = now_ts()
    data["minutes_running"] = max(0, (current - data["start_time"]) // 60) if data["start_time"] else 0
    if data["duration"] > 0 and data["start_time"] > 0:
        remaining = data["duration"] - (current - data["start_time"])
        data["seconds_remaining"] = max(0, remaining)
    else:
        data["seconds_remaining"] = None

    return data


def is_valid_session_user(username: str) -> bool:
    return bool(SESSION_USER_RE.match(username or ""))


def session_file_path(username: str) -> Path:
    return SESSION_DIR / username


def session_exists(username: str) -> bool:
    return session_file_path(username).exists()


def is_session_record(entry: Path) -> bool:
    if not entry.is_file():
        return False
    return is_valid_session_user(entry.name)


def stop_single_session(username: str) -> tuple[bool, str]:
    if not is_valid_session_user(username):
        return False, "Invalid username."

    subprocess.run(["pkill", "-9", "-u", username], capture_output=True, text=True)
    subprocess.run(["loginctl", "terminate-user", username], capture_output=True, text=True)
    subprocess.run(["umount", "-l", f"/home/{username}/submit"], capture_output=True, text=True)
    subprocess.run(["userdel", "-f", "-r", username], capture_output=True, text=True)
    session_file_path(username).unlink(missing_ok=True)
    (SESSION_DIR / f"{username}.policy.conf").unlink(missing_ok=True)
    (SESSION_DIR / f"{username}.online.conf").unlink(missing_ok=True)
    (SESSION_DIR / f"{username}.monitor.conf").unlink(missing_ok=True)
    (SESSION_DIR / f"{username}.limits.intent").unlink(missing_ok=True)
    (SESSION_DIR / f"{username}.report.json").unlink(missing_ok=True)

    return True, f"Stopped/cleaned session artifacts for {username}."


def extend_session_duration(username: str, extra_minutes: int) -> tuple[bool, str]:
    if not is_valid_session_user(username):
        return False, "Invalid username."
    if extra_minutes <= 0:
        return False, "Extra minutes must be greater than 0."
    if not session_exists(username):
        return False, "Session not found."

    path = session_file_path(username)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False, "Could not read session file."

    added_seconds = extra_minutes * 60
    found = False
    updated = []

    for line in lines:
        if line.startswith("duration="):
            try:
                cur = int(line.split("=", 1)[1])
            except ValueError:
                cur = 7200
            updated.append(f"duration={cur + added_seconds}")
            found = True
        else:
            updated.append(line)

    if not found:
        updated.append(f"duration={7200 + added_seconds}")

    try:
        path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    except OSError:
        return False, "Could not update session duration."

    return True, f"Extended {username} by {extra_minutes} minute(s)."


def get_sessions() -> list[dict]:
    sessions = []
    if not SESSION_DIR.exists():
        return sessions

    for entry in sorted(SESSION_DIR.iterdir()):
        if is_session_record(entry):
            sessions.append(parse_session_file(entry))

    return sessions


def read_session_config_bundle(username: str) -> tuple[bool, str, str]:
    if not is_valid_session_user(username):
        return False, "Invalid username.", ""

    policy = SESSION_DIR / f"{username}.policy.conf"
    online = SESSION_DIR / f"{username}.online.conf"
    monitor = SESSION_DIR / f"{username}.monitor.conf"
    limits_intent = SESSION_DIR / f"{username}.limits.intent"

    if not policy.exists() and not online.exists() and not monitor.exists() and not limits_intent.exists():
        return False, "No config snapshot found for this session.", ""

    chunks = []
    for path in [policy, online, monitor, limits_intent]:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = "<Failed to read file>"
        chunks.append(f"# {path.name}\n{text.rstrip()}\n")

    return True, "Config snapshot loaded.", "\n".join(chunks).strip() + "\n"


def tail_log_lines(limit: int = 80) -> list[str]:
    if not LOG_FILE.exists():
        return []

    try:
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        return [line.rstrip("\n") for line in lines[-limit:]]
    except OSError:
        return []


def get_session_report(username: str) -> tuple[bool, str, str]:
    if not is_valid_session_user(username):
        return False, "Invalid username.", ""

    report = SESSION_DIR / f"{username}.report.json"
    if not report.exists():
        return False, "No report found for this session.", ""

    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, "Could not read report file.", ""

    return True, "Report loaded.", text


def run_vanish(args: list[str]) -> tuple[int, str, str]:
    if not VANISH_BIN.exists():
        return 1, "", f"Binary not found: {VANISH_BIN}"

    cmd = [str(VANISH_BIN)] + args
    completed = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def as_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def normalize_domain_token(value: str) -> str:
    token = (value or "").strip().lower()
    if token.startswith("http://"):
        token = token[len("http://") :]
    if token.startswith("https://"):
        token = token[len("https://") :]
    token = token.split("/", 1)[0]
    token = token.split(":", 1)[0]
    token = token.rstrip(".")
    if token.startswith("www."):
        token = token[4:]
    return token.strip()


def normalize_domain_csv(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    normalized = raw.replace("\n", ",")
    out = []
    seen = set()
    for piece in normalized.split(","):
        domain = normalize_domain_token(piece)
        if not domain:
            continue
        if domain in seen:
            continue
        seen.add(domain)
        out.append(domain)
    return ",".join(out)


def extract_username_from_start_output(output: str) -> str:
    match = re.search(r"Username:\s+([A-Za-z0-9_-]+)", output or "")
    return match.group(1) if match else ""


def rollback_start_failure(username: str) -> None:
    if not is_valid_session_user(username):
        return
    subprocess.run(["pkill", "-9", "-u", username], capture_output=True, text=True)
    subprocess.run(["loginctl", "terminate-user", username], capture_output=True, text=True)
    subprocess.run(["umount", "-l", f"/home/{username}/submit"], capture_output=True, text=True)
    subprocess.run(["userdel", "-f", "-r", username], capture_output=True, text=True)
    for suffix in ["", ".policy.conf", ".online.conf", ".monitor.conf", ".limits.intent", ".report.json"]:
        (SESSION_DIR / f"{username}{suffix}").unlink(missing_ok=True)


def load_presets() -> dict:
    if not PRESETS_FILE.exists():
        return {}
    try:
        data = json.loads(PRESETS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_presets(presets: dict) -> bool:
    try:
        PRESETS_FILE.write_text(json.dumps(presets, indent=2), encoding="utf-8")
        return True
    except OSError:
        return False


# ===========================================================================
# Cloud Sync Helpers (MongoDB Atlas GridFS)
# ===========================================================================

# Paths that map to a friendly application label.
_KNOWN_PATHS: list[tuple[str, str]] = [
    (".mozilla/firefox",                  "Firefox Profile"),
    (".var/app/org.mozilla.firefox",      "Firefox Flatpak Data"),
    ("snap/firefox/common/.mozilla",      "Firefox Snap Profile"),
    (".mozilla",                          "Mozilla Profile Data"),
    (".config/google-chrome",             "Google Chrome Profile"),
    (".config/chromium",                  "Chromium Profile"),
    (".config/BraveSoftware",             "Brave Browser Profile"),
    (".config/Code",                      "VS Code Settings"),
    (".vscode-server",                    "VS Code Server"),
    (".config/Cursor",                    "Cursor IDE Settings"),
    (".vim",                              "Vim Config Directory"),
    (".vimrc",                            "Vim Config File"),
    (".config/nvim",                      "Neovim Config"),
    (".ssh",                              "SSH Keys & Config"),
    (".gitconfig",                        "Git Config"),
    (".gitignore_global",                 "Git Global Ignore"),
    (".local/share/Steam",                "Steam Game Data"),
    (".steam",                            "Steam Directory"),
    (".wine",                             "Wine Prefix"),
    (".bashrc",                           "Bash Config"),
    (".bash_profile",                     "Bash Profile"),
    (".bash_aliases",                     "Bash Aliases"),
    (".zshrc",                            "Zsh Config"),
    (".zsh_history",                      "Zsh History"),
    (".oh-my-zsh",                        "Oh My Zsh"),
    (".profile",                          "Shell Profile"),
    (".config/htop",                      "htop Config"),
    (".config/gtk-3.0",                   "GTK3 Theme"),
    (".themes",                           "Desktop Themes"),
    (".icons",                            "Desktop Icons"),
    (".local/share/recently-used.xbel",   "Recent Files List"),
    (".config/pulse",                     "PulseAudio Config"),
]

# Paths to skip entirely regardless of mode.
_SKIP_PREFIXES: tuple[str, ...] = (
    ".cache",
    ".local/share/Trash",
    ".local/share/flatpak",
    ".gvfs",
    ".dbus",
    ".Xauthority",
)

# Async cloud upload jobs: {job_id -> status dict}
_CLOUD_UPLOAD_JOBS: dict[str, dict] = {}
_CLOUD_UPLOAD_LOCK = threading.Lock()
_CLOUD_UPLOAD_JOB_TTL_SECONDS = 60 * 60


def _dir_size_mb(path: Path) -> float:
    """Return total size of a path in megabytes (best-effort)."""
    try:
        if path.is_file():
            return round(path.stat().st_size / (1024 * 1024), 2)
        total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        return round(total / (1024 * 1024), 2)
    except OSError:
        return 0.0


def scan_home_dir(username: str) -> list[dict]:
    """Scan /home/<username> and return labelled entries."""
    home = Path("/home") / username
    if not home.is_dir():
        return []

    results: list[dict] = []
    seen_rel_paths: set[str] = set()

    def is_skipped(rel_path: str) -> bool:
        return any(
            rel_path == prefix or rel_path.startswith(prefix + "/")
            for prefix in _SKIP_PREFIXES
        )

    def append_entry(rel_path: str, label: str, is_known: bool, source_path: Path) -> None:
        if rel_path in seen_rel_paths or is_skipped(rel_path):
            return
        seen_rel_paths.add(rel_path)
        results.append({
            "rel_path": rel_path,
            "label": label,
            "size_mb": _dir_size_mb(source_path),
            "is_known": is_known,
        })

    # First pass: known labelled paths.
    for rel, label in _KNOWN_PATHS:
        candidate = home / rel
        if candidate.exists():
            append_entry(rel, label, True, candidate)

    # Second pass: unknown items in common app-data roots.
    for scan_base_rel, scan_label in [
        (".config", "Generic App Config"),
        (".local/share", "Generic App Data"),
        (".var/app", "Generic Flatpak App Data"),
        ("snap", "Generic Snap App Data"),
    ]:
        scan_base = home / scan_base_rel
        if not scan_base.is_dir():
            continue
        try:
            for child in sorted(scan_base.iterdir()):
                child_rel = f"{scan_base_rel}/{child.name}"
                # Skip if the whole known-path list already covers it.
                already = any(
                    child_rel == r or child_rel.startswith(r + "/")
                    for r, _ in _KNOWN_PATHS
                )
                if already:
                    continue
                append_entry(child_rel, f"{scan_label}: {child.name}", False, child)
        except OSError:
            pass

    # Third pass: hidden top-level entries (dotfiles/directories) and snap.
    try:
        for child in sorted(home.iterdir()):
            rel = child.name
            if rel in {"snap"}:
                pass
            elif not rel.startswith("."):
                continue
            already = any(rel == r or rel.startswith(r + "/") for r, _ in _KNOWN_PATHS)
            if already:
                continue
            append_entry(rel, f"Generic Home Config: {rel}", False, child)
    except OSError:
        pass

    # Sort: known first, then alpha.
    results.sort(key=lambda x: (not x["is_known"], x["rel_path"]))
    return results


def _cleanup_cloud_upload_jobs() -> None:
    now = now_ts()
    stale_ids: list[str] = []
    with _CLOUD_UPLOAD_LOCK:
        for job_id, data in _CLOUD_UPLOAD_JOBS.items():
            updated = int(data.get("updated_at", now))
            if now - updated > _CLOUD_UPLOAD_JOB_TTL_SECONDS:
                stale_ids.append(job_id)
        for job_id in stale_ids:
            _CLOUD_UPLOAD_JOBS.pop(job_id, None)


def _set_cloud_upload_job(job_id: str, **fields) -> None:
    _cleanup_cloud_upload_jobs()
    with _CLOUD_UPLOAD_LOCK:
        current = _CLOUD_UPLOAD_JOBS.get(job_id, {})
        current.update(fields)
        current["updated_at"] = now_ts()
        _CLOUD_UPLOAD_JOBS[job_id] = current


def _get_cloud_upload_job(job_id: str) -> dict | None:
    _cleanup_cloud_upload_jobs()
    with _CLOUD_UPLOAD_LOCK:
        data = _CLOUD_UPLOAD_JOBS.get(job_id)
        return dict(data) if data else None


def _atlas_client_ok() -> tuple[bool, str]:
    """Return (True, '') if Atlas is usable, else (False, error_message)."""
    atlas_uri, atlas_source = _get_atlas_uri_and_source()
    if not _PYMONGO_AVAILABLE:
        msg = "pymongo is not installed. Run: pip install pymongo"
        print(f"[Atlas Error] {msg}", file=sys.stderr)
        return False, msg
    if not atlas_uri:
        msg = "VANISH_ATLAS_URI is not set (neither environment nor .env file)."
        print(f"[Atlas Error] {msg}", file=sys.stderr)
        return False, msg
    if not atlas_uri.startswith("mongodb://") and not atlas_uri.startswith("mongodb+srv://"):
        msg = "VANISH_ATLAS_URI must start with mongodb:// or mongodb+srv://"
        print(f"[Atlas Error] {msg}", file=sys.stderr)
        return False, msg
    client = None
    try:
        client = MongoClient(atlas_uri, serverSelectionTimeoutMS=8000, connectTimeoutMS=8000)
        client.admin.command("ping")
    except Exception as exc:
        if "dnspython" in str(exc).lower():
            msg = (
                "MongoDB Atlas connection failed: dnspython is required for mongodb+srv:// URIs. "
                "Install with: pip install dnspython (or pip install 'pymongo[srv]')."
            )
            print(f"[Atlas Error] {msg}", file=sys.stderr)
            return False, msg
        source_msg = f", source={atlas_source}" if atlas_source else ""
        msg = f"MongoDB Atlas connection failed ({type(exc).__name__}{source_msg}): {exc}"
        print(f"[Atlas Error] {msg}", file=sys.stderr)
        return False, msg
    finally:
        if client is not None:
            client.close()
    return True, ""


def _cloudinary_config_ok(log_error: bool = False) -> tuple[bool, str, dict]:
    cfg = _get_cloudinary_config()
    missing = []
    if not cfg["cloud_name"]:
        missing.append("VANISH_CLOUDINARY_CLOUD_NAME")
    if not cfg["api_key"]:
        missing.append("VANISH_CLOUDINARY_API_KEY")
    if not cfg["api_secret"]:
        missing.append("VANISH_CLOUDINARY_API_SECRET")
    if missing:
        msg = (
            "Cloudinary is not configured. Set: "
            + ", ".join(missing)
            + ". Backups store file URLs in MongoDB metadata."
        )
        if log_error:
            print(f"[Cloudinary Error] {msg}", file=sys.stderr)
        return False, msg, cfg
    return True, "", cfg


def _supabase_config_ok(log_error: bool = False, verify_bucket: bool = False) -> tuple[bool, str, dict]:
    cfg = _get_supabase_config()
    missing = []
    if not cfg["url"]:
        missing.append("VANISH_SUPABASE_URL")
    if not cfg["service_key"]:
        missing.append("VANISH_SUPABASE_SERVICE_ROLE_KEY")
    if not cfg["bucket"]:
        missing.append("VANISH_SUPABASE_BUCKET")
    if missing:
        msg = (
            "Supabase storage is not configured. Set: "
            + ", ".join(missing)
            + ". Backups store file metadata in MongoDB Atlas."
        )
        if log_error:
            print(f"[Supabase Error] {msg}", file=sys.stderr)
        return False, msg, cfg
    if not cfg["url"].startswith("http://") and not cfg["url"].startswith("https://"):
        msg = "VANISH_SUPABASE_URL must start with http:// or https://"
        if log_error:
            print(f"[Supabase Error] {msg}", file=sys.stderr)
        return False, msg, cfg

    if not verify_bucket:
        return True, "", cfg

    bucket_ref = urllib.parse.quote(cfg["bucket"], safe="")
    endpoint = f"{cfg['url']}/storage/v1/bucket/{bucket_ref}"
    req = urllib.request.Request(
        endpoint,
        method="GET",
        headers={
            "Authorization": f"Bearer {cfg['service_key']}",
            "apikey": cfg["service_key"],
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=_build_ssl_context()) as resp:
            _ = resp.read()
        return True, "", cfg
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        detail = raw
        try:
            parsed = json.loads(raw)
            detail = parsed.get("message", raw) or raw
        except Exception:
            pass
        msg = f"Supabase bucket check failed (HTTP {exc.code}): {detail}"
        if log_error:
            print(f"[Supabase Error] {msg}", file=sys.stderr)
        return False, msg, cfg
    except Exception as exc:
        msg = f"Supabase bucket check failed: {exc}"
        if log_error:
            print(f"[Supabase Error] {msg}", file=sys.stderr)
        return False, msg, cfg


def _get_db():
    atlas_uri, _ = _get_atlas_uri_and_source()
    client = MongoClient(atlas_uri, serverSelectionTimeoutMS=8000)
    return client[ATLAS_DB_NAME]


def _get_fs():
    """Return a legacy GridFS instance for backward compatibility."""
    if not _GRIDFS_AVAILABLE:
        raise RuntimeError("gridfs module not available")
    db = _get_db()
    return gridfs.GridFS(db), db


def _get_users_col():
    """Return the users collection. Caller must confirm Atlas is configured."""
    db = _get_db()
    db["users"].create_index("username", unique=True)
    return db["users"]


def _get_backups_col():
    """Return the cloud backup metadata collection."""
    db = _get_db()
    col = db["cloud_backups"]
    col.create_index([("owner", 1), ("timestamp", -1)])
    return col


def _build_owner_query(owner: str) -> dict:
    """
    Build a backward-compatible owner filter.
    New records use 'owner'; older records may only have 'username'.
    """
    if not owner:
        return {}
    return {
        "$or": [
            {"owner": owner},
            {"owner": {"$exists": False}, "username": owner},
        ]
    }


def _get_cloudinary_chunk_bytes() -> tuple[int, int]:
    """
    Return (chunk_bytes, chunk_mb) for multipart Cloudinary uploads.
    Config key: VANISH_CLOUDINARY_CHUNK_MB (default 20, clamped 5..95).
    """
    raw, _ = _get_env_var_and_source("VANISH_CLOUDINARY_CHUNK_MB")
    chunk_mb = 20
    if raw:
        try:
            chunk_mb = int(raw)
        except ValueError:
            chunk_mb = 20
    chunk_mb = max(5, min(95, chunk_mb))
    return chunk_mb * 1024 * 1024, chunk_mb


def _get_storage_chunk_bytes() -> tuple[int, int]:
    """
    Return (chunk_bytes, chunk_mb) for large archive uploads.
    Config key precedence:
      1) VANISH_STORAGE_CHUNK_MB
      2) VANISH_SUPABASE_CHUNK_MB
      3) VANISH_CLOUDINARY_CHUNK_MB (legacy)
    Default: 20 MB, clamped 5..95.
    """
    raw, _ = _get_env_var_and_source("VANISH_STORAGE_CHUNK_MB")
    if not raw:
        raw, _ = _get_env_var_and_source("VANISH_SUPABASE_CHUNK_MB")
    if not raw:
        raw, _ = _get_env_var_and_source("VANISH_CLOUDINARY_CHUNK_MB")
    chunk_mb = 20
    if raw:
        try:
            chunk_mb = int(raw)
        except ValueError:
            chunk_mb = 20
    chunk_mb = max(5, min(95, chunk_mb))
    return chunk_mb * 1024 * 1024, chunk_mb


def _sanitize_cloudinary_component(text: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip())
    return sanitized.strip("-") or "config"


def _build_multipart_form(fields: dict[str, str], file_field: str, filename: str, file_bytes: bytes, mime_type: str) -> tuple[str, bytes]:
    boundary = f"----VanishBoundary{secrets.token_hex(16)}"
    body = bytearray()
    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        (
            f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode("utf-8")
    )
    body.extend(file_bytes)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return f"multipart/form-data; boundary={boundary}", bytes(body)


def _cloudinary_sign_params(params: dict[str, str], api_secret: str) -> str:
    base = "&".join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.sha1(f"{base}{api_secret}".encode("utf-8")).hexdigest()


def _extract_public_id_from_cloudinary_url(url: str) -> str:
    """
    Best-effort extraction of Cloudinary raw public_id from a delivery URL.
    Handles .../raw/upload/v<version>/<public_id>[.<ext>].
    """
    try:
        parsed = urlparse(url or "")
        path = parsed.path or ""
        marker = "/raw/upload/"
        idx = path.find(marker)
        if idx < 0:
            return ""
        tail = path[idx + len(marker):].lstrip("/")
        parts = tail.split("/")
        if parts and re.fullmatch(r"v\d+", parts[0]):
            parts = parts[1:]
        if not parts:
            return ""
        public_id = "/".join(parts)
        # Remove extension from final segment if present.
        if "." in parts[-1]:
            last = parts[-1].rsplit(".", 1)[0]
            public_id = "/".join(parts[:-1] + [last])
        return public_id.strip("/")
    except Exception:
        return ""


def _cloudinary_make_public(public_id: str) -> tuple[bool, str]:
    """Attempt to switch a raw asset to public delivery mode."""
    ok, msg, cfg = _cloudinary_config_ok(log_error=True)
    if not ok:
        return False, msg
    if not public_id:
        return False, "Cloudinary public_id missing for access-mode recovery."

    ts = str(now_ts())
    sign_params = {
        "access_mode": "public",
        "public_id": public_id,
        "timestamp": ts,
        "type": "upload",
    }
    signature = _cloudinary_sign_params(sign_params, cfg["api_secret"])
    post_data = {
        **sign_params,
        "api_key": cfg["api_key"],
        "signature": signature,
    }
    body = urllib.parse.urlencode(post_data).encode("utf-8")
    endpoint = f"https://api.cloudinary.com/v1_1/{cfg['cloud_name']}/raw/explicit"
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60, context=_build_ssl_context()) as resp:
            _ = resp.read()
        return True, ""
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return False, f"Cloudinary explicit failed (HTTP {exc.code}): {raw}"
    except Exception as exc:
        return False, f"Cloudinary explicit failed: {exc}"


def _build_ssl_context() -> ssl.SSLContext:
    """Create TLS context for Cloudinary requests."""
    ctx = ssl.create_default_context()
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx


def _is_transient_network_error(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = [
        "eof occurred in violation of protocol",
        "unexpected eof",
        "connection reset",
        "timed out",
        "ssl",
        "tls",
        "temporarily unavailable",
    ]
    return any(marker in text for marker in markers)


def _sanitize_storage_component(text: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip())
    return sanitized.strip("-") or "config"


def _is_cloudinary_size_limit_error(message: str) -> bool:
    text = (message or "").lower()
    markers = [
        "file size too large",
        "max file size",
        "maximum file size",
        "request entity too large",
        "payload too large",
        "100 mb",
        "100mb",
        "104857600",
    ]
    return any(marker in text for marker in markers)


def _is_storage_size_limit_error(message: str) -> bool:
    text = (message or "").lower()
    markers = [
        "file too large",
        "entity too large",
        "payload too large",
        "request too large",
        "maximum size",
        "max size",
        "exceeds",
    ]
    return any(marker in text for marker in markers) or _is_cloudinary_size_limit_error(message)


def _extract_supabase_error_detail(raw: str) -> str:
    detail = raw
    try:
        parsed = json.loads(raw)
        detail = (
            parsed.get("message")
            or parsed.get("error_description")
            or parsed.get("error")
            or raw
        )
    except Exception:
        pass
    return str(detail)


def _upload_archive_to_supabase(
    archive_bytes: bytes,
    filename: str,
    owner: str,
    config_name: str,
    part_index: int | None = None,
    total_parts: int | None = None,
) -> tuple[bool, str, dict]:
    ok, msg, cfg = _supabase_config_ok(log_error=True, verify_bucket=False)
    if not ok:
        return False, msg, {}

    ts = str(now_ts())
    owner_part = _sanitize_storage_component(owner or "owner")
    config_part = _sanitize_storage_component(config_name)
    file_part = _sanitize_storage_component(filename or "backup.tar.gz")
    if part_index is not None and total_parts is not None:
        file_part = f"{config_part}-part-{part_index:04d}-of-{total_parts:04d}.bin"
    token = secrets.token_hex(6)
    object_path = f"{cfg['prefix']}/{owner_part}/{config_part}/{ts}-{token}-{file_part}".strip("/")

    bucket_ref = urllib.parse.quote(cfg["bucket"], safe="")
    object_ref = urllib.parse.quote(object_path, safe="/")
    endpoint = f"{cfg['url']}/storage/v1/object/{bucket_ref}/{object_ref}"

    headers = {
        "Authorization": f"Bearer {cfg['service_key']}",
        "apikey": cfg["service_key"],
        "Content-Type": "application/octet-stream",
        "x-upsert": "false",
    }
    max_attempts = 4
    for attempt in range(1, max_attempts + 1):
        try:
            req = urllib.request.Request(endpoint, data=archive_bytes, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=180, context=_build_ssl_context()) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            if raw:
                try:
                    _ = json.loads(raw)
                except Exception:
                    pass
            return True, "", {
                "object_path": object_path,
                "bytes": len(archive_bytes),
                "storage_bucket": cfg["bucket"],
                "resource_type": "raw",
            }
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            detail = _extract_supabase_error_detail(raw)
            if 500 <= exc.code < 600 and attempt < max_attempts:
                wait_s = attempt
                print(
                    f"[Supabase Warning] HTTP {exc.code} on attempt {attempt}/{max_attempts}; retrying in {wait_s}s",
                    file=sys.stderr,
                )
                time.sleep(wait_s)
                continue
            return False, f"Supabase upload failed (HTTP {exc.code}): {detail}", {}
        except Exception as exc:
            if _is_transient_network_error(exc) and attempt < max_attempts:
                wait_s = attempt
                print(
                    f"[Supabase Warning] transient upload error on attempt {attempt}/{max_attempts}: {exc}; retrying in {wait_s}s",
                    file=sys.stderr,
                )
                time.sleep(wait_s)
                continue
            if _is_transient_network_error(exc):
                return False, (
                    "Supabase upload failed after retries due to SSL/network instability. "
                    f"Last error: {exc}"
                ), {}
            return False, f"Supabase upload failed: {exc}", {}
    return False, "Supabase upload failed after retries with no response.", {}


def _download_supabase_object_to_temp(object_path: str) -> tuple[bool, str, str]:
    object_path = (object_path or "").strip()
    if not object_path:
        return False, "Supabase object path is empty.", ""

    ok, msg, cfg = _supabase_config_ok(log_error=True, verify_bucket=False)
    if not ok:
        return False, msg, ""

    bucket_ref = urllib.parse.quote(cfg["bucket"], safe="")
    object_ref = urllib.parse.quote(object_path, safe="/")
    endpoint = f"{cfg['url']}/storage/v1/object/{bucket_ref}/{object_ref}"
    req = urllib.request.Request(
        endpoint,
        method="GET",
        headers={
            "Authorization": f"Bearer {cfg['service_key']}",
            "apikey": cfg["service_key"],
        },
    )
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="vanish_supabase_", suffix=".tar.gz")
        with os.fdopen(fd, "wb") as dst:
            with urllib.request.urlopen(req, timeout=240, context=_build_ssl_context()) as src:
                shutil.copyfileobj(src, dst)
        return True, "Downloaded archive from Supabase.", tmp_path
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        detail = _extract_supabase_error_detail(raw)
        return False, f"Supabase download failed (HTTP {exc.code}): {detail}", ""
    except Exception as exc:
        return False, f"Supabase download failed: {exc}", ""


def _is_supabase_not_found_error(message: str) -> bool:
    text = (message or "").lower()
    markers = [
        "not found",
        "no such object",
        "object not found",
        "does not exist",
    ]
    return any(marker in text for marker in markers)


def _delete_supabase_object(object_path: str) -> tuple[bool, str]:
    object_path = (object_path or "").strip()
    if not object_path:
        return True, ""

    ok, msg, cfg = _supabase_config_ok(log_error=True, verify_bucket=False)
    if not ok:
        return False, msg

    bucket_ref = urllib.parse.quote(cfg["bucket"], safe="")
    object_ref = urllib.parse.quote(object_path, safe="/")
    endpoint = f"{cfg['url']}/storage/v1/object/{bucket_ref}/{object_ref}"
    req = urllib.request.Request(
        endpoint,
        method="DELETE",
        headers={
            "Authorization": f"Bearer {cfg['service_key']}",
            "apikey": cfg["service_key"],
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90, context=_build_ssl_context()) as resp:
            _ = resp.read()
        return True, ""
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        detail = _extract_supabase_error_detail(raw)
        if _is_supabase_not_found_error(detail):
            return True, ""
        return False, f"Supabase delete failed (HTTP {exc.code}) for '{object_path}': {detail}"
    except Exception as exc:
        if _is_supabase_not_found_error(str(exc)):
            return True, ""
        return False, f"Supabase delete failed for '{object_path}': {exc}"


def _upload_archive_to_cloudinary(
    archive_bytes: bytes,
    filename: str,
    owner: str,
    config_name: str,
    part_index: int | None = None,
    total_parts: int | None = None,
) -> tuple[bool, str, dict]:
    ok, msg, cfg = _cloudinary_config_ok(log_error=True)
    if not ok:
        return False, msg, {}

    ts = str(now_ts())
    owner_part = _sanitize_cloudinary_component(owner or "owner")
    config_part = _sanitize_cloudinary_component(config_name)
    if part_index is not None and total_parts is not None:
        config_part = f"{config_part}-part-{part_index:04d}-of-{total_parts:04d}"
    public_id = f"{cfg['folder'].strip('/')}/{owner_part}/{config_part}-{ts}-{secrets.token_hex(4)}"
    sign_params = {
        "access_mode": "public",
        "folder": cfg["folder"],
        "public_id": public_id,
        "timestamp": ts,
        "type": "upload",
    }
    signature = _cloudinary_sign_params(sign_params, cfg["api_secret"])
    fields = {
        "api_key": cfg["api_key"],
        "timestamp": ts,
        "folder": cfg["folder"],
        "public_id": public_id,
        "type": "upload",
        "access_mode": "public",
        "signature": signature,
    }
    content_type, payload = _build_multipart_form(
        fields=fields,
        file_field="file",
        filename=filename,
        file_bytes=archive_bytes,
        mime_type="application/gzip",
    )
    upload_url = f"https://api.cloudinary.com/v1_1/{cfg['cloud_name']}/raw/upload"
    ssl_ctx = _build_ssl_context()
    max_attempts = 4
    data = {}

    for attempt in range(1, max_attempts + 1):
        try:
            req = urllib.request.Request(
                upload_url,
                data=payload,
                method="POST",
                headers={"Content-Type": content_type, "Content-Length": str(len(payload))},
            )
            with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            break
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            detail = raw
            try:
                parsed = json.loads(raw)
                detail = parsed.get("error", {}).get("message", raw)
            except Exception:
                pass
            detail_lower = detail.lower()
            if "cloud" in detail_lower and "not found" in detail_lower:
                hint = (
                    "Cloudinary cloud not found. Verify VANISH_CLOUDINARY_CLOUD_NAME is exactly the "
                    "Cloud Name from Dashboard -> Product Environment Credentials, and ensure API key/secret "
                    "are from that same environment."
                )
                return False, f"{hint} Provider message: {detail}", {}
            if 500 <= exc.code < 600 and attempt < max_attempts:
                wait_s = attempt
                print(
                    f"[Cloudinary Warning] HTTP {exc.code} on attempt {attempt}/{max_attempts}; retrying in {wait_s}s",
                    file=sys.stderr,
                )
                time.sleep(wait_s)
                continue
            return False, f"Cloudinary upload failed (HTTP {exc.code}): {detail}", {}
        except Exception as exc:
            if _is_transient_network_error(exc) and attempt < max_attempts:
                wait_s = attempt
                print(
                    f"[Cloudinary Warning] transient upload error on attempt {attempt}/{max_attempts}: {exc}; retrying in {wait_s}s",
                    file=sys.stderr,
                )
                time.sleep(wait_s)
                continue
            if _is_transient_network_error(exc):
                return False, (
                    "Cloudinary upload failed after retries due to SSL/network instability. "
                    f"Last error: {exc}"
                ), {}
            return False, f"Cloudinary upload failed: {exc}", {}
    else:
        return False, "Cloudinary upload failed after retries with no response.", {}

    secure_url = data.get("secure_url", "")
    if not secure_url:
        return False, "Cloudinary upload returned no secure_url.", {}

    return True, "", {
        "secure_url": secure_url,
        "public_id": data.get("public_id", public_id),
        "bytes": int(data.get("bytes", len(archive_bytes))),
        "resource_type": data.get("resource_type", "raw"),
    }


def _download_url_to_temp(url: str, public_id: str = "") -> tuple[bool, str, str]:
    if not url:
        return False, "Archive URL is empty.", ""
    effective_public_id = public_id or _extract_public_id_from_cloudinary_url(url)
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="vanish_cloud_", suffix=".tar.gz")
        with os.fdopen(fd, "wb") as dst:
            try:
                with urllib.request.urlopen(url, timeout=180, context=_build_ssl_context()) as src:
                    shutil.copyfileobj(src, dst)
            except urllib.error.HTTPError as http_exc:
                if http_exc.code == 401 and effective_public_id:
                    ok_pub, pub_msg = _cloudinary_make_public(effective_public_id)
                    if ok_pub:
                        dst.seek(0)
                        dst.truncate(0)
                        with urllib.request.urlopen(url, timeout=180, context=_build_ssl_context()) as src:
                            shutil.copyfileobj(src, dst)
                    else:
                        Path(tmp_path).unlink(missing_ok=True)
                        return False, (
                            "Cloudinary returned 401 Unauthorized and automatic access-mode recovery failed. "
                            f"{pub_msg}"
                        ), ""
                else:
                    raise
        return True, "Downloaded archive from Cloudinary.", tmp_path
    except Exception as exc:
        return False, f"Cloudinary download failed: {exc}", ""


def _is_cloudinary_not_found_error(message: str) -> bool:
    text = (message or "").lower()
    markers = [
        "not found",
        "resource not found",
        "unknown public_id",
        "can't find",
    ]
    return any(marker in text for marker in markers)


def _cloudinary_delete_public_id(public_id: str) -> tuple[bool, str]:
    """Delete a raw asset by public_id. 'Not found' is treated as success."""
    public_id = (public_id or "").strip()
    if not public_id:
        return True, ""

    ok, msg, cfg = _cloudinary_config_ok(log_error=True)
    if not ok:
        return False, msg

    ts = str(now_ts())
    sign_params = {
        "invalidate": "true",
        "public_id": public_id,
        "timestamp": ts,
        "type": "upload",
    }
    signature = _cloudinary_sign_params(sign_params, cfg["api_secret"])
    post_data = {
        **sign_params,
        "api_key": cfg["api_key"],
        "signature": signature,
    }
    body = urllib.parse.urlencode(post_data).encode("utf-8")
    endpoint = f"https://api.cloudinary.com/v1_1/{cfg['cloud_name']}/raw/destroy"
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90, context=_build_ssl_context()) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw) if raw else {}
        result = str(data.get("result", "")).strip().lower()
        if result in {"ok", "not found"}:
            return True, ""
        if result:
            if _is_cloudinary_not_found_error(result):
                return True, ""
            return False, f"Cloudinary destroy returned '{result}' for public_id '{public_id}'."
        return True, ""
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        detail = raw
        try:
            parsed = json.loads(raw)
            detail = parsed.get("error", {}).get("message", raw)
        except Exception:
            pass
        if _is_cloudinary_not_found_error(detail):
            return True, ""
        return False, f"Cloudinary destroy failed (HTTP {exc.code}) for '{public_id}': {detail}"
    except Exception as exc:
        if _is_cloudinary_not_found_error(str(exc)):
            return True, ""
        return False, f"Cloudinary destroy failed for '{public_id}': {exc}"


def _doc_belongs_to_owner(doc: dict, owner: str) -> bool:
    if not owner:
        return False
    doc_owner = str(doc.get("owner", "")).strip()
    if doc_owner:
        return doc_owner == owner
    return str(doc.get("username", "")).strip() == owner


def _collect_cloudinary_public_ids(doc: dict) -> tuple[list[str], int]:
    """
    Return (public_ids, unresolved_assets_count) for a backup metadata document.
    unresolved_assets_count > 0 means we could not identify Cloudinary public_id(s).
    """
    ids: list[str] = []
    unresolved = 0

    def add_candidate(public_id: str, url: str) -> None:
        nonlocal unresolved
        pid = (public_id or "").strip()
        if not pid and url:
            pid = _extract_public_id_from_cloudinary_url(url)
        if pid:
            ids.append(pid)
        elif url:
            unresolved += 1

    parts = doc.get("archive_parts", [])
    if isinstance(parts, list) and parts:
        for part in parts:
            if not isinstance(part, dict):
                unresolved += 1
                continue
            part_public_id = str(part.get("archive_public_id", "")).strip()
            part_url = str(part.get("archive_url", "")).strip()
            if not part_public_id and not part_url:
                unresolved += 1
                continue
            add_candidate(public_id=part_public_id, url=part_url)
    else:
        doc_public_id = str(doc.get("archive_public_id", "")).strip()
        doc_url = str(doc.get("archive_url", "")).strip()
        if doc_public_id or doc_url:
            add_candidate(public_id=doc_public_id, url=doc_url)
        elif str(doc.get("storage_backend", "")).strip().lower() == "cloudinary":
            unresolved += 1

    # Stable-order de-duplication.
    deduped = list(dict.fromkeys([p for p in ids if p]))
    return deduped, unresolved


def _collect_supabase_object_paths(doc: dict) -> tuple[list[str], int]:
    """
    Return (object_paths, unresolved_assets_count) for a Supabase-backed backup doc.
    """
    paths: list[str] = []
    unresolved = 0

    def add_path(path: str) -> None:
        nonlocal unresolved
        p = (path or "").strip().strip("/")
        if p:
            paths.append(p)
        else:
            unresolved += 1

    parts = doc.get("archive_parts", [])
    if isinstance(parts, list) and parts:
        for part in parts:
            if not isinstance(part, dict):
                unresolved += 1
                continue
            part_path = str(
                part.get("archive_object_path")
                or part.get("object_path")
                or ""
            ).strip()
            add_path(part_path)
    else:
        doc_path = str(
            doc.get("archive_object_path")
            or doc.get("object_path")
            or ""
        ).strip()
        if doc_path:
            add_path(doc_path)
        elif str(doc.get("storage_backend", "")).strip().lower() == "supabase":
            unresolved += 1

    deduped = list(dict.fromkeys([p for p in paths if p]))
    return deduped, unresolved


def delete_from_atlas(config_id: str, owner: str) -> tuple[bool, str]:
    """
    Delete one cloud backup:
    1) delete storage file(s) (Supabase or legacy Cloudinary)
    2) delete MongoDB metadata document
    Fallback: delete legacy GridFS object if present.
    """
    ok, err = _atlas_client_ok()
    if not ok:
        return False, err
    if not owner:
        return False, "Not logged in. Please log in first."

    try:
        obj_id = ObjectId(config_id)
    except Exception:
        return False, "Invalid config_id format."

    try:
        col = _get_backups_col()
        doc = col.find_one({"_id": obj_id})
    except Exception as exc:
        return False, f"Atlas metadata fetch failed: {exc}"

    if doc:
        if not _doc_belongs_to_owner(doc, owner):
            return False, "You do not have permission to delete this config."

        storage_backend = str(doc.get("storage_backend", "")).strip().lower()
        parts = doc.get("archive_parts", [])
        has_supabase_paths = bool(doc.get("archive_object_path")) or any(
            isinstance(p, dict) and p.get("archive_object_path")
            for p in (parts if isinstance(parts, list) else [])
        )
        if storage_backend == "supabase" or has_supabase_paths:
            object_paths, unresolved = _collect_supabase_object_paths(doc)
            if unresolved > 0:
                return False, (
                    f"Cannot resolve Supabase object path for {unresolved} archive asset(s). "
                    "Deletion aborted to avoid orphaned storage files."
                )

            failed_storage_deletes: list[str] = []
            for object_path in object_paths:
                ok_del, msg_del = _delete_supabase_object(object_path)
                if not ok_del:
                    failed_storage_deletes.append(msg_del or f"Failed to delete '{object_path}'.")

            if failed_storage_deletes:
                return False, (
                    "Failed deleting one or more Supabase objects. Atlas metadata was kept unchanged. "
                    + " | ".join(failed_storage_deletes[:3])
                )

            removed_count = len(object_paths)
            removed_backend = "Supabase"
        else:
            public_ids, unresolved = _collect_cloudinary_public_ids(doc)
            if unresolved > 0:
                return False, (
                    f"Cannot resolve Cloudinary public_id for {unresolved} archive asset(s). "
                    "Deletion aborted to avoid orphaned cloud files."
                )

            failed_cloud_deletes: list[str] = []
            for pid in public_ids:
                ok_del, msg_del = _cloudinary_delete_public_id(pid)
                if not ok_del:
                    failed_cloud_deletes.append(msg_del or f"Failed to delete '{pid}'.")

            if failed_cloud_deletes:
                return False, (
                    "Failed deleting one or more Cloudinary files. Atlas metadata was kept unchanged. "
                    + " | ".join(failed_cloud_deletes[:3])
                )

            removed_count = len(public_ids)
            removed_backend = "Cloudinary"

        delete_result = col.delete_one({"_id": obj_id})
        if delete_result.deleted_count != 1:
            return False, "Failed deleting Atlas metadata."

        return True, (
            f"Deleted config '{config_id}' from Atlas and removed {removed_count} {removed_backend} file(s)."
        )

    # Legacy fallback for old GridFS-only records.
    if _GRIDFS_AVAILABLE:
        try:
            fs, db = _get_fs()
            grid_out = fs.get(obj_id)
            grid_owner = str(getattr(grid_out, "owner", "")).strip()
            grid_username = str(getattr(grid_out, "username", "")).strip()
            if grid_owner:
                if grid_owner != owner:
                    return False, "You do not have permission to delete this config."
            elif grid_username and grid_username != owner:
                return False, "You do not have permission to delete this config."
            fs.delete(obj_id)
            return True, f"Deleted legacy GridFS config '{config_id}' from Atlas."
        except Exception:
            pass

    return False, f"Config '{config_id}' not found."


# ===========================================================================
# Cloud User Auth (account system)
# Always stored in MongoDB; no auth if Atlas not configured.
# ===========================================================================

# In-memory session store: { token_str -> username }
_CLOUD_SESSIONS: dict[str, str] = {}


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def cloud_register(username: str, password: str) -> tuple[bool, str]:
    """Register a new account. Returns (ok, message)."""
    ok, err = _atlas_client_ok()
    if not ok:
        return False, err
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters."
    try:
        col = _get_users_col()
        col.insert_one({
            "username": username,
            "password_hash": _hash_password(password),
            "created_at": now_ts(),
        })
        return True, f"Account '{username}' created."
    except Exception as exc:
        if "duplicate key" in str(exc).lower() or "E11000" in str(exc):
            return False, f"Username '{username}' is already taken."
        print("[Atlas Error] cloud_register exception:", file=sys.stderr)
        traceback.print_exc()
        return False, f"Registration failed: {exc}"


def cloud_login(username: str, password: str) -> tuple[bool, str, str]:
    """Login and return (ok, message, token)."""
    ok, err = _atlas_client_ok()
    if not ok:
        return False, err, ""
    try:
        col = _get_users_col()
        user = col.find_one({"username": username})
        if not user or user["password_hash"] != _hash_password(password):
            return False, "Invalid username or password.", ""
        token = secrets.token_hex(32)
        _CLOUD_SESSIONS[token] = username
        return True, f"Logged in as '{username}'.", token
    except Exception as exc:
        print("[Atlas Error] cloud_login exception:", file=sys.stderr)
        traceback.print_exc()
        return False, f"Login failed: {exc}", ""


def cloud_logout(token: str) -> tuple[bool, str]:
    """Invalidate a session token."""
    removed = _CLOUD_SESSIONS.pop(token, None)
    if removed:
        return True, f"Logged out '{removed}'."
    return False, "Token not found."


def _resolve_token(handler) -> str | None:
    """Extract and validate the cloud session token from the request.
    Looks in the X-Cloud-Token header first, then falls back to the
    'token' field if the request body was already read (POST calls pass
    it explicitly).
    """
    return handler.headers.get("X-Cloud-Token", "").strip() or None


def upload_to_atlas(
    username: str,
    rel_paths: list[str],
    config_name: str,
    owner: str = "",
    progress_cb=None,
) -> tuple[bool, str, str]:
    """
    Package selected paths from /home/<username> into a .tar.gz and upload
    to Supabase Storage. Store metadata/object paths in MongoDB.
    Returns (ok, message, config_id_str). owner is the cloud account username.
    """
    def emit_progress(percent: int, stage: str) -> None:
        if progress_cb is None:
            return
        try:
            bounded = max(0, min(100, int(percent)))
            progress_cb(bounded, stage)
        except Exception:
            pass

    emit_progress(2, "Validating Atlas and Supabase configuration…")
    ok, err = _atlas_client_ok()
    if not ok:
        return False, err, ""
    ok_storage, err_storage, _ = _supabase_config_ok(log_error=True, verify_bucket=True)
    if not ok_storage:
        return False, err_storage, ""

    home = Path("/home") / username
    if not home.is_dir():
        return False, f"Home directory /home/{username} does not exist.", ""

    # Validate rel_paths – no absolute paths, no traversal.
    clean_paths = []
    for rel in rel_paths:
        if rel.startswith("/") or ".." in rel:
            return False, f"Invalid path: {rel}", ""
        candidate = home / rel
        if candidate.exists():
            clean_paths.append(rel)

    if not clean_paths:
        return False, "None of the selected paths exist in the user's home directory.", ""

    emit_progress(8, f"Preparing archive for {len(clean_paths)} selected path(s)…")

    archive_fd, archive_tmp = tempfile.mkstemp(prefix="vanish_storage_", suffix=".tar.gz")
    os.close(archive_fd)
    archive_path = Path(archive_tmp)
    try:
        # Build tar.gz on disk so very large backups don't require large RAM allocations.
        with tarfile.open(str(archive_path), mode="w:gz") as tar:
            total_paths = len(clean_paths)
            for idx, rel in enumerate(clean_paths, start=1):
                full = home / rel
                tar.add(str(full), arcname=rel)
                pct = 8 + int((idx / total_paths) * 58)
                emit_progress(pct, f"Packaging {idx}/{total_paths}: {rel}")
    except Exception as exc:
        archive_path.unlink(missing_ok=True)
        return False, f"Failed to create archive: {exc}", ""

    try:
        total_bytes = archive_path.stat().st_size
    except OSError as exc:
        archive_path.unlink(missing_ok=True)
        return False, f"Could not read archive size: {exc}", ""

    total_mb = round(total_bytes / (1024 * 1024), 2)
    chunk_bytes, _ = _get_storage_chunk_bytes()
    min_chunk_bytes = 5 * 1024 * 1024
    effective_chunk_bytes = max(min_chunk_bytes, chunk_bytes)
    effective_chunk_mb = round(effective_chunk_bytes / (1024 * 1024), 2)
    emit_progress(72, f"Archive ready ({total_mb} MB). Uploading to Supabase…")

    try:
        metadata_doc = {
            "storage_backend": "supabase",
            "filename": f"{config_name}.tar.gz",
            "config_name": config_name,
            "username": username,
            "owner": owner or username,
            "apps_included": clean_paths,
            "timestamp": now_ts(),
            "total_size_mb": total_mb,
            "archive_total_bytes": total_bytes,
        }

        parts: list[dict] = []
        resource_type = "raw"
        while True:
            total_parts = (total_bytes + effective_chunk_bytes - 1) // effective_chunk_bytes
            total_parts = max(1, total_parts)
            if total_parts > 1:
                emit_progress(
                    74,
                    (
                        f"Large archive detected ({total_mb} MB). "
                        f"Uploading {total_parts} chunk(s) of ~{effective_chunk_mb} MB and merging on restore…"
                    ),
                )
            else:
                emit_progress(74, f"Uploading archive ({total_mb} MB)…")

            parts = []
            retry_with_smaller_chunks = False
            size_limit_error = ""

            with archive_path.open("rb") as archive_file:
                for idx in range(total_parts):
                    part_index = idx + 1
                    start = idx * effective_chunk_bytes
                    end = min(start + effective_chunk_bytes, total_bytes)
                    archive_file.seek(start)
                    part_bytes = archive_file.read(end - start)
                    part_size_mb = round(len(part_bytes) / (1024 * 1024), 2)
                    pct = 74 + int((part_index / total_parts) * 16)
                    emit_progress(
                        pct,
                        f"Uploading chunk {part_index}/{total_parts} ({part_size_mb} MB)…",
                    )

                    part_filename = (
                        f"{config_name}.tar.gz"
                        if total_parts == 1
                        else f"{config_name}.part{part_index:04d}.bin"
                    )
                    ok_up, up_msg, storage_meta = _upload_archive_to_supabase(
                        archive_bytes=part_bytes,
                        filename=part_filename,
                        owner=owner or username,
                        config_name=config_name,
                        part_index=part_index if total_parts > 1 else None,
                        total_parts=total_parts if total_parts > 1 else None,
                    )
                    if not ok_up:
                        if _is_storage_size_limit_error(up_msg) and effective_chunk_bytes > min_chunk_bytes:
                            retry_with_smaller_chunks = True
                            size_limit_error = up_msg
                            break
                        return False, up_msg, ""

                    resource_type = storage_meta.get("resource_type", "raw")
                    parts.append({
                        "index": part_index,
                        "archive_object_path": storage_meta.get("object_path", ""),
                        "bytes": storage_meta.get("bytes", len(part_bytes)),
                    })

            if retry_with_smaller_chunks:
                new_chunk_bytes = max(min_chunk_bytes, effective_chunk_bytes // 2)
                if new_chunk_bytes >= effective_chunk_bytes:
                    return False, size_limit_error, ""
                prev_mb = round(effective_chunk_bytes / (1024 * 1024), 2)
                effective_chunk_bytes = new_chunk_bytes
                effective_chunk_mb = round(effective_chunk_bytes / (1024 * 1024), 2)
                emit_progress(
                    73,
                    (
                        f"Storage rejected {prev_mb} MB chunks due to size limit. "
                        f"Retrying with ~{effective_chunk_mb} MB chunks…"
                    ),
                )
                continue
            break

        if len(parts) == 1:
            first = parts[0]
            metadata_doc.update({
                "storage_mode": "single",
                "archive_object_path": first.get("archive_object_path", ""),
                "archive_bytes": first.get("bytes", total_bytes),
                "resource_type": resource_type,
            })
        else:
            metadata_doc.update({
                "storage_mode": "multipart",
                "chunk_size_mb": effective_chunk_mb,
                "archive_total_parts": len(parts),
                "archive_parts": parts,
                "resource_type": resource_type,
            })

        emit_progress(90, "Supabase upload complete. Saving metadata in Atlas…")
        backups = _get_backups_col()
        result = backups.insert_one(metadata_doc)
        emit_progress(100, "Upload complete.")
    except Exception as exc:
        print("[Atlas Error] upload_to_atlas exception:", file=sys.stderr)
        traceback.print_exc()
        return False, f"Storage upload failed: {exc}", ""
    finally:
        archive_path.unlink(missing_ok=True)

    return True, f"Uploaded {total_mb} MB to Supabase. Metadata saved in Atlas.", str(result.inserted_id)


def list_atlas_configs(owner: str = "") -> tuple[bool, str, list[dict]]:
    """List cloud backup records with backward-compatible support."""
    ok, err = _atlas_client_ok()
    if not ok:
        return False, err, []
    try:
        def collect_entries(query: dict, limit: int = 100) -> list[dict]:
            entries: list[dict] = []
            seen_ids: set[str] = set()

            col = _get_backups_col()
            for doc in col.find(query).sort("timestamp", -1).limit(limit):
                config_id = str(doc.get("_id"))
                if config_id in seen_ids:
                    continue
                seen_ids.add(config_id)
                entries.append({
                    "config_id": config_id,
                    "config_name": doc.get("config_name", doc.get("filename", "backup")),
                    "username": doc.get("username", ""),
                    "owner": doc.get("owner", ""),
                    "apps_included": doc.get("apps_included", []),
                    "timestamp": doc.get("timestamp", 0),
                    "total_size_mb": doc.get("total_size_mb", 0),
                })

            if _GRIDFS_AVAILABLE:
                try:
                    fs, db = _get_fs()
                    for grid_out in fs.find(query).sort("uploadDate", -1).limit(limit):
                        config_id = str(grid_out._id)
                        if config_id in seen_ids:
                            continue
                        seen_ids.add(config_id)
                        entries.append({
                            "config_id": config_id,
                            "config_name": getattr(grid_out, "config_name", getattr(grid_out, "filename", "backup")),
                            "username": getattr(grid_out, "username", ""),
                            "owner": getattr(grid_out, "owner", ""),
                            "apps_included": getattr(grid_out, "apps_included", []),
                            "timestamp": getattr(grid_out, "timestamp", 0),
                            "total_size_mb": getattr(grid_out, "total_size_mb", 0),
                        })
                except Exception as grid_exc:
                    print(f"[Atlas Warning] legacy GridFS list failed: {grid_exc}", file=sys.stderr)

            entries.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            return entries[:limit]

        scoped_query = _build_owner_query(owner)
        scoped_entries = collect_entries(scoped_query, limit=100)
        if scoped_entries:
            return True, f"{len(scoped_entries)} config(s) found.", scoped_entries

        # Fallback for owner/account mismatch: show all available configs.
        if owner:
            all_entries = collect_entries({}, limit=100)
            if all_entries:
                return True, (
                    f"No configs found for account '{owner}'. "
                    f"Showing {len(all_entries)} config(s) across all owners."
                ), all_entries

        return True, "0 config(s) found.", []
    except Exception as exc:
        print("[Atlas Error] list_atlas_configs exception:", file=sys.stderr)
        traceback.print_exc()
        return False, f"Atlas list failed: {exc}", []


def _run_cloud_upload_job(job_id: str, username: str, paths: list[str], config_name: str, owner: str) -> None:
    try:
        _set_cloud_upload_job(
            job_id,
            status="running",
            progress=1,
            stage="Upload started.",
            message="",
            error="",
            config_id="",
        )

        def progress_cb(percent: int, stage: str) -> None:
            _set_cloud_upload_job(
                job_id,
                status="running",
                progress=percent,
                stage=stage,
            )

        ok, msg, config_id = upload_to_atlas(
            username,
            paths,
            config_name,
            owner=owner,
            progress_cb=progress_cb,
        )
        if ok:
            _set_cloud_upload_job(
                job_id,
                status="completed",
                progress=100,
                stage="Upload complete.",
                message=msg,
                error="",
                config_id=config_id,
            )
        else:
            _set_cloud_upload_job(
                job_id,
                status="failed",
                progress=100,
                stage="Upload failed.",
                message="",
                error=msg,
                config_id="",
            )
    except Exception as exc:
        print("[Atlas Error] _run_cloud_upload_job exception:", file=sys.stderr)
        traceback.print_exc()
        _set_cloud_upload_job(
            job_id,
            status="failed",
            progress=100,
            stage="Upload failed unexpectedly.",
            message="",
            error=f"{type(exc).__name__}: {exc}",
            config_id="",
        )


def stream_from_atlas(config_id: str) -> tuple[bool, str, str]:
    """
    Download a cloud backup archive to a secure temp path.
    Primary backend: Supabase object path from Mongo metadata.
    Secondary backend: legacy Cloudinary URL metadata.
    Fallback backend: legacy GridFS object.
    Returns (ok, message, tmp_file_path).
    """
    ok, err = _atlas_client_ok()
    if not ok:
        return False, err, ""

    try:
        obj_id = ObjectId(config_id)
    except Exception:
        return False, "Invalid config_id format.", ""

    try:
        col = _get_backups_col()
        doc = col.find_one({"_id": obj_id})
        if doc:
            storage_backend = str(doc.get("storage_backend", "")).strip().lower()
            parts = doc.get("archive_parts", [])
            has_supabase_paths = bool(doc.get("archive_object_path")) or any(
                isinstance(p, dict) and p.get("archive_object_path")
                for p in (parts if isinstance(parts, list) else [])
            )
            if storage_backend == "supabase" or has_supabase_paths:
                if isinstance(parts, list) and len(parts) > 0:
                    sorted_parts = sorted(
                        [
                            p for p in parts
                            if isinstance(p, dict) and p.get("archive_object_path")
                        ],
                        key=lambda p: int(p.get("index", 0)),
                    )
                    if not sorted_parts:
                        return False, "Multipart archive metadata is invalid (no object paths).", ""
                    fd, tmp_path = tempfile.mkstemp(prefix="vanish_storage_", suffix=".tar.gz")
                    try:
                        with os.fdopen(fd, "wb") as dst:
                            total = len(sorted_parts)
                            for idx, part in enumerate(sorted_parts, start=1):
                                object_path = str(part.get("archive_object_path", "")).strip()
                                if not object_path:
                                    Path(tmp_path).unlink(missing_ok=True)
                                    return False, f"Missing object path for chunk {idx}.", ""
                                ok_part, msg_part, tmp_chunk = _download_supabase_object_to_temp(object_path)
                                if not ok_part:
                                    Path(tmp_path).unlink(missing_ok=True)
                                    return False, f"Failed downloading chunk {idx}/{total}: {msg_part}", ""
                                try:
                                    with open(tmp_chunk, "rb") as src:
                                        shutil.copyfileobj(src, dst)
                                finally:
                                    Path(tmp_chunk).unlink(missing_ok=True)
                        return True, f"Downloaded and merged {len(sorted_parts)} archive chunks from Supabase.", tmp_path
                    except Exception:
                        Path(tmp_path).unlink(missing_ok=True)
                        raise

                object_path = str(doc.get("archive_object_path", "")).strip()
                ok_dl, msg_dl, tmp_path = _download_supabase_object_to_temp(object_path)
                if not ok_dl:
                    return False, msg_dl, ""
                return True, msg_dl, tmp_path

            # Legacy Cloudinary metadata fallback.
            if isinstance(parts, list) and len(parts) > 0:
                sorted_parts = sorted(
                    [
                        p for p in parts
                        if isinstance(p, dict) and p.get("archive_url")
                    ],
                    key=lambda p: int(p.get("index", 0)),
                )
                if not sorted_parts:
                    return False, "Multipart archive metadata is invalid (no chunk URLs).", ""
                fd, tmp_path = tempfile.mkstemp(prefix="vanish_cloud_", suffix=".tar.gz")
                try:
                    with os.fdopen(fd, "wb") as dst:
                        total = len(sorted_parts)
                        for idx, part in enumerate(sorted_parts, start=1):
                            url = str(part.get("archive_url", "")).strip()
                            if not url:
                                Path(tmp_path).unlink(missing_ok=True)
                                return False, f"Missing URL for chunk {idx}.", ""
                            public_id = str(part.get("archive_public_id", "")).strip()
                            ok_part, msg_part, tmp_chunk = _download_url_to_temp(url, public_id=public_id)
                            if not ok_part:
                                Path(tmp_path).unlink(missing_ok=True)
                                return False, f"Failed downloading chunk {idx}/{total}: {msg_part}", ""
                            try:
                                with open(tmp_chunk, "rb") as src:
                                    shutil.copyfileobj(src, dst)
                            finally:
                                Path(tmp_chunk).unlink(missing_ok=True)
                    return True, f"Downloaded and merged {len(sorted_parts)} archive chunks from Cloudinary.", tmp_path
                except Exception:
                    Path(tmp_path).unlink(missing_ok=True)
                    raise

            url = doc.get("archive_url", "")
            public_id = str(doc.get("archive_public_id", "")).strip()
            ok_dl, msg_dl, tmp_path = _download_url_to_temp(url, public_id=public_id)
            if not ok_dl:
                return False, msg_dl, ""
            return True, msg_dl, tmp_path
    except Exception as exc:
        return False, f"Atlas metadata fetch failed: {exc}", ""

    # Legacy fallback for old GridFS records already in Atlas.
    if _GRIDFS_AVAILABLE:
        try:
            fs, db = _get_fs()
            grid_out = fs.get(obj_id)
            fd, tmp_path = tempfile.mkstemp(prefix="vanish_cloud_", suffix=".tar.gz")
            with os.fdopen(fd, "wb") as f:
                shutil.copyfileobj(grid_out, f)
            return True, "Downloaded legacy archive from Atlas GridFS.", tmp_path
        except Exception:
            pass

    return False, f"Config '{config_id}' not found.", ""


def restore_from_atlas(config_id: str, target_username: str) -> tuple[bool, str]:
    """
    Download archive from Atlas and extract into /home/<target_username>.
    Fixes ownership with chown afterwards.
    """
    if not is_valid_session_user(target_username):
        return False, "Invalid target username."

    target_home = Path("/home") / target_username
    if not target_home.is_dir():
        return False, f"/home/{target_username} does not exist."

    ok, msg, tmp_path = stream_from_atlas(config_id)
    if not ok:
        return False, msg

    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            # Safety: only extract members that don't escape the target dir.
            safe_members = [
                m for m in tar.getmembers()
                if not os.path.isabs(m.name) and ".." not in m.name
            ]
            tar.extractall(path=str(target_home), members=safe_members)
    except Exception as exc:
        return False, f"Extraction failed: {exc}"
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    # Fix ownership so the session user owns their own files.
    subprocess.run(
        ["chown", "-R", f"{target_username}:{target_username}", str(target_home)],
        capture_output=True,
    )

    return True, f"Restored archive into /home/{target_username}. Ownership fixed."


def build_policy_lines(payload: dict) -> list[str]:
    cfg = payload.get("config", {})
    if not isinstance(cfg, dict):
        cfg = {}

    lines = [
        f"exam.restrict_network={str(as_bool(cfg.get('exam_restrict_network'), True)).lower()}",
        f"exam.disable_usb={str(as_bool(cfg.get('exam_disable_usb'), True)).lower()}",
        f"exam.enable_persistence={str(as_bool(cfg.get('exam_enable_persistence'), True)).lower()}",
        f"online.enable_network={str(as_bool(cfg.get('online_enable_network'), True)).lower()}",
        f"online.enable_dns_filtering={str(as_bool(cfg.get('online_enable_dns_filtering'), True)).lower()}",
        f"online.disable_usb={str(as_bool(cfg.get('online_disable_usb'), True)).lower()}",
        f"online.enable_persistence={str(as_bool(cfg.get('online_enable_persistence'), True)).lower()}",
        f"online.enable_command_restriction={str(as_bool(cfg.get('online_enable_command_restriction'), False)).lower()}",
        f"privacy.enable_ram_home={str(as_bool(cfg.get('privacy_enable_ram_home'), True)).lower()}",
        f"privacy.enable_privacy_dns={str(as_bool(cfg.get('privacy_enable_privacy_dns'), True)).lower()}",
        f"privacy.block_telemetry={str(as_bool(cfg.get('privacy_block_telemetry'), True)).lower()}",
        f"privacy.apply_dark_theme={str(as_bool(cfg.get('privacy_apply_dark_theme'), True)).lower()}",
    ]

    proc_limit = cfg.get("proc_limit_override")
    if isinstance(proc_limit, int) and proc_limit > 0:
        lines.append(f"resource.proc_limit={proc_limit}")

    ram_home_size = cfg.get("privacy_ram_home_size_mb")
    if isinstance(ram_home_size, int) and ram_home_size > 0:
        lines.append(f"privacy.ram_home_size_mb={ram_home_size}")

    allow_sites = normalize_domain_csv(cfg.get("online_allow_sites", ""))
    block_sites = normalize_domain_csv(cfg.get("online_block_sites", ""))
    block_commands = cfg.get("online_block_commands", "")

    if isinstance(allow_sites, str):
        lines.append(f"online.allow_sites={allow_sites}")
    if isinstance(block_sites, str):
        lines.append(f"online.block_sites={block_sites}")
    if isinstance(block_commands, str):
        lines.append(f"online.block_commands={block_commands.strip()}")

    return lines


def write_policy_config(payload: dict) -> tuple[str, str]:
    lines = build_policy_lines(payload)

    fd, path = tempfile.mkstemp(prefix="vanish_admin_", suffix=".conf")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")

    return path, "\n".join(lines) + "\n"


class AdminHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format, *args):
        try:
            if len(args) > 0 and ("/api/status" in str(args[0]) or "/api/logs" in str(args[0])):
                return
        except Exception:
            pass
        super().log_message(format, *args)

    def _send_json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return {}
        raw = self.rfile.read(content_length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/status":
            sessions = get_sessions()
            self._send_json({"ok": True, "sessions": sessions, "count": len(sessions)})
            return

        if parsed.path == "/api/logs":
            self._send_json({"ok": True, "lines": tail_log_lines()})
            return

        if parsed.path == "/api/session/config":
            query = parse_qs(parsed.query)
            username = (query.get("username", [""])[0]).strip()
            ok, message, config_text = read_session_config_bundle(username)
            self._send_json(
                {"ok": ok, "message": message, "username": username, "config_text": config_text},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if parsed.path == "/api/session/report":
            query = parse_qs(parsed.query)
            username = (query.get("username", [""])[0]).strip()
            ok, message, report_text = get_session_report(username)
            self._send_json(
                {"ok": ok, "message": message, "username": username, "report_text": report_text},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if parsed.path == "/api/presets" or parsed.path == "/api/presets/":
            self._send_json({"ok": True, "presets": load_presets()})
            return

        if parsed.path == "/api/health":
            atlas_ok, atlas_err = _atlas_client_ok()
            atlas_uri, atlas_source = _get_atlas_uri_and_source()
            storage_ok, storage_err, storage_cfg = _supabase_config_ok(verify_bucket=True)
            _, storage_chunk_mb = _get_storage_chunk_bytes()
            self._send_json(
                {
                    "ok": True,
                    "service": "vanish-admin",
                    "running_as_root": os.geteuid() == 0,
                    "vanish_binary_exists": VANISH_BIN.exists(),
                    "atlas_configured": atlas_ok,
                    "atlas_error": atlas_err,
                    "atlas_uri_set": bool(atlas_uri),
                    "atlas_uri_source": atlas_source or "missing",
                    "pymongo_available": _PYMONGO_AVAILABLE,
                    "storage_provider": "supabase",
                    "supabase_configured": storage_ok,
                    "supabase_error": storage_err,
                    "supabase_url_set": bool(storage_cfg.get("url")),
                    "supabase_service_key_set": bool(storage_cfg.get("service_key")),
                    "supabase_bucket": storage_cfg.get("bucket", ""),
                    "supabase_prefix": storage_cfg.get("prefix", ""),
                    "storage_chunk_mb": storage_chunk_mb,
                    # Legacy aliases kept for older frontend compatibility.
                    "cloudinary_configured": storage_ok,
                    "cloudinary_error": storage_err,
                    "cloudinary_chunk_mb": storage_chunk_mb,
                }
            )
            return

        if parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return

        # ----- Cloud Sync routes (GET) ------------------------------------
        if parsed.path == "/api/cloud/scan":
            if os.geteuid() != 0:
                self._send_json({"ok": False, "error": "Root required."}, status=HTTPStatus.BAD_REQUEST)
                return
            # Auth check
            token = _resolve_token(self)
            if not token or token not in _CLOUD_SESSIONS:
                self._send_json({"ok": False, "error": "Not logged in. Please register or log in first."}, status=HTTPStatus.UNAUTHORIZED)
                return
            query = parse_qs(parsed.query)
            username = (query.get("username", [""])[0]).strip()
            if not is_valid_session_user(username):
                self._send_json({"ok": False, "error": "Invalid username."}, status=HTTPStatus.BAD_REQUEST)
                return
            ok, err = _atlas_client_ok()
            if not ok:
                self._send_json({"ok": False, "error": err}, status=HTTPStatus.BAD_REQUEST)
                return
            entries = scan_home_dir(username)
            self._send_json({"ok": True, "username": username, "entries": entries})
            return

        if parsed.path == "/api/cloud/list":
            token = _resolve_token(self)
            owner = _CLOUD_SESSIONS.get(token, "") if token else ""
            ok, msg, configs = list_atlas_configs(owner=owner)
            self._send_json(
                {"ok": ok, "message": msg, "configs": configs},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if parsed.path in {"/api/cloud/upload/status", "/api/cloud/upload/status/"}:
            token = _resolve_token(self)
            owner = _CLOUD_SESSIONS.get(token, "") if token else ""
            if not owner:
                self._send_json({"ok": False, "error": "Not logged in. Please log in first."}, status=HTTPStatus.UNAUTHORIZED)
                return
            query = parse_qs(parsed.query)
            job_id = (query.get("job_id", [""])[0]).strip()
            if not job_id:
                self._send_json({"ok": False, "error": "job_id is required."}, status=HTTPStatus.BAD_REQUEST)
                return
            job = _get_cloud_upload_job(job_id)
            if not job:
                self._send_json({"ok": False, "error": f"Upload job '{job_id}' not found."}, status=HTTPStatus.BAD_REQUEST)
                return
            if job.get("owner") != owner:
                self._send_json({"ok": False, "error": "Upload job does not belong to this account."}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._send_json(
                {
                    "ok": True,
                    "job_id": job_id,
                    "status": job.get("status", "unknown"),
                    "progress": int(job.get("progress", 0)),
                    "stage": job.get("stage", ""),
                    "message": job.get("message", ""),
                    "error": job.get("error", ""),
                    "config_id": job.get("config_id", ""),
                }
            )
            return

        if parsed.path == "/api/cloud/me":
            token = _resolve_token(self)
            if token and token in _CLOUD_SESSIONS:
                self._send_json({"ok": True, "logged_in": True, "username": _CLOUD_SESSIONS[token]})
            else:
                self._send_json({"ok": True, "logged_in": False, "username": ""})
            return

        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/start/validate":
            payload = self._read_json()
            mode = payload.get("mode", "").strip().lower()
            username = payload.get("username", "").strip()
            errors = []

            if mode not in ALLOWED_MODES:
                errors.append("Invalid mode.")
            if username and not is_valid_session_user(username):
                errors.append("Invalid username format.")
            if not VANISH_BIN.exists():
                errors.append(f"Binary not found: {VANISH_BIN}")

            self._send_json(
                {
                    "ok": len(errors) == 0,
                    "valid": len(errors) == 0,
                    "errors": errors,
                    "running_as_root": os.geteuid() == 0,
                },
                status=HTTPStatus.OK if len(errors) == 0 else HTTPStatus.BAD_REQUEST,
            )
            return

        if self.path == "/api/start/dry-run":
            payload = self._read_json()
            mode = payload.get("mode", "").strip().lower()
            username = payload.get("username", "").strip()
            persist_until_shutdown = as_bool(payload.get("persist_until_shutdown"), False)

            if mode not in ALLOWED_MODES:
                self._send_json(
                    {"ok": False, "error": "Invalid mode. Use: dev, secure, privacy, exam, online."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            config_text = "\n".join(build_policy_lines(payload)) + "\n"
            args = ["start", mode, "--config", "<temp_config_path>"]
            if username:
                args += ["--username", username]
            if payload.get("password", ""):
                args += ["--password", "<hidden>"]
            if persist_until_shutdown:
                args += ["--persist-until-shutdown"]

            self._send_json({"ok": True, "planned_args": args, "config_text": config_text})
            return

        if self.path == "/api/start":
            payload = self._read_json()
            mode = payload.get("mode", "").strip().lower()
            username = payload.get("username", "").strip()
            password = payload.get("password", "")
            persist_until_shutdown = as_bool(payload.get("persist_until_shutdown"), False)

            if os.geteuid() != 0:
                self._send_json(
                    {"ok": False, "error": "Admin panel must run with sudo/root to create sessions."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            if mode not in ALLOWED_MODES:
                self._send_json(
                    {"ok": False, "error": "Invalid mode. Use: dev, secure, privacy, exam, online."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            config_path, _ = write_policy_config(payload)
            args = ["start", mode, "--config", config_path]
            if username:
                args += ["--username", username]
            if password:
                args += ["--password", password]
            if persist_until_shutdown:
                args += ["--persist-until-shutdown"]

            try:
                code, out, err = run_vanish(args)
            finally:
                Path(config_path).unlink(missing_ok=True)

            if code != 0:
                rollback_user = username or extract_username_from_start_output(out)
                rollback_start_failure(rollback_user)

            self._send_json({"ok": code == 0, "stdout": out, "stderr": err, "exit_code": code})
            return

        if self.path == "/api/stop":
            if os.geteuid() != 0:
                self._send_json(
                    {"ok": False, "error": "Admin panel must run with sudo/root to stop sessions."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            code, out, err = run_vanish(["stop"])
            self._send_json({"ok": code == 0, "stdout": out, "stderr": err, "exit_code": code})
            return

        if self.path == "/api/session/stop":
            if os.geteuid() != 0:
                self._send_json(
                    {"ok": False, "error": "Admin panel must run with sudo/root to stop sessions."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            payload = self._read_json()
            username = payload.get("username", "").strip()
            ok, message = stop_single_session(username)
            self._send_json({"ok": ok, "message": message}, status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/session/extend":
            if os.geteuid() != 0:
                self._send_json(
                    {"ok": False, "error": "Admin panel must run with sudo/root to extend sessions."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            payload = self._read_json()
            username = payload.get("username", "").strip()
            try:
                extra_minutes = int(payload.get("extra_minutes", 0))
            except (TypeError, ValueError):
                extra_minutes = 0

            ok, message = extend_session_duration(username, extra_minutes)
            self._send_json({"ok": ok, "message": message}, status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/presets/save":
            payload = self._read_json()
            name = payload.get("name", "").strip()
            preset = payload.get("preset", {})

            if not name:
                self._send_json({"ok": False, "error": "Preset name is required."}, status=HTTPStatus.BAD_REQUEST)
                return
            if not isinstance(preset, dict):
                self._send_json({"ok": False, "error": "Preset payload must be an object."}, status=HTTPStatus.BAD_REQUEST)
                return

            presets = load_presets()
            presets[name] = preset
            if not save_presets(presets):
                self._send_json({"ok": False, "error": "Failed to save presets."}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return

            self._send_json({"ok": True, "message": f"Preset '{name}' saved.", "presets": presets})
            return

        if self.path == "/api/presets/delete":
            payload = self._read_json()
            name = payload.get("name", "").strip()
            presets = load_presets()

            if name not in presets:
                self._send_json({"ok": False, "error": "Preset not found."}, status=HTTPStatus.BAD_REQUEST)
                return

            del presets[name]
            if not save_presets(presets):
                self._send_json({"ok": False, "error": "Failed to save presets."}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return

            self._send_json({"ok": True, "message": f"Preset '{name}' deleted.", "presets": presets})
            return

        # ----- Cloud Auth routes (POST) -----------------------------------
        if self.path == "/api/cloud/register":
            payload = self._read_json()
            cloud_user = payload.get("username", "").strip()
            cloud_pass = payload.get("password", "")
            ok, msg = cloud_register(cloud_user, cloud_pass)
            self._send_json(
                {"ok": ok, "message": msg},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if self.path == "/api/cloud/login":
            payload = self._read_json()
            cloud_user = payload.get("username", "").strip()
            cloud_pass = payload.get("password", "")
            ok, msg, token = cloud_login(cloud_user, cloud_pass)
            self._send_json(
                {"ok": ok, "message": msg, "token": token, "username": cloud_user if ok else ""},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if self.path == "/api/cloud/logout":
            token = _resolve_token(self)
            if token:
                ok, msg = cloud_logout(token)
            else:
                ok, msg = False, "No token provided."
            self._send_json(
                {"ok": ok, "message": msg},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        # ----- Cloud Sync routes (POST) -----------------------------------
        if self.path in {"/api/cloud/upload", "/api/cloud/upload/"}:
            if os.geteuid() != 0:
                self._send_json({"ok": False, "error": "Root required."}, status=HTTPStatus.BAD_REQUEST)
                return
            payload = self._read_json()
            # Auth check
            token = payload.get("token", "") or _resolve_token(self)
            owner = _CLOUD_SESSIONS.get(token, "") if token else ""
            if not owner:
                self._send_json({"ok": False, "error": "Not logged in. Please log in first."}, status=HTTPStatus.UNAUTHORIZED)
                return
            username = payload.get("username", "").strip()
            paths = payload.get("paths", [])
            config_name = payload.get("config_name", "").strip() or f"{username}-backup"

            if not is_valid_session_user(username):
                self._send_json({"ok": False, "error": "Invalid username."}, status=HTTPStatus.BAD_REQUEST)
                return
            if not isinstance(paths, list) or not paths:
                self._send_json({"ok": False, "error": "'paths' must be a non-empty list."}, status=HTTPStatus.BAD_REQUEST)
                return

            ok, msg, config_id = upload_to_atlas(username, paths, config_name, owner=owner)
            self._send_json(
                {"ok": ok, "message": msg, "config_id": config_id},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if self.path in {"/api/cloud/upload/start", "/api/cloud/upload/start/"}:
            if os.geteuid() != 0:
                self._send_json({"ok": False, "error": "Root required."}, status=HTTPStatus.BAD_REQUEST)
                return
            payload = self._read_json()
            token = payload.get("token", "") or _resolve_token(self)
            owner = _CLOUD_SESSIONS.get(token, "") if token else ""
            if not owner:
                self._send_json({"ok": False, "error": "Not logged in. Please log in first."}, status=HTTPStatus.UNAUTHORIZED)
                return

            username = payload.get("username", "").strip()
            paths = payload.get("paths", [])
            config_name = payload.get("config_name", "").strip() or f"{username}-backup"
            if not is_valid_session_user(username):
                self._send_json({"ok": False, "error": "Invalid username."}, status=HTTPStatus.BAD_REQUEST)
                return
            if not isinstance(paths, list) or not paths:
                self._send_json({"ok": False, "error": "'paths' must be a non-empty list."}, status=HTTPStatus.BAD_REQUEST)
                return

            normalized_paths = []
            for rel in paths:
                if not isinstance(rel, str):
                    continue
                rel = rel.strip()
                if rel:
                    normalized_paths.append(rel)
            if not normalized_paths:
                self._send_json({"ok": False, "error": "No valid paths provided."}, status=HTTPStatus.BAD_REQUEST)
                return

            job_id = secrets.token_hex(16)
            _set_cloud_upload_job(
                job_id,
                owner=owner,
                username=username,
                config_name=config_name,
                status="queued",
                progress=0,
                stage="Queued for upload.",
                message="",
                error="",
                config_id="",
            )
            worker = threading.Thread(
                target=_run_cloud_upload_job,
                args=(job_id, username, normalized_paths, config_name, owner),
                daemon=True,
            )
            worker.start()
            self._send_json(
                {
                    "ok": True,
                    "job_id": job_id,
                    "status": "queued",
                    "message": "Upload job queued.",
                }
            )
            return

        if self.path == "/api/cloud/restore":
            if os.geteuid() != 0:
                self._send_json({"ok": False, "error": "Root required."}, status=HTTPStatus.BAD_REQUEST)
                return
            payload = self._read_json()
            # Auth check
            token = payload.get("token", "") or _resolve_token(self)
            owner = _CLOUD_SESSIONS.get(token, "") if token else ""
            if not owner:
                self._send_json({"ok": False, "error": "Not logged in. Please log in first."}, status=HTTPStatus.UNAUTHORIZED)
                return
            config_id = payload.get("config_id", "").strip()
            target_username = payload.get("target_username", "").strip()

            if not config_id:
                self._send_json({"ok": False, "error": "config_id is required."}, status=HTTPStatus.BAD_REQUEST)
                return
            if not is_valid_session_user(target_username):
                self._send_json({"ok": False, "error": "Invalid target_username."}, status=HTTPStatus.BAD_REQUEST)
                return

            ok, msg = restore_from_atlas(config_id, target_username)
            self._send_json(
                {"ok": ok, "message": msg},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        if self.path in {"/api/cloud/delete", "/api/cloud/delete/"}:
            if os.geteuid() != 0:
                self._send_json({"ok": False, "error": "Root required."}, status=HTTPStatus.BAD_REQUEST)
                return
            payload = self._read_json()
            token = payload.get("token", "") or _resolve_token(self)
            owner = _CLOUD_SESSIONS.get(token, "") if token else ""
            if not owner:
                self._send_json({"ok": False, "error": "Not logged in. Please log in first."}, status=HTTPStatus.UNAUTHORIZED)
                return
            config_id = payload.get("config_id", "").strip()
            if not config_id:
                self._send_json({"ok": False, "error": "config_id is required."}, status=HTTPStatus.BAD_REQUEST)
                return
            ok, msg = delete_from_atlas(config_id=config_id, owner=owner)
            self._send_json(
                {"ok": ok, "message": msg},
                status=HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
            )
            return

        self._send_json({"ok": False, "error": f"Not found: {self.path}"}, status=HTTPStatus.NOT_FOUND)


def main() -> None:
    host = os.getenv("VANISH_ADMIN_HOST", "127.0.0.1")
    port = int(os.getenv("VANISH_ADMIN_PORT", "8080"))

    server = ThreadingHTTPServer((host, port), AdminHandler)
    print(f"Vanish admin panel running at http://{host}:{port}")
    print("Run this server with sudo so it can control vanish sessions.")
    server.serve_forever()


if __name__ == "__main__":
    main()
