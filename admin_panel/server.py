#!/usr/bin/env python3
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
            self._send_json(
                {
                    "ok": True,
                    "service": "vanish-admin",
                    "running_as_root": os.geteuid() == 0,
                    "vanish_binary_exists": VANISH_BIN.exists(),
                }
            )
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

        self._send_json({"ok": False, "error": "Not found"}, status=HTTPStatus.NOT_FOUND)


def main() -> None:
    host = os.getenv("VANISH_ADMIN_HOST", "127.0.0.1")
    port = int(os.getenv("VANISH_ADMIN_PORT", "8080"))

    server = ThreadingHTTPServer((host, port), AdminHandler)
    print(f"Vanish admin panel running at http://{host}:{port}")
    print("Run this server with sudo so it can control vanish sessions.")
    server.serve_forever()


if __name__ == "__main__":
    main()
