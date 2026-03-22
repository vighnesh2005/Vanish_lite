#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This integration test must run as root."
  echo "Run: sudo scripts/test_modes_integration.sh"
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/vanish_mode_tests.XXXXXX)"
TEST_USERS=()

cleanup() {
  set +e
  ./vanish stop >/dev/null 2>&1 || true

  for u in "${TEST_USERS[@]:-}"; do
    pkill -9 -u "$u" >/dev/null 2>&1 || true
    loginctl terminate-user "$u" >/dev/null 2>&1 || true
    umount -l "/home/$u/submit" >/dev/null 2>&1 || true
    userdel -f -r "$u" >/dev/null 2>&1 || true
    rm -f "/var/vanish_sessions/$u" \
          "/var/vanish_sessions/$u.policy.conf" \
          "/var/vanish_sessions/$u.online.conf" \
          "/var/vanish_sessions/$u.monitor.conf" \
          "/var/vanish_sessions/$u.limits.intent" \
          "/var/vanish_sessions/$u.report.json" >/dev/null 2>&1 || true
  done

  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

assert_file_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$file"; then
    echo "Assertion failed: '$needle' not found in $file"
    echo "--- File content ---"
    cat "$file" || true
    exit 1
  fi
}

assert_file_exists() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "Assertion failed: expected file $file"
    exit 1
  fi
}

assert_user_absent() {
  local user="$1"
  loginctl terminate-user "$user" >/dev/null 2>&1 || true
  pkill -9 -u "$user" >/dev/null 2>&1 || true
  userdel -f -r "$user" >/dev/null 2>&1 || true
  if id "$user" >/dev/null 2>&1; then
    echo "Assertion failed: user still exists after cleanup: $user"
    exit 1
  fi
}

wait_until_user_absent() {
  local user="$1"
  local timeout="${2:-40}"
  local elapsed=0
  while (( elapsed < timeout )); do
    if ! id "$user" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "Assertion failed: user still exists after waiting ${timeout}s: $user"
  return 1
}

start_and_check() {
  local mode="$1"
  local user="$2"
  local pass="$3"
  local conf="$4"
  local persist_flag="${5:-0}"

  TEST_USERS+=("$user")

  local cmd=(./vanish start "$mode" --username "$user" --password "$pass" --config "$conf")
  if [[ "$persist_flag" == "1" ]]; then
    cmd+=(--persist-until-shutdown)
  fi

  echo "[TEST] start mode=$mode user=$user"
  "${cmd[@]}" >/tmp/vanish_test_start.log 2>&1 || {
    echo "Failed to start mode=$mode"
    cat /tmp/vanish_test_start.log || true
    exit 1
  }

  local session_file="/var/vanish_sessions/$user"
  local policy_snapshot="/var/vanish_sessions/$user.policy.conf"
  local monitor_snapshot="/var/vanish_sessions/$user.monitor.conf"
  local report_snapshot="/var/vanish_sessions/$user.report.json"

  assert_file_exists "$session_file"
  assert_file_exists "$policy_snapshot"
  assert_file_exists "$monitor_snapshot"
  assert_file_exists "$report_snapshot"

  assert_file_contains "$session_file" "username=$user"
  assert_file_contains "$session_file" "mode=$mode"
  if [[ "$persist_flag" == "1" ]]; then
    assert_file_contains "$session_file" "persist_until_shutdown=1"
  else
    assert_file_contains "$session_file" "persist_until_shutdown=0"
  fi

  assert_file_contains "$policy_snapshot" "mode=$mode"
}

make all

cat > "$TMP_DIR/dev.conf" <<'CFG'
resource.proc_limit=1333
CFG

cat > "$TMP_DIR/secure.conf" <<'CFG'
resource.proc_limit=1111
CFG

cat > "$TMP_DIR/privacy.conf" <<'CFG'
privacy.enable_ram_home=true
privacy.ram_home_size_mb=1024
privacy.enable_privacy_dns=false
privacy.block_telemetry=true
privacy.apply_dark_theme=false
resource.proc_limit=1001
CFG

cat > "$TMP_DIR/exam.conf" <<'CFG'
exam.restrict_network=true
exam.disable_usb=true
exam.enable_persistence=true
resource.proc_limit=777
CFG

cat > "$TMP_DIR/online_custom.conf" <<'CFG'
online.enable_network=true
online.enable_dns_filtering=true
online.disable_usb=true
online.enable_persistence=true
online.enable_command_restriction=true
online.allow_sites=docs.python.org,cppreference.com
online.block_sites=chat.openai.com,github.com
online.block_commands=curl,wget,git,python3
resource.proc_limit=888
CFG

SUFFIX="$(date +%s)"

# dev
USER_DEV="vdev_${SUFFIX}"
start_and_check "dev" "$USER_DEV" "DevPass123" "$TMP_DIR/dev.conf"
assert_file_contains "/var/vanish_sessions/$USER_DEV.policy.conf" "resource.proc_limit=1333"
# Simulate login/logout cycle and verify auto-delete on logout.
su - "$USER_DEV" -c "sleep 2" >/dev/null 2>&1 || true
wait_until_user_absent "$USER_DEV" 50

# secure
USER_SEC="vsec_${SUFFIX}"
start_and_check "secure" "$USER_SEC" "SecPass123" "$TMP_DIR/secure.conf"
assert_file_contains "/var/vanish_sessions/$USER_SEC.policy.conf" "resource.proc_limit=1111"
./vanish stop >/dev/null 2>&1
assert_user_absent "$USER_SEC"

# privacy
USER_PRI="vpri_${SUFFIX}"
start_and_check "privacy" "$USER_PRI" "PriPass123" "$TMP_DIR/privacy.conf"
assert_file_contains "/var/vanish_sessions/$USER_PRI.policy.conf" "privacy.ram_home_size_mb=1024"
assert_file_contains "/var/vanish_sessions/$USER_PRI.policy.conf" "privacy.enable_privacy_dns=false"
./vanish stop >/dev/null 2>&1
assert_user_absent "$USER_PRI"

# exam + persist until shutdown flag
USER_EXM="vexm_${SUFFIX}"
start_and_check "exam" "$USER_EXM" "ExmPass123" "$TMP_DIR/exam.conf" "1"
assert_file_contains "/var/vanish_sessions/$USER_EXM" "persist_until_shutdown=1"
assert_file_contains "/var/vanish_sessions/$USER_EXM.policy.conf" "exam.restrict_network=true"
# Simulate logout and ensure user is still present because persist-until-shutdown is enabled.
su - "$USER_EXM" -c "sleep 2" >/dev/null 2>&1 || true
sleep 8
if ! id "$USER_EXM" >/dev/null 2>&1; then
  echo "Assertion failed: persist-until-shutdown user deleted after logout: $USER_EXM"
  exit 1
fi
./vanish stop >/dev/null 2>&1
assert_user_absent "$USER_EXM"

# online custom config
USER_ONL="vonl_${SUFFIX}"
start_and_check "online" "$USER_ONL" "OnlPass123" "$TMP_DIR/online_custom.conf"
assert_file_exists "/var/vanish_sessions/$USER_ONL.online.conf"
assert_file_contains "/var/vanish_sessions/$USER_ONL.policy.conf" "online.enable_command_restriction=true"
assert_file_contains "/var/vanish_sessions/$USER_ONL.policy.conf" "online.allow_sites=docs.python.org,cppreference.com"
assert_file_contains "/var/vanish_sessions/$USER_ONL.policy.conf" "online.block_sites=chat.openai.com,github.com"
assert_file_contains "/var/vanish_sessions/$USER_ONL.policy.conf" "online.block_commands=curl,wget,git,python3"
./vanish stop >/dev/null 2>&1
assert_user_absent "$USER_ONL"

echo "All mode integration tests passed, and all test sessions were cleaned up."
