const sessionsBody = document.getElementById('sessions-body');
const logsBox = document.getElementById('logs-box');
const statusLine = document.getElementById('action-status');
const sessionCount = document.getElementById('session-count');
const modeSelect = document.getElementById('mode-select');
const modeHint = document.getElementById('mode-hint');
const modeDescTitle = document.getElementById('mode-desc-title');
const modeDescSummary = document.getElementById('mode-desc-summary');
const modeDescList = document.getElementById('mode-desc-list');
const modeCards = document.querySelectorAll('.mode-card');
const configToggleButtons = document.querySelectorAll('.config-toggle-btn');
const configEditorWraps = document.querySelectorAll('.config-editor-wrap');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const procLimitInput = document.getElementById('proc-limit-input');
const persistUntilShutdownInput = document.getElementById('persist-until-shutdown');
const presetSelect = document.getElementById('preset-select');
const loadPresetBtn = document.getElementById('load-preset-btn');
const savePresetBtn = document.getElementById('save-preset-btn');
const deletePresetBtn = document.getElementById('delete-preset-btn');
const validateBtn = document.getElementById('validate-btn');
const dryRunBtn = document.getElementById('dry-run-btn');
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');
const refreshBtn = document.getElementById('refresh-btn');
const configViewer = document.getElementById('config-viewer');
const configBox = document.getElementById('config-box');
const configTitle = document.getElementById('config-title');
const closeConfigBtn = document.getElementById('close-config-btn');

const examRestrictNetwork = document.getElementById('exam-restrict-network');
const examDisableUsb = document.getElementById('exam-disable-usb');
const examEnablePersistence = document.getElementById('exam-enable-persistence');

const onlineEnableNetwork = document.getElementById('online-enable-network');
const onlineEnableDnsFiltering = document.getElementById('online-enable-dns-filtering');
const onlineDisableUsb = document.getElementById('online-disable-usb');
const onlineEnablePersistence = document.getElementById('online-enable-persistence');
const onlineEnableCommandRestriction = document.getElementById('online-enable-command-restriction');
const onlineAllowSites = document.getElementById('online-allow-sites');
const onlineBlockSites = document.getElementById('online-block-sites');
const onlineBlockCommands = document.getElementById('online-block-commands');

const privacyEnableRamHome = document.getElementById('privacy-enable-ram-home');
const privacyRamSizeMb = document.getElementById('privacy-ram-size-mb');
const privacyEnableDns = document.getElementById('privacy-enable-dns');
const privacyBlockTelemetry = document.getElementById('privacy-block-telemetry');
const privacyApplyDarkTheme = document.getElementById('privacy-apply-dark-theme');
let presets = {};

const MODE_DESCRIPTIONS = {
  dev: {
    title: 'Mode: dev',
    summary: 'Default lightweight disposable session with minimal restrictions.',
    features: [
      'Creates isolated temporary user workspace',
      'Applies default process limit (~1500 nproc)',
      'No forced network or USB lockdown by default'
    ]
  },
  secure: {
    title: 'Mode: secure',
    summary: 'Balanced restricted workspace for safer usage.',
    features: [
      'Creates isolated temporary user workspace',
      'Applies stricter process limit (~1200 nproc)',
      'No extra exam/privacy policies unless explicitly toggled in config'
    ]
  },
  privacy: {
    title: 'Mode: privacy',
    summary: 'Focuses on reducing local traces and privacy hardening.',
    features: [
      'RAM-backed home mount enabled by default (size configurable)',
      'Privacy DNS enabled by default',
      'Telemetry domains blocked and dark theme applied by default'
    ]
  },
  exam: {
    title: 'Mode: exam',
    summary: 'Offline exam-like lockdown behavior.',
    features: [
      'Network restriction enabled by default',
      'USB disabled by default',
      'Persistent submit folder mount enabled by default'
    ]
  },
  online: {
    title: 'Mode: online',
    summary: 'Controlled internet exam mode with optional restrictions.',
    features: [
      'HTTP/HTTPS/DNS network allowed by default',
      'DNS block-list filtering enabled by default',
      'USB + submit persistence enabled by default, command restriction optional'
    ]
  }
};

function syncModeVisibility() {
  const selected = modeSelect.value;
  let anyVisible = false;

  modeCards.forEach((card) => {
    const show = card.dataset.mode === selected;
    card.classList.toggle('hidden', !show);
    if (show) anyVisible = true;
  });

  modeHint.textContent = anyVisible ? `Showing ${selected} mode options.` : 'No extra options for this mode.';
  hideAllConfigEditors();
  updateModeDescription(selected);
}

function updateModeDescription(mode) {
  const item = MODE_DESCRIPTIONS[mode] || MODE_DESCRIPTIONS.dev;
  modeDescTitle.textContent = item.title;
  modeDescSummary.textContent = item.summary;
  modeDescList.innerHTML = item.features.map((f) => `<li>${f}</li>`).join('');
}

function hideAllConfigEditors() {
  configEditorWraps.forEach((wrap) => wrap.classList.add('hidden'));
}

function toggleConfigEditor(targetId) {
  const target = document.getElementById(targetId);
  if (!target) return;

  const shouldOpen = target.classList.contains('hidden');
  hideAllConfigEditors();
  if (shouldOpen) {
    target.classList.remove('hidden');
  }
}

function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return 'N/A';
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hrs}h ${mins}m`;
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.style.color = isError ? '#8f2d2d' : '#6f665b';
}

function renderSessions(sessions) {
  if (!sessions.length) {
    sessionsBody.innerHTML = '<tr><td colspan="6">No active sessions.</td></tr>';
    return;
  }

  sessionsBody.innerHTML = sessions.map((s) => {
    return `<tr>
      <td>${s.username}</td>
      <td>${s.mode}</td>
      <td>${s.minutes_running} min</td>
      <td>${fmtDuration(s.seconds_remaining)}</td>
      <td><span class="persist-badge ${s.persist_until_shutdown ? 'on' : 'off'}">${s.persist_until_shutdown ? 'Shutdown' : 'Logout'}</span></td>
      <td>
        <button class="btn ghost mini" data-action="view-config" data-user="${s.username}">Config</button>
        <button class="btn ghost mini" data-action="view-report" data-user="${s.username}">Report</button>
        <button class="btn ghost mini" data-action="extend" data-user="${s.username}">Extend</button>
        <button class="btn danger mini" data-action="stop-user" data-user="${s.username}">Stop</button>
      </td>
    </tr>`;
  }).join('');
}

function buildStartPayload() {
  const procLimit = Number.parseInt(procLimitInput.value, 10);
  return {
    mode: modeSelect.value,
    username: usernameInput.value.trim(),
    password: passwordInput.value,
    persist_until_shutdown: persistUntilShutdownInput.checked,
    config: {
      exam_restrict_network: examRestrictNetwork.checked,
      exam_disable_usb: examDisableUsb.checked,
      exam_enable_persistence: examEnablePersistence.checked,
      online_enable_network: onlineEnableNetwork.checked,
      online_enable_dns_filtering: onlineEnableDnsFiltering.checked,
      online_disable_usb: onlineDisableUsb.checked,
      online_enable_persistence: onlineEnablePersistence.checked,
      online_enable_command_restriction: onlineEnableCommandRestriction.checked,
      online_allow_sites: onlineAllowSites.value.trim(),
      online_block_sites: onlineBlockSites.value.trim(),
      online_block_commands: onlineBlockCommands.value.trim(),
      privacy_enable_ram_home: privacyEnableRamHome.checked,
      privacy_ram_home_size_mb: Number.parseInt(privacyRamSizeMb.value, 10) || null,
      privacy_enable_privacy_dns: privacyEnableDns.checked,
      privacy_block_telemetry: privacyBlockTelemetry.checked,
      privacy_apply_dark_theme: privacyApplyDarkTheme.checked,
      proc_limit_override: Number.isFinite(procLimit) && procLimit > 0 ? procLimit : null
    }
  };
}

function applyPresetToForm(preset) {
  if (!preset || typeof preset !== 'object') return;

  if (preset.mode) modeSelect.value = preset.mode;
  usernameInput.value = preset.username || '';
  passwordInput.value = preset.password || '';
  persistUntilShutdownInput.checked = Boolean(preset.persist_until_shutdown);

  const cfg = preset.config || {};
  examRestrictNetwork.checked = cfg.exam_restrict_network ?? examRestrictNetwork.checked;
  examDisableUsb.checked = cfg.exam_disable_usb ?? examDisableUsb.checked;
  examEnablePersistence.checked = cfg.exam_enable_persistence ?? examEnablePersistence.checked;
  onlineEnableNetwork.checked = cfg.online_enable_network ?? onlineEnableNetwork.checked;
  onlineEnableDnsFiltering.checked = cfg.online_enable_dns_filtering ?? onlineEnableDnsFiltering.checked;
  onlineDisableUsb.checked = cfg.online_disable_usb ?? onlineDisableUsb.checked;
  onlineEnablePersistence.checked = cfg.online_enable_persistence ?? onlineEnablePersistence.checked;
  onlineEnableCommandRestriction.checked = cfg.online_enable_command_restriction ?? onlineEnableCommandRestriction.checked;
  onlineAllowSites.value = cfg.online_allow_sites || '';
  onlineBlockSites.value = cfg.online_block_sites || '';
  onlineBlockCommands.value = cfg.online_block_commands || '';
  privacyEnableRamHome.checked = cfg.privacy_enable_ram_home ?? privacyEnableRamHome.checked;
  privacyRamSizeMb.value = cfg.privacy_ram_home_size_mb || privacyRamSizeMb.value;
  privacyEnableDns.checked = cfg.privacy_enable_privacy_dns ?? privacyEnableDns.checked;
  privacyBlockTelemetry.checked = cfg.privacy_block_telemetry ?? privacyBlockTelemetry.checked;
  privacyApplyDarkTheme.checked = cfg.privacy_apply_dark_theme ?? privacyApplyDarkTheme.checked;
  procLimitInput.value = cfg.proc_limit_override || '';

  syncModeVisibility();
}

function renderPresetSelect() {
  const names = Object.keys(presets).sort();
  presetSelect.innerHTML = '<option value="">Select preset</option>' +
    names.map((name) => `<option value="${name}">${name}</option>`).join('');
}

async function loadPresets() {
  try {
    let data;
    try {
      data = await getJSON('/api/presets');
    } catch (_) {
      // Some deployments may expose this route with a trailing slash.
      data = await getJSON('/api/presets/');
    }
    presets = data.presets || {};
    renderPresetSelect();
  } catch (err) {
    setStatus(`Preset load failed: ${err.message}`, true);
  }
}

async function getJSON(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data;

  try {
    data = JSON.parse(text);
  } catch (_) {
    const sample = text.slice(0, 80).replace(/\s+/g, ' ');
    throw new Error(`Expected JSON from ${url}, got: ${sample}`);
  }

  if (!res.ok || !data.ok) {
    const message = data.error || data.message || data.stderr || data.stdout || `Request failed: ${res.status}`;
    console.error(`[API Error] ${url}: ${message}`, data);
    throw new Error(message);
  }
  return data;
}

async function refreshStatus() {
  try {
    const data = await getJSON('/api/status');
    renderSessions(data.sessions);
    sessionCount.textContent = `${data.count} session${data.count === 1 ? '' : 's'}`;
  } catch (err) {
    setStatus(`Status error: ${err.message}`, true);
  }
}

async function refreshLogs() {
  try {
    const data = await getJSON('/api/logs');
    logsBox.textContent = data.lines.join('\n') || 'No logs yet.';
    logsBox.scrollTop = logsBox.scrollHeight;
  } catch (err) {
    setStatus(`Log error: ${err.message}`, true);
  }
}

async function startSession() {
  const mode = modeSelect.value;
  setStatus(`Starting ${mode} session...`);

  try {
    const payload = buildStartPayload();
    const data = await getJSON('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const summary = data.stdout || `Started ${mode} session.`;
    setStatus(summary);
    await refreshStatus();
    await refreshLogs();
  } catch (err) {
    setStatus(`Start failed: ${err.message}`, true);
  }
}

async function validateStartConfig() {
  setStatus('Validating current config...');
  try {
    const data = await getJSON('/api/start/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildStartPayload())
    });
    setStatus(data.valid ? 'Validation passed.' : `Validation failed: ${(data.errors || []).join(', ')}`, !data.valid);
  } catch (err) {
    setStatus(`Validation failed: ${err.message}`, true);
  }
}

async function dryRunStartConfig() {
  setStatus('Generating dry run...');
  try {
    const data = await getJSON('/api/start/dry-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildStartPayload())
    });
    configTitle.textContent = 'Dry Run: Planned Args + Generated Config';
    configBox.textContent = `$ vanish ${data.planned_args.join(' ')}\n\n${data.config_text}`;
    configViewer.classList.remove('hidden');
    setStatus('Dry run generated.');
  } catch (err) {
    setStatus(`Dry run failed: ${err.message}`, true);
  }
}

async function saveCurrentPreset() {
  const name = window.prompt('Preset name:', modeSelect.value + '-preset');
  if (!name) return;
  try {
    const data = await getJSON('/api/presets/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, preset: buildStartPayload() })
    });
    presets = data.presets || {};
    renderPresetSelect();
    presetSelect.value = name;
    setStatus(data.message || 'Preset saved.');
  } catch (err) {
    setStatus(`Save preset failed: ${err.message}`, true);
  }
}

function loadSelectedPreset() {
  const name = presetSelect.value;
  if (!name || !presets[name]) {
    setStatus('Select a preset first.', true);
    return;
  }
  applyPresetToForm(presets[name]);
  setStatus(`Loaded preset: ${name}`);
}

async function deleteSelectedPreset() {
  const name = presetSelect.value;
  if (!name) {
    setStatus('Select a preset first.', true);
    return;
  }
  if (!window.confirm(`Delete preset '${name}'?`)) return;
  try {
    const data = await getJSON('/api/presets/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    presets = data.presets || {};
    renderPresetSelect();
    setStatus(data.message || 'Preset deleted.');
  } catch (err) {
    setStatus(`Delete preset failed: ${err.message}`, true);
  }
}

async function stopAll() {
  if (!window.confirm('Stop and cleanup all vanish sessions?')) {
    return;
  }

  setStatus('Stopping all sessions...');

  try {
    const data = await getJSON('/api/stop', { method: 'POST' });
    const summary = data.stdout || 'All sessions stopped.';
    setStatus(summary);
    await refreshStatus();
    await refreshLogs();
  } catch (err) {
    setStatus(`Stop failed: ${err.message}`, true);
  }
}

async function stopOneUser(username) {
  if (!window.confirm(`Stop and cleanup session for ${username}?`)) {
    return;
  }

  setStatus(`Stopping ${username}...`);
  try {
    const data = await getJSON('/api/session/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    setStatus(data.message || `Stopped ${username}.`);
    await refreshStatus();
    await refreshLogs();
  } catch (err) {
    setStatus(`Stop user failed: ${err.message}`, true);
  }
}

async function extendOneUser(username) {
  const raw = window.prompt(`Add minutes to ${username}'s session:`, '15');
  if (raw === null) return;

  const extraMinutes = Number.parseInt(raw, 10);
  if (!Number.isFinite(extraMinutes) || extraMinutes <= 0) {
    setStatus('Enter a valid positive number of minutes.', true);
    return;
  }

  setStatus(`Extending ${username} by ${extraMinutes} minute(s)...`);
  try {
    const data = await getJSON('/api/session/extend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, extra_minutes: extraMinutes })
    });
    setStatus(data.message || `Extended ${username}.`);
    await refreshStatus();
  } catch (err) {
    setStatus(`Extend failed: ${err.message}`, true);
  }
}

async function showSessionConfig(username) {
  setStatus(`Loading config snapshot for ${username}...`);
  try {
    const data = await getJSON(`/api/session/config?username=${encodeURIComponent(username)}`);
    configTitle.textContent = `Session Config Snapshot: ${username}`;
    configBox.textContent = data.config_text || 'No config snapshot found.';
    configViewer.classList.remove('hidden');
    setStatus(data.message || `Loaded config for ${username}.`);
  } catch (err) {
    setStatus(`Config load failed: ${err.message}`, true);
  }
}

async function showSessionReport(username) {
  setStatus(`Loading compliance report for ${username}...`);
  try {
    const data = await getJSON(`/api/session/report?username=${encodeURIComponent(username)}`);
    configTitle.textContent = `Session Compliance Report: ${username}`;
    configBox.textContent = data.report_text || 'No report found.';
    configViewer.classList.remove('hidden');
    setStatus(data.message || `Loaded report for ${username}.`);
  } catch (err) {
    setStatus(`Report load failed: ${err.message}`, true);
  }
}

// Password visibility toggle logic
document.querySelectorAll('.password-toggle').forEach((btn) => {
  btn.addEventListener('click', () => {
    const targetId = btn.dataset.target;
    const input = document.getElementById(targetId);
    if (!input) return;

    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';

    // Update icon to eye or eye-off
    if (isPassword) {
      btn.innerHTML = `<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
    } else {
      btn.innerHTML = `<svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    }
  });
});

startBtn.addEventListener('click', startSession);
stopBtn.addEventListener('click', stopAll);
validateBtn.addEventListener('click', validateStartConfig);
dryRunBtn.addEventListener('click', dryRunStartConfig);
savePresetBtn.addEventListener('click', saveCurrentPreset);
loadPresetBtn.addEventListener('click', loadSelectedPreset);
deletePresetBtn.addEventListener('click', deleteSelectedPreset);
modeSelect.addEventListener('change', syncModeVisibility);
configToggleButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    const targetId = btn.dataset.target;
    if (!targetId) return;
    toggleConfigEditor(targetId);
  });
});
refreshBtn.addEventListener('click', async () => {
  await refreshStatus();
  await refreshLogs();
  setStatus('Refreshed.');
});
closeConfigBtn.addEventListener('click', () => {
  configViewer.classList.add('hidden');
});

sessionsBody.addEventListener('click', async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const action = target.dataset.action;
  const username = target.dataset.user;
  if (!action || !username) return;

  if (action === 'stop-user') {
    await stopOneUser(username);
  } else if (action === 'extend') {
    await extendOneUser(username);
  } else if (action === 'view-config') {
    await showSessionConfig(username);
  } else if (action === 'view-report') {
    await showSessionReport(username);
  }
});

(async () => {
  try {
    const health = await getJSON('/api/health');
    if (!health.running_as_root) {
      setStatus('Panel is not running as root. Start with: sudo make admin-panel', true);
    }
  } catch (err) {
    setStatus(`Health error: ${err.message}`, true);
  }

  await refreshStatus();
  await refreshLogs();
  await loadPresets();
  syncModeVisibility();
  setInterval(refreshStatus, 5000);
  setInterval(refreshLogs, 5000);
})();

// ===========================================================================
// Cloud Sync — auth-aware version
// ===========================================================================

// ── Token storage (survives page refresh within the tab) ──────────────────
const CLOUD_TOKEN_KEY = 'vanish_cloud_token';
const CLOUD_USER_KEY = 'vanish_cloud_user';

function cloudGetToken() { return sessionStorage.getItem(CLOUD_TOKEN_KEY) || ''; }
function cloudGetUser() { return sessionStorage.getItem(CLOUD_USER_KEY) || ''; }
function cloudSaveSession(token, username) {
  sessionStorage.setItem(CLOUD_TOKEN_KEY, token);
  sessionStorage.setItem(CLOUD_USER_KEY, username);
}
function cloudClearSession() {
  sessionStorage.removeItem(CLOUD_TOKEN_KEY);
  sessionStorage.removeItem(CLOUD_USER_KEY);
}

// ── DOM references ────────────────────────────────────────────────────────
const cloudAuthPanel = document.getElementById('cloud-auth-panel');
const cloudUserBanner = document.getElementById('cloud-user-banner');
const cloudSyncPanels = document.getElementById('cloud-sync-panels');
const cloudUsernameDisplay = document.getElementById('cloud-username-display');
const cloudAuthUser = document.getElementById('cloud-auth-user');
const cloudAuthPass = document.getElementById('cloud-auth-pass');
const cloudAuthStatus = document.getElementById('cloud-auth-status');
const cloudLoginBtn = document.getElementById('cloud-login-btn');
const cloudRegisterBtn = document.getElementById('cloud-register-btn');
const cloudLogoutBtn = document.getElementById('cloud-logout-btn');
const cloudScanBtn = document.getElementById('cloud-scan-btn');
const cloudUploadBtn = document.getElementById('cloud-upload-btn');
const cloudListBtn = document.getElementById('cloud-list-btn');
const cloudRestoreBtn = document.getElementById('cloud-restore-btn');
const cloudSelectAll = document.getElementById('cloud-select-all-btn');
const cloudDeselectAll = document.getElementById('cloud-deselect-all-btn');
const cloudScanUser = document.getElementById('cloud-scan-user');
const cloudConfigName = document.getElementById('cloud-config-name');
const cloudScanResults = document.getElementById('cloud-scan-results');
const cloudEntriesList = document.getElementById('cloud-entries-list');
const cloudConfigsWrap = document.getElementById('cloud-configs-table-wrap');
const cloudConfigsBody = document.getElementById('cloud-configs-body');
const cloudRestoreId = document.getElementById('cloud-restore-id');
const cloudRestoreUser = document.getElementById('cloud-restore-user');
const cloudStatusBox = document.getElementById('cloud-status-box');
const cloudAtlasStatus = document.getElementById('cloud-atlas-status');
const cloudUploadOverlay = document.getElementById('cloud-upload-overlay');
const cloudUploadTitle = document.getElementById('cloud-upload-title');
const cloudUploadStage = document.getElementById('cloud-upload-stage');
const cloudUploadMeta = document.getElementById('cloud-upload-meta');
const cloudUploadProgressFill = document.getElementById('cloud-upload-progress-fill');
const cloudUploadProgressText = document.getElementById('cloud-upload-progress-text');
const cloudUploadEta = document.getElementById('cloud-upload-eta');
const cloudUploadElapsed = document.getElementById('cloud-upload-elapsed');

const CLOUD_UPLOAD_IDLE_LABEL = 'Upload Selected to Cloud';
const CLOUD_UPLOAD_BUSY_LABEL = 'Uploading…';

let cloudUploadOverlayTimer = null;
let cloudUploadOverlayStartedAt = 0;
let cloudUploadOverlayProgress = 0;
let cloudBusy = false;
let cloudUploadEnabledBySelection = false;

// ── Helpers ───────────────────────────────────────────────────────────────
function cloudLog(msg, isError = false) {
  const ts = new Date().toLocaleTimeString();
  cloudStatusBox.textContent = `[${ts}] ${msg}`;
  cloudStatusBox.style.color = isError ? '#e05c5c' : '';
  if (isError) {
    console.error(`[Cloud] ${msg}`);
  }
}

function cloudAuthLog(msg, isError = false) {
  cloudAuthStatus.textContent = msg;
  cloudAuthStatus.style.color = isError ? '#e05c5c' : '';
  if (isError) {
    console.error(`[Cloud Auth] ${msg}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function fmtDuration(totalSeconds) {
  const secs = Math.max(0, Math.floor(totalSeconds || 0));
  const mm = String(Math.floor(secs / 60)).padStart(2, '0');
  const ss = String(secs % 60).padStart(2, '0');
  return `${mm}:${ss}`;
}

function fmtSizeShort(sizeMb) {
  const num = Number(sizeMb);
  if (!Number.isFinite(num) || num <= 0) return '0 MB';
  if (num >= 1024) return `${(num / 1024).toFixed(2)} GB`;
  return `${num.toFixed(2)} MB`;
}

function syncCloudUploadButtonState() {
  cloudUploadBtn.disabled = cloudBusy || !cloudUploadEnabledBySelection;
  cloudUploadBtn.textContent = cloudBusy ? CLOUD_UPLOAD_BUSY_LABEL : CLOUD_UPLOAD_IDLE_LABEL;
}

function refreshCloudSelectionState() {
  const checks = [...document.querySelectorAll('.cloud-entry-check')];
  const checkedCount = checks.filter(cb => cb.checked).length;
  cloudUploadEnabledBySelection = checks.length > 0 && checkedCount > 0;
  syncCloudUploadButtonState();
}

function cloudSetBusy(busy) {
  cloudBusy = Boolean(busy);
  syncCloudUploadButtonState();
  cloudScanBtn.disabled = busy;
  cloudListBtn.disabled = busy;
  cloudRestoreBtn.disabled = busy;
}

function showCloudUploadOverlay(title = 'Uploading Config to Cloud', details = {}) {
  const pathsCount = Number(details.pathsCount) || 0;
  const selectedSizeMb = Number(details.selectedSizeMb) || 0;
  const pathLabel = pathsCount === 1 ? '1 path' : `${pathsCount} paths`;
  cloudUploadTitle.textContent = title;
  cloudUploadStage.textContent = 'Preparing upload…';
  cloudUploadMeta.textContent = `Selected: ${pathLabel} • Approx size: ${fmtSizeShort(selectedSizeMb)}`;
  cloudUploadProgressFill.style.width = '0%';
  cloudUploadProgressText.textContent = '0%';
  cloudUploadEta.textContent = 'ETA: calculating…';
  cloudUploadElapsed.textContent = 'Elapsed: 00:00';
  cloudUploadOverlayProgress = 0;
  cloudUploadOverlayStartedAt = Date.now();
  if (cloudUploadOverlayTimer) {
    clearInterval(cloudUploadOverlayTimer);
  }
  cloudUploadOverlayTimer = setInterval(() => {
    if (!cloudUploadOverlayStartedAt) return;
    const elapsed = Math.floor((Date.now() - cloudUploadOverlayStartedAt) / 1000);
    cloudUploadElapsed.textContent = `Elapsed: ${fmtDuration(elapsed)}`;
    if (cloudUploadOverlayProgress > 0 && cloudUploadOverlayProgress < 100) {
      const etaSec = Math.ceil((elapsed * (100 - cloudUploadOverlayProgress)) / cloudUploadOverlayProgress);
      cloudUploadEta.textContent = `ETA: ${fmtDuration(etaSec)}`;
    }
  }, 1000);
  cloudUploadOverlay.classList.remove('hidden');
}

function updateCloudUploadOverlay(progress, stage) {
  const bounded = Math.max(0, Math.min(100, Number(progress) || 0));
  cloudUploadOverlayProgress = bounded;
  cloudUploadProgressFill.style.width = `${bounded}%`;
  cloudUploadProgressText.textContent = `${Math.round(bounded)}%`;
  if (stage) cloudUploadStage.textContent = stage;
  if (bounded >= 100) cloudUploadEta.textContent = 'ETA: complete';
}

function hideCloudUploadOverlay() {
  if (cloudUploadOverlayTimer) {
    clearInterval(cloudUploadOverlayTimer);
    cloudUploadOverlayTimer = null;
  }
  cloudUploadOverlayStartedAt = 0;
  cloudUploadOverlay.classList.add('hidden');
}

function fmtTs(unix) {
  if (!unix) return '—';
  return new Date(unix * 1000).toLocaleString();
}

/** Returns fetch options with the cloud auth token header already set. */
function cloudFetchOpts(extra = {}) {
  const token = cloudGetToken();
  return {
    ...extra,
    headers: {
      'Content-Type': 'application/json',
      'X-Cloud-Token': token,
      ...(extra.headers || {}),
    },
  };
}

// ── UI state: show/hide panels based on login status ─────────────────────
function applyCloudLoginState(loggedIn, username = '') {
  if (loggedIn) {
    cloudAuthPanel.classList.add('hidden');
    cloudUserBanner.classList.remove('hidden');
    cloudSyncPanels.classList.remove('hidden');
    cloudUsernameDisplay.textContent = username;
    listCloudConfigs();    // auto-load user's configs on login
  } else {
    cloudAuthPanel.classList.remove('hidden');
    cloudUserBanner.classList.add('hidden');
    cloudSyncPanels.classList.add('hidden');
    cloudUsernameDisplay.textContent = '';
  }
}

// ── Atlas status pill ─────────────────────────────────────────────────────
async function checkAtlasStatus() {
  try {
    const data = await getJSON('/api/health');
    const storageReady = (
      data.supabase_configured !== undefined
        ? Boolean(data.supabase_configured)
        : ((data.cloudinary_configured === undefined) ? true : Boolean(data.cloudinary_configured))
    );
    if (data.atlas_configured && storageReady) {
      cloudAtlasStatus.textContent = '✓ Atlas Connected';
      cloudAtlasStatus.style.background = 'rgba(80,200,120,0.15)';
      cloudAtlasStatus.style.color = '#50c878';
      cloudAtlasStatus.title = 'MongoDB Atlas + Supabase Storage reachable/configured';
    } else {
      cloudAtlasStatus.textContent = '✗ Atlas Not Connected';
      cloudAtlasStatus.style.background = 'rgba(224,92,92,0.15)';
      cloudAtlasStatus.style.color = '#e05c5c';
      const reason = data.atlas_error || data.supabase_error || data.cloudinary_error || 'Atlas/Cloud storage is not configured or unreachable.';
      cloudAtlasStatus.title = reason;
      console.error(`[Atlas] ${reason}`);
    }
  } catch (_) {
    cloudAtlasStatus.textContent = '? Unknown';
    cloudAtlasStatus.title = 'Failed to load Atlas health status';
    console.error('[Atlas] Failed to load Atlas health status.');
  }
}

// Restore login state if a token is stored from earlier in this tab session.
async function restoreCloudSession() {
  const token = cloudGetToken();
  if (!token) { applyCloudLoginState(false); return; }
  try {
    const data = await getJSON('/api/cloud/me', cloudFetchOpts());
    if (data.logged_in) {
      cloudSaveSession(token, data.username);
      applyCloudLoginState(true, data.username);
    } else {
      cloudClearSession();
      applyCloudLoginState(false);
    }
  } catch (_) {
    applyCloudLoginState(false);
  }
}

// ── Auth actions ──────────────────────────────────────────────────────────
async function cloudRegister() {
  const username = cloudAuthUser.value.trim();
  const password = cloudAuthPass.value;
  if (!username || !password) { cloudAuthLog('Enter username and password.', true); return; }

  cloudAuthLog('Creating account…');
  try {
    const data = await getJSON('/api/cloud/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    cloudAuthLog(`✓ ${data.message}. You can now log in.`);
  } catch (err) {
    cloudAuthLog(`Registration failed: ${err.message}`, true);
  }
}

async function cloudLogin() {
  const username = cloudAuthUser.value.trim();
  const password = cloudAuthPass.value;
  if (!username || !password) { cloudAuthLog('Enter username and password.', true); return; }

  cloudAuthLog('Logging in…');
  try {
    const data = await getJSON('/api/cloud/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    cloudSaveSession(data.token, data.username);
    applyCloudLoginState(true, data.username);
    cloudAuthLog(`✓ ${data.message}`);
    cloudAuthPass.value = '';
  } catch (err) {
    cloudAuthLog(`Login failed: ${err.message}`, true);
  }
}

async function cloudLogout() {
  const token = cloudGetToken();
  try {
    await getJSON('/api/cloud/logout', cloudFetchOpts({ method: 'POST' }));
  } catch (_) { /* ignore */ }
  cloudClearSession();
  applyCloudLoginState(false);
  cloudAuthLog('Logged out.');
}

// ── Cloud Sync actions ────────────────────────────────────────────────────
async function scanUserForCloud() {
  const username = cloudScanUser.value.trim();
  if (!username) { cloudLog('Enter a session username to scan.', true); return; }

  cloudLog(`Scanning /home/${username}…`);
  cloudUploadEnabledBySelection = false;
  syncCloudUploadButtonState();
  cloudScanResults.classList.add('hidden');

  try {
    const data = await getJSON(
      `/api/cloud/scan?username=${encodeURIComponent(username)}`,
      cloudFetchOpts(),
    );
    renderCloudScanResults(data.entries || []);
    cloudLog(`Found ${data.entries.length} path(s) in /home/${username}.`);
  } catch (err) {
    cloudLog(`Scan failed: ${err.message}`, true);
  }
}

function renderCloudScanResults(entries) {
  if (!entries.length) {
    cloudEntriesList.innerHTML = '<p style="opacity:.6;font-size:.85em;">No data found in this user\'s home directory.</p>';
    cloudScanResults.classList.remove('hidden');
    cloudUploadEnabledBySelection = false;
    syncCloudUploadButtonState();
    return;
  }
  cloudEntriesList.innerHTML = entries.map((e, i) => `
    <label class="cloud-entry">
      <input type="checkbox" class="cloud-entry-check" data-rel="${e.rel_path}" data-idx="${i}" data-size-mb="${Number(e.size_mb) || 0}" checked>
      <span class="cloud-entry-label">${e.label}</span>
      <span class="cloud-badge ${e.is_known ? 'known' : 'generic'}">${e.is_known ? 'Known' : 'Generic'}</span>
      <span class="cloud-entry-path">${e.rel_path}</span>
      <span class="cloud-entry-size">${e.size_mb} MB</span>
    </label>`).join('');
  cloudScanResults.classList.remove('hidden');
  document.querySelectorAll('.cloud-entry-check').forEach((cb) => {
    cb.addEventListener('change', refreshCloudSelectionState);
  });
  refreshCloudSelectionState();
}

async function uploadSelectedPaths() {
  const username = cloudScanUser.value.trim();
  const configName = cloudConfigName.value.trim() || `${username}-backup`;
  const checked = [...document.querySelectorAll('.cloud-entry-check:checked')];
  const paths = checked.map(cb => cb.dataset.rel);
  const selectedSizeMb = checked.reduce((sum, cb) => sum + (Number(cb.dataset.sizeMb) || 0), 0);
  const token = cloudGetToken();

  if (!paths.length) { cloudLog('Select at least one path to upload.', true); return; }

  cloudLog(`Preparing upload for ${paths.length} path(s) (about ${fmtSizeShort(selectedSizeMb)})…`);
  showCloudUploadOverlay('Uploading Config to Cloud', {
    pathsCount: paths.length,
    selectedSizeMb,
  });
  updateCloudUploadOverlay(2, 'Starting upload job…');
  cloudSetBusy(true);

  try {
    let start;
    try {
      start = await getJSON('/api/cloud/upload/start', cloudFetchOpts({
        method: 'POST',
        body: JSON.stringify({ username, paths, config_name: configName, token }),
      }));
    } catch (startErr) {
      // Backward-compatible fallback for older backend instances.
      if ((startErr.message || '').toLowerCase().includes('not found')) {
        cloudLog('Async upload endpoint unavailable; falling back to direct upload mode.');
        updateCloudUploadOverlay(40, 'Uploading directly (fallback mode)…');
        const direct = await getJSON('/api/cloud/upload', cloudFetchOpts({
          method: 'POST',
          body: JSON.stringify({ username, paths, config_name: configName, token }),
        }));
        updateCloudUploadOverlay(100, 'Upload complete.');
        cloudLog(`✓ Upload complete. Config ID: ${direct.config_id}  (${direct.message || 'Saved to cloud.'})`);
        cloudRestoreId.value = direct.config_id || '';
        await listCloudConfigs();
        return;
      }
      throw startErr;
    }
    const jobId = start.job_id;
    if (!jobId) {
      throw new Error('Upload job started but no job_id was returned.');
    }

    cloudLog(`Upload job ${jobId.slice(0, 8)}… started.`);

    const maxPolls = 1200; // up to ~40 minutes
    let finalData = null;
    for (let i = 0; i < maxPolls; i += 1) {
      const status = await getJSON(
        `/api/cloud/upload/status?job_id=${encodeURIComponent(jobId)}`,
        cloudFetchOpts(),
      );
      updateCloudUploadOverlay(status.progress, status.stage || 'Uploading…');

      if (status.status === 'completed') {
        finalData = status;
        break;
      }
      if (status.status === 'failed') {
        throw new Error(status.error || 'Upload failed.');
      }
      await sleep(2000);
    }

    if (!finalData) {
      throw new Error('Upload timed out while waiting for completion. Please check cloud status and retry.');
    }

    updateCloudUploadOverlay(100, finalData.stage || 'Upload complete.');
    cloudLog(`✓ Upload complete. Config ID: ${finalData.config_id}  (${finalData.message || 'Saved to Atlas.'})`);
    cloudRestoreId.value = finalData.config_id || '';
    await listCloudConfigs();
  } catch (err) {
    updateCloudUploadOverlay(100, `Upload failed: ${err.message}`);
    cloudLog(`Upload failed: ${err.message}`, true);
    await sleep(1600);
  } finally {
    hideCloudUploadOverlay();
    cloudSetBusy(false);
  }
}

async function listCloudConfigs() {
  cloudLog('Fetching your saved configs from Atlas…');
  try {
    const data = await getJSON('/api/cloud/list', cloudFetchOpts());
    renderCloudConfigs(data.configs || []);
    if (!data.configs || data.configs.length === 0) {
      cloudLog(`${data.message || '0 configs found.'} If you just uploaded, refresh once after 2-3 seconds.`, true);
    } else {
      cloudLog(data.message || 'Config list refreshed.');
    }
  } catch (err) {
    cloudLog(`List failed: ${err.message}`, true);
  }
}

function renderCloudConfigs(configs) {
  cloudConfigsWrap.classList.remove('hidden');
  if (!configs.length) {
    cloudConfigsBody.innerHTML = '<tr><td colspan="5" style="opacity:.6;">No configs stored yet. Upload one above.</td></tr>';
    return;
  }
  cloudConfigsBody.innerHTML = configs.map(c => `
    <tr>
      <td>${c.config_name}</td>
      <td>${c.username || '—'}</td>
      <td>${c.total_size_mb}</td>
      <td>${fmtTs(c.timestamp)}</td>
      <td>
        <span class="cloud-id-chip" title="${c.config_id}">${c.config_id.slice(0, 8)}…</span>
        <button class="btn ghost mini" onclick="copyToClipboard('${c.config_id}')">Copy</button>
        <button class="btn ghost mini" onclick="prefillRestore('${c.config_id}')">Use</button>
        <button class="btn danger mini" onclick="deleteCloudConfig('${c.config_id}')">Delete</button>
      </td>
    </tr>`).join('');
}

function prefillRestore(configId) {
  cloudRestoreId.value = configId;
  cloudRestoreUser.focus();
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => cloudLog(`Copied ${text} to clipboard.`));
}

async function deleteCloudConfig(config_id) {
  const token = cloudGetToken();
  const cfgId = String(config_id || '').trim();
  if (!cfgId) {
    cloudLog('Cannot delete: missing config ID.', true);
    return;
  }
  if (!window.confirm(`Delete config "${cfgId}" from Supabase Storage + MongoDB Atlas? This cannot be undone.`)) return;

  cloudLog(`Deleting config ${cfgId.slice(0, 8)}… from cloud storage…`);
  cloudSetBusy(true);
  try {
    const data = await getJSON('/api/cloud/delete', cloudFetchOpts({
      method: 'POST',
      body: JSON.stringify({ config_id: cfgId, token }),
    }));
    cloudLog(`✓ ${data.message || `Deleted ${cfgId}.`}`);
    if (cloudRestoreId.value.trim() === cfgId) {
      cloudRestoreId.value = '';
    }
    await listCloudConfigs();
  } catch (err) {
    cloudLog(`Delete failed: ${err.message}`, true);
  } finally {
    cloudSetBusy(false);
  }
}

async function restoreCloudConfig() {
  const config_id = cloudRestoreId.value.trim();
  const target_username = cloudRestoreUser.value.trim();
  const token = cloudGetToken();

  if (!config_id || !target_username) {
    cloudLog('Enter both a Config ID and Target Username.', true);
    return;
  }
  if (!window.confirm(`Restore config "${config_id}" into /home/${target_username}? Existing files may be overwritten.`)) return;

  cloudLog(`Downloading and restoring into /home/${target_username}…`);
  cloudRestoreBtn.disabled = true;

  try {
    const data = await getJSON('/api/cloud/restore', cloudFetchOpts({
      method: 'POST',
      body: JSON.stringify({ config_id, target_username, token }),
    }));
    cloudLog(`✓ ${data.message}`);
  } catch (err) {
    cloudLog(`Restore failed: ${err.message}`, true);
  } finally {
    cloudRestoreBtn.disabled = false;
  }
}

// ── Event listeners ───────────────────────────────────────────────────────
cloudLoginBtn.addEventListener('click', cloudLogin);
cloudRegisterBtn.addEventListener('click', cloudRegister);
cloudLogoutBtn.addEventListener('click', cloudLogout);

// Allow Enter key in auth fields to trigger login.
[cloudAuthUser, cloudAuthPass].forEach(el =>
  el.addEventListener('keydown', e => { if (e.key === 'Enter') cloudLogin(); })
);

cloudScanBtn.addEventListener('click', scanUserForCloud);
cloudUploadBtn.addEventListener('click', uploadSelectedPaths);
cloudListBtn.addEventListener('click', listCloudConfigs);
cloudRestoreBtn.addEventListener('click', restoreCloudConfig);
cloudSelectAll.addEventListener('click', () =>
  document.querySelectorAll('.cloud-entry-check').forEach(cb => { cb.checked = true; })
);
cloudDeselectAll.addEventListener('click', () =>
  document.querySelectorAll('.cloud-entry-check').forEach(cb => { cb.checked = false; })
);
cloudSelectAll.addEventListener('click', refreshCloudSelectionState);
cloudDeselectAll.addEventListener('click', refreshCloudSelectionState);

// Convenience: clicking Config in the sessions table pre-fills the scan user field.
sessionsBody.addEventListener('click', (event) => {
  const target = event.target;
  if (target instanceof HTMLElement && target.dataset.action === 'view-config') {
    cloudScanUser.value = target.dataset.user || '';
  }
});

// ── Initialise ────────────────────────────────────────────────────────────
checkAtlasStatus();
restoreCloudSession();    // restore login state if token still valid
syncCloudUploadButtonState();
