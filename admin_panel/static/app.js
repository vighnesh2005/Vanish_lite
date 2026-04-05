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
    const message = data.error || data.stderr || data.stdout || `Request failed: ${res.status}`;
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
