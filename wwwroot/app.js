'use strict';

/* ============================================================
   Helpers
   ============================================================ */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const fmtBytes = (n) => {
  if (!n) return '0 MB';
  const gb = n / 1073741824;
  if (gb >= 1) return `${gb.toFixed(gb >= 10 ? 0 : 1)} GB`;
  const mb = n / 1048576;
  return `${mb >= 10 ? mb.toFixed(0) : mb.toFixed(1)} MB`;
};
const fmtMb = (mb) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${Math.round(mb)} MB`);
const fmtDate = (iso) => {
  if (!iso) return 'Unknown';
  const d = new Date(iso);
  if (isNaN(d) || d.getFullYear() < 1990) return 'Unknown';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
};
const fmtDateTime = (iso) => {
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
};
const fmtUptime = (s) => {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
};
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const loadLevel = (p) => (p >= 85 ? 'bad' : p >= 65 ? 'attn' : 'ok');
const LEVEL_COLOR = { ok: '#34e0a1', attn: '#ffb547', bad: '#ff5d6c' };
const METRIC_COLOR = { cpu: '#38c8ff', gpu: '#a78bfa', ram: '#34e0a1', disk: '#ffb547' };
/** The metric's own colour, turning amber then red under heavy load. */
const metricColor = (m, p) => (p >= 90 ? LEVEL_COLOR.bad : p >= 75 ? LEVEL_COLOR.attn : METRIC_COLOR[m]);

/* ============================================================
   Bridge to C#
   ============================================================ */

const hasHost = !!(window.chrome && window.chrome.webview);
const pending = new Map();
const listeners = {};
let seq = 0;

function call(cmd, args = {}) {
  if (!hasHost) return Promise.reject(new Error('Open this page inside SystemForge.'));
  return new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    window.chrome.webview.postMessage({ id, cmd, args });
  });
}

function on(name, fn) { (listeners[name] ??= []).push(fn); }

if (hasHost) {
  window.chrome.webview.addEventListener('message', (e) => {
    const m = e.data;
    if (m.type === 'reply') {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      m.ok ? p.resolve(m.data) : p.reject(new Error(m.error));
    } else if (m.type === 'event') {
      (listeners[m.name] || []).forEach((fn) => fn(m.data));
    }
  });
}

/* ============================================================
   UI primitives
   ============================================================ */

function toast(message, bad = false) {
  const el = document.createElement('div');
  el.className = `toast${bad ? ' bad' : ''}`;
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), 5000);
}

function confirmBox(title, body, okLabel, danger = false) {
  const d = $('#confirm');
  $('#confirmTitle').textContent = title;
  $('#confirmBody').textContent = body;
  const ok = $('#confirmOk');
  ok.textContent = okLabel;
  ok.className = `btn ${danger ? 'danger armed' : 'primary'}`;
  d.returnValue = '';
  d.showModal();
  return new Promise((resolve) => d.addEventListener('close', () => resolve(d.returnValue === 'ok'), { once: true }));
}

/** A dialog with a single OK button, for explaining why something can't be done. */
function alertBox(title, body) {
  const cancel = $('#confirmCancel');
  cancel.hidden = true;
  return confirmBox(title, body, 'OK').finally(() => { cancel.hidden = false; });
}

function empty(title, body, action = '') {
  return `<div class="empty"><strong>${esc(title)}</strong>${esc(body)}${action ? `<div style="margin-top:18px">${action}</div>` : ''}</div>`;
}

async function withBusy(button, busyLabel, work) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = busyLabel;
  try { return await work(); }
  finally { button.disabled = false; button.textContent = label; }
}

/* ============================================================
   State and navigation
   ============================================================ */

const state = {
  page: 'overview',
  info: null,
  snap: null,
  history: { cpu: [], gpu: [], ram: [] },
  disks: null,
  checks: {
    drivers: { level: '', title: 'Drivers', detail: 'Not checked yet.', page: 'drivers' },
    cleanup: { level: 'busy', title: 'Cleanup', detail: 'Measuring leftover files…', page: 'cleanup' },
    apps: { level: '', title: 'App updates', detail: 'Not checked yet.', page: 'apps' },
    security: { level: 'busy', title: 'Security', detail: 'Checking protection…', page: 'security' },
    startup: { level: 'busy', title: 'Startup apps', detail: 'Counting…', page: 'startup' },
    drives: { level: 'busy', title: 'Drive health', detail: 'Reading drives…', page: null },
  },
  drivers: { tab: 'updates', installed: null, check: null, checking: false, checkedAt: null, selected: new Set(),
             installing: false, progress: null, results: null, backups: null, query: '', cls: '', scan: null, groupsOpen: {} },
  apps2: { tab: 'updates', check: null, checking: false, selected: new Set(), installing: false, progress: null, results: null, query: '', showIgnored: false },
  sec: { status: null, scan: null, scanning: false, progress: null, selected: new Set(), tab: 'findings', history: null,
         applying: false, applyProgress: null, results: null, busy: '', query: '', onlyConcerning: true, open: new Set() },
  junk: { cats: null, selected: new Set(), scanning: false, excluded: new Map(), view: null },
  startup: { items: null, query: '' },
  apps: { list: null, armed: null, armedTimer: null },
  game: { status: null, candidates: null, picking: false },
  temps: { report: null, installing: false, progress: null, showAll: false },
};

const onEnter = {
  drivers: () => { if (!state.drivers.installed) scanDevices(); renderDrivers(); },
  apps: () => { if (!state.apps2.check && !state.apps2.checking) loadLastApps(); else renderApps2(); },
  security: () => { if (!state.sec.status) loadSecurityStatus(); renderSecurity(); if (!state.sec.scan && !state.sec.scanning) loadLastSecurityScan(); },
  cleanup: () => { if (!state.junk.cats && !state.junk.scanning) scanJunk(); else renderJunk(); },
  startup: () => { if (!state.startup.items) loadStartup(); else renderStartup(); },
  performance: () => { loadApps(); drawCharts(); loadGame(); loadTemps(); },
  settings: () => { renderSettings(); renderUpdates(); if (!state.selfUpdate.check) call('app.lastUpdate').then((r) => { if (r) { state.selfUpdate.check = r; renderUpdates(); } }).catch(() => {}); },
};

function go(page) {
  state.page = page;
  $$('.nav-item').forEach((b) => (b.dataset.page === page ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current')));
  $$('.page').forEach((p) => (p.hidden = p.id !== `page-${page}`));
  $('#main').scrollTop = 0;
  onEnter[page]?.();
}

$$('.nav-item').forEach((b) => b.addEventListener('click', () => go(b.dataset.page)));

/* ============================================================
   Overview: gauges, checkup, specs
   ============================================================ */

const G = { cx: 100, cy: 96, r: 82, start: 210, sweep: 240 };

function polar(r, deg) {
  const a = (deg * Math.PI) / 180;
  return [G.cx + r * Math.cos(a), G.cy - r * Math.sin(a)];
}

/** SVG arc along the dial from one percentage to another, at radius r. */
function dialArc(r, from = 0, to = 100) {
  const a1 = G.start - (G.sweep * from) / 100;
  const a2 = G.start - (G.sweep * to) / 100;
  const [sx, sy] = polar(r, a1);
  const [ex, ey] = polar(r, a2);
  const large = a1 - a2 > 180 ? 1 : 0;
  return `M${sx.toFixed(2)} ${sy.toFixed(2)} A${r} ${r} 0 ${large} 1 ${ex.toFixed(2)} ${ey.toFixed(2)}`;
}

function buildGauge(el, label) {
  const id = el.id;
  const arc = dialArc(G.r);
  let ticks = '';
  for (let i = 0; i <= 20; i++) {
    const deg = G.start - (G.sweep * i) / 20;
    const major = i % 5 === 0;
    const [x1, y1] = polar(G.r - 17, deg);
    const [x2, y2] = polar(G.r - (major ? 29 : 23), deg);
    ticks += `<line class="tick${major ? ' major' : ''}" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"/>`;
  }
  const tipY = G.cy - (G.r - 20);
  el.innerHTML = `
    <svg viewBox="0 0 200 140" aria-hidden="true">
      <defs>
        <linearGradient id="${id}-grad" gradientUnits="userSpaceOnUse" x1="14" y1="0" x2="186" y2="0">
          <stop offset="0" stop-color="#4fd1b4"/>
          <stop offset="0.55" stop-color="#e0a943"/>
          <stop offset="0.9" stop-color="#ef6a4c"/>
        </linearGradient>
        <filter id="${id}-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="5"/>
        </filter>
      </defs>
      <path class="bezel" d="${dialArc(G.r + 10)}"/>
      <path class="track" d="${arc}"/>
      <path class="bezel-inner" d="${dialArc(G.r - 7)}"/>
      <path class="redline" d="${dialArc(G.r - 12, 85, 100)}"/>
      <path class="fill-glow" d="${arc}" pathLength="100" stroke-dasharray="100" stroke-dashoffset="100"
            stroke="url(#${id}-grad)" filter="url(#${id}-glow)"/>
      <path class="fill" d="${arc}" pathLength="100" stroke-dasharray="100" stroke-dashoffset="100" stroke="url(#${id}-grad)"/>
      ${ticks}
      <path class="needle" d="M${G.cx} ${tipY} L${G.cx + 3.4} ${G.cy} L${G.cx} ${G.cy + 15} L${G.cx - 3.4} ${G.cy} Z"
            style="transform: rotate(-120deg)"/>
      <circle class="hub" cx="${G.cx}" cy="${G.cy}" r="8"/>
      <circle class="hub-cap" cx="${G.cx}" cy="${G.cy}" r="3"/>
    </svg>
    <div class="reading"><span class="v">0</span><small>%</small></div>
    <figcaption>${esc(label)}</figcaption>
    <div class="sub">&nbsp;</div>`;
}

function setGauge(el, pct, sub) {
  const p = Math.max(0, Math.min(100, pct || 0));
  for (const f of el.querySelectorAll('.fill, .fill-glow')) f.style.strokeDashoffset = String(100 - p);
  el.style.setProperty('--lvl', LEVEL_COLOR[loadLevel(p)]);
  el.querySelector('.needle').style.transform = `rotate(${-120 + 2.4 * p}deg)`;
  el.querySelector('.v').textContent = Math.round(p);
  if (sub !== undefined) el.querySelector('.sub').textContent = sub;
}

/** Start-up sweep: needles swing to the top of the dial and settle on the live reading, like a car's cluster. */
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function sweepGauges() {
  if (reduceMotion) return;
  state.sweepUntil = Date.now() + 1300;
  const gauges = ['#gCpu', '#gGpu', '#gRam', '#gDisk'].map((s) => $(s));
  requestAnimationFrame(() => gauges.forEach((g, i) => setTimeout(() => setGauge(g, 100), i * 90)));
  setTimeout(() => renderSnapshot(), 1350);
}

buildGauge($('#gCpu'), 'Processor');
buildGauge($('#gGpu'), 'Graphics');
buildGauge($('#gRam'), 'Memory');
buildGauge($('#gDisk'), 'System drive');

function renderSnapshot() {
  const s = state.snap;
  if (!s) return;
  const sweeping = state.sweepUntil && Date.now() < state.sweepUntil;
  if (!sweeping) {
    const threads = state.info?.system?.threads;
    const withTemp = (text, c) => [text, c != null ? fmtTemp(c) : ''].filter(Boolean).join(' · ');
    setGauge($('#gCpu'), s.cpu, withTemp(threads ? `${threads} threads` : '', s.cpuTempC));
    const gpuName = (state.info?.system?.gpu || '').split(' + ').pop().replace(/^NVIDIA |^AMD |^Intel\(R\) /, '');
    setGauge($('#gGpu'), s.gpu, withTemp(gpuName, s.gpuTempC));
    setGauge($('#gRam'), s.ramPercent, `${s.ramUsedGb.toFixed(1)} of ${Math.round(s.ramTotalGb)} GB in use`);
    const sys = s.volumes.find((v) => v.isSystem) || s.volumes[0];
    if (sys) setGauge($('#gDisk'), sys.usedPercent, `${Math.round(sys.freeGb)} GB free of ${Math.round(sys.totalGb)} GB on ${sys.name}`);
  }

  if (state.info) {
    $('#ovGreeting').textContent = `Live readings from ${state.info.system.machineName}, up for ${fmtUptime(s.uptimeSeconds)}.`;
    const up = $('#specUptime');
    if (up) up.textContent = fmtUptime(s.uptimeSeconds);
  }
  $('#cpuNow').textContent = `${Math.round(s.cpu)}%`;
  $('#gpuNow').textContent = `${Math.round(s.gpu)}%`;
  $('#ramNow').textContent = `${Math.round(s.ramPercent)}%`;
}

function renderSpecs() {
  const sys = state.info?.system;
  if (!sys) return;
  const rows = [
    ['Windows', `${sys.os} (build ${sys.build})`],
    ['Processor', sys.cpu],
    ['Graphics', sys.gpu],
    ['Memory', `${Math.round(sys.ramGb)} GB`],
  ];
  $('#specs').innerHTML =
    rows.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('') +
    `<div><dt>Uptime</dt><dd id="specUptime">…</dd></div>`;
}

function setCheck(key, level, detail) {
  Object.assign(state.checks[key], { level, detail });
  renderChecks();
}

function renderChecks() {
  $('#checkList').innerHTML = Object.entries(state.checks).map(([key, c]) => `
    <li>
      <span class="dot ${c.level}" aria-hidden="true"></span>
      <div class="stack">
        <span class="check-title">${esc(c.title)}</span>
        <span class="check-detail">${esc(c.detail)}</span>
      </div>
      ${c.page ? `<button class="btn small" data-go="${c.page}">Open</button>` : ''}
    </li>`).join('');
  $$('#checkList [data-go]').forEach((b) => b.addEventListener('click', () => go(b.dataset.go)));
}

function summarizeDrivers() {
  const d = state.drivers;
  if (d.checking) return setCheck('drivers', 'busy', 'Checking Windows Update, the catalog, NVIDIA and winget…');
  if (!d.check) return setCheck('drivers', '', 'Not checked yet.');
  const n = visibleOffers().length;
  const badge = $('#navDriversBadge');
  badge.hidden = n === 0;
  badge.textContent = n;
  setCheck('drivers', n ? 'attn' : 'ok', n ? `${plural(n, 'update')} available for drivers and game components.` : 'Every driver and game component is up to date.');
}

function summarizeJunk() {
  const cats = state.junk.cats;
  if (!cats) return;
  const bytes = cats.filter((c) => c.defaultOn).reduce((s, c) => s + c.bytes, 0);
  setCheck('cleanup', bytes > 500 * 1048576 ? 'attn' : 'ok',
    bytes > 0 ? `${fmtBytes(bytes)} of leftover files can be removed.` : 'Nothing worth cleaning right now.');
}

function summarizeStartup() {
  const items = state.startup.items;
  if (!items) return;
  const on = items.filter((i) => i.enabled).length;
  setCheck('startup', on > 10 ? 'attn' : 'ok',
    `${plural(on, 'app')} start${on === 1 ? 's' : ''} when you sign in${on > 10 ? '. Turning some off speeds up boot.' : '.'}`);
}

function summarizeDisks() {
  const disks = state.disks;
  if (!disks) return;
  if (!disks.length) return setCheck('drives', '', "Windows didn't report drive health.");
  const bad = disks.filter((d) => d.health === 'Unhealthy');
  const warn = disks.filter((d) => d.health === 'Warning' || (d.wearPercent ?? 0) >= 80);
  const temps = disks.map((d) => d.temperatureC).filter(Boolean);
  const hottest = temps.length ? ` Hottest is ${Math.max(...temps)} °C.` : '';
  const names = (list) => list.map((d) => d.name).join(', ');
  if (bad.length) return setCheck('drives', 'bad', `${names(bad)} is failing. Back up anything important on it now.`);
  if (warn.length) return setCheck('drives', 'attn', `${names(warn)} is wearing out or reporting warnings.${hottest}`);
  setCheck('drives', 'ok', `${disks.length === 1 ? 'Your drive is' : `All ${disks.length} drives are`} healthy.${hottest}`);
}

$('#btnCheckup').addEventListener('click', (e) => withBusy(e.currentTarget, 'Checking…', () =>
  Promise.allSettled([checkDrivers(), checkApps(), loadSecurityStatus(), scanJunk(), loadStartup(), loadDisks()])));

async function loadDisks() {
  try { state.disks = await call('health.disks'); } catch { state.disks = []; }
  summarizeDisks();
}

/* ============================================================
   Drivers
   ============================================================ */

$$('#page-drivers .tab').forEach((t) => t.addEventListener('click', () => {
  state.drivers.tab = t.dataset.tab;
  $$('#page-drivers .tab').forEach((x) => x.setAttribute('aria-selected', String(x === t)));
  $$('#page-drivers .tabpanel').forEach((p) => (p.hidden = p.dataset.panel !== t.dataset.tab));
  if (t.dataset.tab === 'backups') loadBackups();
  renderDrivers();
}));

$('#btnDrvCheck').addEventListener('click', () => checkDrivers());

// Buttons inside the install results (rendered in several states, so handled once here).
$('#drvUpdates').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-act="undo"], [data-act="enable-restore"]');
  if (!b) return;
  if (b.dataset.act === 'undo') {
    const ok = await confirmBox('Open System Restore?',
      'Pick the restore point named "SystemForge driver update" from just before the install. Your files and documents are not affected, only drivers, apps and settings changed since then. Your PC restarts to finish.',
      'Open System Restore');
    if (ok) call('system.openRestore').catch((err) => toast(err.message, true));
  } else {
    await withBusy(b, 'Turning on…', async () => {
      try {
        toast((await call('drivers.enableRestore')).message);
        state.drivers.results = null;
        renderDrivers();
      } catch (err) { toast(err.message, true); }
    });
  }
}, true);

/** Mirrors DriverGuard.cs: devices Windows needs to start, plus firmware and the TPM. */
const CRITICAL_CLASSES = ['scsiadapter', 'hdc', 'diskdrive', 'volume', 'volumesnapshot', 'system', 'computer', 'processor', 'firmware', 'securitydevices'];
const isCriticalClass = (c) => CRITICAL_CLASSES.includes((c || '').toLowerCase());
const advanced = () => !!state.info?.settings?.advancedDrivers;
/** What the current mode lets the user see and pick. */
const visibleOffers = () => (state.drivers.check?.offers || []).filter((o) => o.manual || advanced() || (!o.critical && o.group !== 'unplugged'));

const SOURCE = {
  wu: ['src-wu', 'Windows Update'],
  catalog: ['src-catalog', 'Update Catalog'],
  nvidia: ['src-nvidia', 'NVIDIA'],
  amd: ['src-amd', 'AMD'],
  intel: ['src-intel', 'Intel'],
  oem: ['src-oem', 'PC maker'],
  winget: ['src-winget', 'winget'],
};
const SOURCE_NAME = { wu: 'Windows Update', catalog: 'Microsoft Update Catalog', nvidia: 'NVIDIA', amd: 'AMD', intel: 'Intel', oem: 'PC maker (BIOS)', winget: 'winget (game components)' };
const GROUPS = [
  { id: 'device', title: 'Device drivers', on: true },
  { id: 'game', title: 'Game components', on: true },
  { id: 'unplugged', title: 'Unplugged devices', on: false },
];

const ICONS = {
  display: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  net: '<path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>',
  audio: '<path d="M4 9v6h4l5 4V5L8 9z"/><path d="M16.5 8.5a5 5 0 0 1 0 7M19 6a8.5 8.5 0 0 1 0 12"/>',
  bt: '<path d="M7 7l10 10-5 4V3l5 4L7 17"/>',
  usb: '<path d="M12 3v14M9 6l3-3 3 3"/><circle cx="12" cy="19" r="2"/><path d="M12 13l-4-2V8M12 11l4-2V7"/>',
  input: '<rect x="7" y="3" width="10" height="18" rx="5"/><path d="M12 7v3"/>',
  storage: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 14h.01M11 14h6"/>',
  runtime: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/>',
};
function iconFor(cls, group) {
  const c = (cls || '').toLowerCase();
  const key = group === 'game' ? 'runtime'
    : c === 'display' ? 'display'
    : c === 'net' ? 'net'
    : ['media', 'audioendpoint', 'audioprocessingobject', 'softwarecomponent'].includes(c) ? 'audio'
    : c === 'bluetooth' ? 'bt'
    : ['usb', 'usbdevice', 'ports'].includes(c) ? 'usb'
    : ['hidclass', 'mouse', 'keyboard'].includes(c) ? 'input'
    : ['diskdrive', 'scsiadapter', 'hdc'].includes(c) ? 'storage' : 'chip';
  return `<span class="dev-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[key]}</svg></span>`;
}

async function scanDevices() {
  try {
    state.drivers.installed = await call('drivers.scan');
  } catch (err) {
    toast(`Couldn't list devices: ${err.message}`, true);
    state.drivers.installed = [];
  }
  renderDrivers();
}

async function checkDrivers() {
  const d = state.drivers;
  if (d.checking || d.installing) return;
  d.checking = true;
  d.results = null;
  d.scan = { stage: 'Starting', done: 0, total: 0 };
  $('#btnDrvCheck').disabled = true;
  summarizeDrivers();
  renderDrivers();
  try {
    d.check = await call('drivers.check');
    d.checkedAt = new Date();
    d.selected = new Set(visibleOffers().filter((o) => !o.critical && GROUPS.find((g) => g.id === o.group)?.on).map((o) => o.key));
  } catch (err) {
    toast(`Couldn't check for updates: ${err.message}`, true);
  } finally {
    d.checking = false;
    d.scan = null;
    $('#btnDrvCheck').disabled = false;
    summarizeDrivers();
    renderDrivers();
  }
}

on('drivers.scanProgress', (p) => {
  state.drivers.scan = p;
  if (state.page === 'drivers' && state.drivers.tab === 'updates') renderDriverUpdates();
});

on('drivers.progress', (p) => {
  state.drivers.progress = p;
  if (state.drivers.tab === 'updates') renderDrivers();
});

async function installDrivers() {
  const d = state.drivers;
  const keys = [...d.selected];
  if (!keys.length) return;
  const offers = d.check.offers.filter((o) => d.selected.has(o.key));
  const gpu = offers.some((o) => (o.deviceClass || '').toLowerCase() === 'display');
  const drivers = offers.some((o) => o.group !== 'game');
  const risky = offers.filter((o) => o.critical);

  let warnings = [];
  if (drivers) {
    try {
      const pre = await call('drivers.preflight');
      if (pre.blockers.length) {
        await alertBox('Not safe to install drivers right now', pre.blockers.join('\n\n'));
        return;
      }
      warnings = pre.warnings;
    } catch { /* the install itself re-checks */ }
  }
  const ok = await confirmBox(
    risky.length ? `Install ${plural(keys.length, 'update')}, including ${plural(risky.length, 'critical device')}?` : `Install ${plural(keys.length, 'update')}?`,
    [
      risky.length ? `${risky.map((o) => o.name).join(', ')}: ${risky[0].riskNote} Only continue if you know you need this update and know how to recover if Windows won't start.` : '',
      warnings.join(' '),
      drivers ? 'SystemForge makes a restore point and backs up the drivers being replaced first.' : '',
      gpu ? 'Your screen will go dark for a moment while the graphics driver installs.' : '',
      'Keep SystemForge open until it finishes.',
    ].filter(Boolean).join(' '),
    risky.length ? 'Install anyway' : 'Install', risky.length > 0);
  if (!ok) return;

  d.installing = true;
  d.resultsHadDrivers = drivers;
  d.progress = { phase: 'Starting', index: 0, total: keys.length, title: '', percent: -1 };
  renderDrivers();
  try {
    const summary = await call('drivers.install', { ids: keys });
    d.results = summary;
    const okCount = summary.items.filter((i) => i.success).length;
    toast(okCount === summary.items.length ? `Installed ${plural(okCount, 'update')}.` : `Installed ${okCount} of ${summary.items.length}. See the list for details.`, okCount < summary.items.length);
  } catch (err) {
    toast(`Install stopped: ${err.message}`, true);
  } finally {
    d.installing = false;
    d.progress = null;
    d.check = null;
    d.installed = null;
    summarizeDrivers();
    renderDrivers();
    scanDevices();
  }
}

function renderDrivers() {
  const tab = state.drivers.tab;
  if (tab === 'updates') renderDriverUpdates();
  else if (tab === 'devices') renderDevices();
  else renderBackups();
}

function progressCard(p, fallback) {
  const pct = p.percent >= 0 ? p.percent : null;
  const overall = p.total ? Math.round(((Math.max(1, p.index) - 1 + (pct ?? 50) / 100) / p.total) * 100) : 0;
  return `
    <div class="progress" role="status">
      <div class="step">${esc(p.index ? `${p.phase}${pct !== null ? ` ${pct}%` : ''} · ${p.index} of ${p.total}` : p.phase)}</div>
      <div class="detail">${esc(p.title || fallback)}</div>
      <div class="bar"><span style="width:${Math.max(3, p.index ? overall : 3)}%"></span></div>
    </div>`;
}

function renderDriverUpdates() {
  const d = state.drivers;
  const el = $('#drvUpdates');

  if (d.installing && d.progress) {
    el.innerHTML = progressCard(d.progress, 'Getting ready. Keep SystemForge open until this finishes.');
    return;
  }

  let html = '';
  if (d.results) {
    const r = d.results;
    html += `<div class="rows results">
      ${r.rebootRequired ? '<div class="row result-row"><span class="name">Restart your PC to finish installing.</span><span></span></div>' : ''}
      ${r.items.map((i) => `
        <div class="row result-row">
          <span class="name">${esc(i.title)}</span>
          <span class="${i.success ? 'result-ok' : 'result-bad'}">${esc(i.message)}</span>
        </div>`).join('')}
      ${r.restorePoint || r.backupFolder ? `<div class="row result-row"><span class="meta" style="white-space:normal">${esc(r.restorePoint)}${r.backupFolder ? ' The replaced drivers were backed up and can be reinstalled from the Backups tab.' : ''}</span><span></span></div>` : ''}
      ${r.needsSystemProtection ? `<div class="row result-row"><span class="meta" style="white-space:normal">System Protection lets Windows make restore points, so any change can be undone. It uses a little disk space.</span><button class="btn primary small" data-act="enable-restore">Turn on System Protection</button></div>` : ''}
      ${r.items.some((i) => i.success) && d.resultsHadDrivers ? `<div class="row result-row"><span class="meta" style="white-space:normal">Something not working right after this update? System Restore puts your drivers back the way they were before it.</span><button class="btn small" data-act="undo">Undo with System Restore</button></div>` : ''}
    </div>`;
  }

  if (d.checking) {
    const sc = d.scan || {};
    const pct = sc.total ? Math.round((sc.done / sc.total) * 100) : 4;
    el.innerHTML = html + `
      <div class="progress" role="status">
        <div class="step">Checking for updates</div>
        <div class="detail">${esc(sc.total ? `${sc.stage}: ${sc.done} of ${plural(sc.total, 'device')}` : 'Asking Windows Update, the Microsoft Update Catalog, NVIDIA and winget at once…')}</div>
        <div class="bar"><span style="width:${Math.max(4, pct)}%"></span></div>
      </div>`;
    return;
  }
  if (!d.check) {
    el.innerHTML = html + empty('Not checked yet', 'SystemForge checks Windows Update, the Microsoft Update Catalog, NVIDIA and winget, and only offers drivers Windows would actually choose for your hardware.',
      '<button class="btn primary" data-act="check">Check for updates</button>');
    el.querySelector('[data-act="check"]')?.addEventListener('click', checkDrivers);
    return;
  }

  const offers = visibleOffers();
  const hidden = d.check.offers.filter((o) => !offers.includes(o));
  const failed = d.check.sources.filter((s) => !s.ok);
  const count = (g) => offers.filter((o) => o.group === g).length;
  const sizeSel = offers.filter((o) => d.selected.has(o.key)).reduce((s, o) => s + (o.sizeBytes || 0), 0);

  html += `
    <div class="drv-stats">
      <div class="stat"><span class="stat-num">${offers.length}</span><span class="stat-label">Updates available</span></div>
      <div class="stat"><span class="stat-num">${count('device')}</span><span class="stat-label">Device drivers</span></div>
      <div class="stat"><span class="stat-num">${count('game')}</span><span class="stat-label">Game components</span></div>
      ${advanced()
        ? `<div class="stat"><span class="stat-num">${count('unplugged')}</span><span class="stat-label">Unplugged devices</span></div>`
        : `<div class="stat"><span class="stat-num">${hidden.length}</span><span class="stat-label">Hidden for safety</span></div>`}
    </div>
    ${hidden.length ? `<p class="hint safe-hint">${plural(hidden.length, 'update is', 'updates are')} hidden to keep your PC safe: ${esc(hidden.slice(0, 3).map((o) => o.name).join(', '))}${hidden.length > 3 ? ' and more' : ''}. Drivers for storage, chipset, firmware and unplugged devices can stop Windows starting if something goes wrong. Experienced users can show them with Advanced driver options in Settings.</p>` : ''}
    ${advanced() && offers.some((o) => o.critical) ? '<p class="hint warn-hint">Advanced driver options are on. Updates marked Critical device are for parts Windows needs to start. They are never pre-selected.</p>' : ''}
    ${failed.map((s) => `<p class="hint warn-hint">${esc(SOURCE_NAME[s.source] || s.source)} didn't answer: ${esc(s.message)}</p>`).join('')}`;

  if (!offers.length) {
    el.innerHTML = html + empty('Everything is up to date',
      `Checked ${plural(d.check.devicesChecked, 'device')} against every source.${d.checkedAt ? ` Last checked at ${d.checkedAt.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}.` : ''}`);
    return;
  }

  for (const g of GROUPS) {
    const list = offers.filter((o) => o.group === g.id);
    if (!list.length) continue;
    const sel = list.filter((o) => d.selected.has(o.key)).length;
    const open = d.groupsOpen[g.id] ?? g.on;
    html += `
      <section class="group" data-open="${open}">
        <header class="group-head">
          <label class="group-check"><input type="checkbox" data-group="${g.id}" ${sel === list.length ? 'checked' : ''} aria-label="Select all ${esc(g.title)}"></label>
          <button class="group-toggle" data-toggle="${g.id}" aria-expanded="${open}">
            <span class="group-title">${esc(g.title)}</span>
            <span class="count">${sel} of ${list.length} selected</span>
            <svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>
          </button>
        </header>
        <div class="rows" ${open ? '' : 'hidden'}>
          <div class="row head updates"><span></span><span></span><span>${g.id === 'game' ? 'Component' : 'Device'}</span><span>Installed now</span><span>Source</span><span class="num">Size</span></div>
          ${list.map((o) => offerRow(o, d.selected.has(o.key))).join('')}
        </div>
      </section>`;
  }

  html += `
    <div class="footer-bar">
      <span class="total"><strong>${d.selected.size}</strong> ${d.selected.size === 1 ? 'update' : 'updates'} selected${sizeSel ? ` · ${fmtBytes(sizeSel)}` : ''}</span>
      <button class="btn primary" data-act="install" ${d.selected.size ? '' : 'disabled'}>Install selected</button>
    </div>`;
  el.innerHTML = html;

  $$('[data-open]', el).forEach((b) => b.addEventListener('click', (e) => { e.preventDefault(); call('system.openVendorUrl', { url: b.dataset.open }).catch((err) => toast(err.message, true)); }));
  $$('input[data-key]', el).forEach((cb) => cb.addEventListener('change', () => {
    cb.checked ? d.selected.add(cb.dataset.key) : d.selected.delete(cb.dataset.key);
    renderDriverUpdates();
  }));
  $$('input[data-group]', el).forEach((cb) => {
    const list = offers.filter((o) => o.group === cb.dataset.group);
    const sel = list.filter((o) => d.selected.has(o.key)).length;
    cb.indeterminate = sel > 0 && sel < list.length;
    cb.addEventListener('change', () => {
      // "Select all" never ticks a critical device; those have to be picked one by one.
      list.forEach((o) => (cb.checked ? (!o.critical && d.selected.add(o.key)) : d.selected.delete(o.key)));
      renderDriverUpdates();
    });
  });
  $$('[data-toggle]', el).forEach((b) => b.addEventListener('click', () => {
    const id = b.dataset.toggle;
    d.groupsOpen[id] = !(d.groupsOpen[id] ?? GROUPS.find((g) => g.id === id).on);
    renderDriverUpdates();
  }));
  el.querySelector('[data-act="install"]').addEventListener('click', installDrivers);
}

function offerRow(o, checked) {
  const [srcClass, srcLabel] = SOURCE[o.source] || ['src-wu', o.source];
  const current = o.currentVersion
    ? `<span class="meta">Version ${esc(o.currentVersion)}</span><span class="meta">${o.currentDate ? `from ${esc(fmtDate(o.currentDate))}` : ''}</span>`
    : `<span class="meta">${o.group === 'game' ? 'Not installed' : 'No driver'}</span><span class="meta"></span>`;
  const newer = `${o.newVersion ? `Version ${o.newVersion}` : 'New driver'}${o.newDate ? ` from ${fmtDate(o.newDate)}` : ''}`;
  return `
    <label class="row updates${o.group === 'unplugged' ? ' unplugged' : ''}">
      ${o.manual ? '<span class="manual-dot" title="Download only"></span>' : `<input type="checkbox" data-key="${esc(o.key)}" ${checked ? 'checked' : ''}>`}
      ${iconFor(o.deviceClass, o.group)}
      <span class="stack">
        <span class="name">${esc(o.name)}${o.group === 'unplugged' ? ' <span class="tag soft">Unplugged</span>' : ''}${o.manual ? ' <span class="tag soft">Notice</span>' : o.critical ? ' <span class="tag">Critical device</span>' : ''}</span>
        <span class="meta">${esc(o.publisher ? `${o.publisher} · ` : '')}${esc(newer)}</span>
        ${o.critical ? `<span class="hint warn-hint">${esc(o.riskNote)}</span>` : o.note ? `<span class="hint">${esc(o.note)}</span>` : ''}
      </span>
      <span class="stack">${current}</span>
      <span><span class="src ${srcClass}">${esc(srcLabel)}</span></span>
      <span class="num">${o.manual ? `<button class="btn small" data-open="${esc(o.infoUrl || '')}">Download</button>` : o.sizeBytes ? fmtBytes(o.sizeBytes) : esc(o.sizeText || '')}</span>
    </label>`;
}

function renderDevices() {
  const d = state.drivers;
  const el = $('#drvDevices');
  if (!d.installed) { el.innerHTML = empty('Listing devices…', 'Reading every driver on this PC.'); return; }

  const classes = [...new Set(d.installed.map((x) => x.deviceClass || 'Other'))].sort();
  const q = d.query.toLowerCase();
  const list = d.installed.filter((x) =>
    (!d.cls || (x.deviceClass || 'Other') === d.cls) &&
    (!q || `${x.deviceName} ${x.provider} ${x.manufacturer}`.toLowerCase().includes(q)));
  const unsigned = d.installed.filter((x) => !x.isSigned).length;

  el.innerHTML = `
    <div class="toolbar">
      <input class="search" type="search" id="devSearch" placeholder="Find a device" value="${esc(d.query)}" aria-label="Find a device">
      <select id="devClass" aria-label="Device type">
        <option value="">All device types</option>
        ${classes.map((c) => `<option ${c === d.cls ? 'selected' : ''}>${esc(c)}</option>`).join('')}
      </select>
      <span class="grow"></span>
      <span class="meta">${plural(d.installed.length, 'device')}${unsigned ? `, ${unsigned} with unsigned drivers` : ''}</span>
    </div>
    <div class="rows">
      <div class="row head devices"><span>Device</span><span>Driver from</span><span>Version</span><span>Date</span><span></span></div>
      ${list.length ? list.map((x) => `
        <div class="row devices">
          <span class="stack">
            <span class="name">${esc(x.deviceName)}</span>
            <span class="meta">${esc(x.deviceClass || 'Other')}${x.isSigned ? '' : ' <span class="tag">Unsigned</span>'}</span>
          </span>
          <span class="meta">${esc(x.provider || x.manufacturer || 'Unknown')}</span>
          <span class="meta">${esc(x.version)}</span>
          <span class="meta">${esc(fmtDate(x.date))}</span>
          ${isCriticalClass(x.deviceClass) && !advanced()
            ? '<span class="meta" title="Windows needs this device to start. Roll back is available with Advanced driver options.">Protected</span>'
            : `<button class="btn small" data-rollback="${esc(x.deviceId)}" data-name="${esc(x.deviceName)}">Roll back</button>`}
        </div>`).join('') : '<div class="row" style="grid-template-columns:1fr"><span class="meta">No devices match.</span></div>'}
    </div>`;

  const search = $('#devSearch');
  search.addEventListener('input', () => {
    d.query = search.value;
    const pos = search.selectionStart;
    renderDevices();
    const s = $('#devSearch');
    s.focus();
    s.setSelectionRange(pos, pos);
  });
  $('#devClass').addEventListener('change', (e) => { d.cls = e.target.value; renderDevices(); });
  $$('[data-rollback]', el).forEach((b) => b.addEventListener('click', async () => {
    const ok = await confirmBox(`Roll back ${b.dataset.name}?`,
      'This switches the device to the driver it used before its last update, the same as Device Manager does. The device may briefly disconnect.',
      'Roll back');
    if (!ok) return;
    await withBusy(b, 'Rolling back…', async () => {
      try { toast((await call('drivers.rollback', { deviceId: b.dataset.rollback })).message); scanDevices(); }
      catch (err) { toast(err.message, true); }
    });
  }));
}

async function loadBackups() {
  try { state.drivers.backups = await call('drivers.backups'); } catch { state.drivers.backups = []; }
  renderDrivers();
}

function renderBackups() {
  const d = state.drivers;
  const el = $('#drvBackups');
  const list = d.backups;
  el.innerHTML = `
    <div class="toolbar">
      <button class="btn primary" data-act="backup">Back up all drivers</button>
      <button class="btn" data-act="folder">Open backup folder</button>
      <span class="grow"></span>
      <span class="meta">Updates through SystemForge back up the drivers they replace automatically.</span>
    </div>
    ${!list ? empty('Loading backups…', '') : !list.length
      ? empty('No backups yet', 'Back up your drivers before a Windows reinstall, or before trying drivers from somewhere else.')
      : `<div class="rows">
          <div class="row head backups"><span>Backup</span><span class="num">Drivers</span><span class="num">Size</span><span></span></div>
          ${list.map((b) => `
            <div class="row backups">
              <span class="stack"><span class="name">${esc(fmtDateTime(b.created))}</span><span class="meta">${esc(b.reason)}</span></span>
              <span class="num">${b.driverCount}</span>
              <span class="num">${fmtMb(b.sizeMb)}</span>
              <button class="btn small" data-restore="${esc(b.id)}">Reinstall</button>
            </div>`).join('')}
        </div>`}`;

  el.querySelector('[data-act="backup"]').addEventListener('click', (e) => withBusy(e.currentTarget, 'Backing up…', async () => {
    try {
      const set = await call('drivers.backupAll');
      toast(`Backed up ${plural(set.driverCount, 'driver')} (${fmtMb(set.sizeMb)}).`);
      await loadBackups();
    } catch (err) { toast(err.message, true); }
  }));
  el.querySelector('[data-act="folder"]').addEventListener('click', () => call('drivers.openBackups').catch((err) => toast(err.message, true)));
  $$('[data-restore]', el).forEach((b) => b.addEventListener('click', async () => {
    const ok = await confirmBox('Reinstall drivers from this backup?',
      'Windows adds every driver in the backup and uses each one wherever it fits better than the current driver.', 'Reinstall');
    if (!ok) return;
    await withBusy(b, 'Reinstalling…', async () => {
      try { toast((await call('drivers.restoreBackup', { id: b.dataset.restore })).message); }
      catch (err) { toast(err.message, true); }
    });
  }));
}

/* ============================================================
   Cleanup
   ============================================================ */

$('#btnJunkScan').addEventListener('click', () => scanJunk());

const FOLDER_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h8.5A1.5 1.5 0 0 1 21 9.5v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/></svg>';
const PAGE = 200;

/** Bytes the user unticked inside a category's file list. */
const excludedBytes = (id) => [...(state.junk.excluded.get(id)?.values() ?? [])].reduce((s, b) => s + b, 0);

async function scanJunk() {
  const j = state.junk;
  if (j.scanning) return;
  j.scanning = true;
  if (state.page === 'cleanup') renderJunk();
  try {
    j.cats = await call('junk.scan');
    if (!j.selected.size) j.cats.filter((c) => c.defaultOn).forEach((c) => j.selected.add(c.id));
    j.excluded = new Map();   // file lists changed, so old exclusions no longer apply
    j.view = null;
  } catch (err) {
    toast(`Couldn't scan: ${err.message}`, true);
  } finally {
    j.scanning = false;
    summarizeJunk();
    if (state.page === 'cleanup') renderJunk();
  }
}

function renderJunk() {
  const j = state.junk;
  const el = $('#junk');
  if (!j.cats) { el.innerHTML = empty('Measuring…', 'Adding up leftover files.'); return; }

  const total = j.cats.filter((c) => j.selected.has(c.id)).reduce((s, c) => s + Math.max(0, c.bytes - excludedBytes(c.id)), 0);
  const kept = j.cats.filter((c) => j.selected.has(c.id)).reduce((s, c) => s + (j.excluded.get(c.id)?.size ?? 0), 0);
  el.innerHTML = `
    <div class="rows">
      ${j.cats.map((c) => {
        const open = j.view?.id === c.id;
        const ex = j.excluded.get(c.id)?.size ?? 0;
        return `
        <div class="junk-item" data-open="${open}">
          <label class="row junk">
            <input type="checkbox" data-id="${esc(c.id)}" ${j.selected.has(c.id) ? 'checked' : ''} ${c.bytes ? '' : 'disabled'}>
            <span class="stack">
              <span class="name">${esc(c.name)}</span>
              <span class="meta" style="white-space:normal">${esc(c.description)}</span>
              ${c.files ? `<span class="hint">${plural(c.files, 'file')}${ex ? `, ${ex} kept by you` : ''}</span>` : ''}
            </span>
            ${c.files ? `<button class="link view-files" data-view="${esc(c.id)}" aria-expanded="${open}">${open ? 'Hide files' : 'View files'}</button>` : '<span></span>'}
            <span class="num">${c.bytes ? fmtBytes(Math.max(0, c.bytes - (j.selected.has(c.id) ? excludedBytes(c.id) : 0))) : 'Empty'}</span>
          </label>
          ${open ? filesShell(c) : ''}
        </div>`;
      }).join('')}
    </div>
    <div class="footer-bar">
      <span class="total"><strong>${fmtBytes(total)}</strong> selected${kept ? ` · ${plural(kept, 'file')} kept` : ''}</span>
      <button class="btn primary" data-act="clean" ${total && !j.scanning ? '' : 'disabled'}>${j.scanning ? 'Scanning…' : 'Clean selected'}</button>
    </div>`;

  $$('input[data-id]', el).forEach((cb) => {
    const ex = j.excluded.get(cb.dataset.id)?.size ?? 0;
    cb.indeterminate = cb.checked && ex > 0;
    cb.addEventListener('change', () => {
      cb.checked ? j.selected.add(cb.dataset.id) : j.selected.delete(cb.dataset.id);
      renderJunk();
    });
  });
  $$('[data-view]', el).forEach((b) => b.addEventListener('click', (e) => {
    e.preventDefault();   // don't toggle the category checkbox the button sits in
    const id = b.dataset.view;
    if (j.view?.id === id) { j.view = null; renderJunk(); return; }
    j.view = { id, query: '', sort: 'size', page: null, loading: true };
    renderJunk();
    loadFiles(0);
  }));
  if (j.view) wireFiles();
  el.querySelector('[data-act="clean"]').addEventListener('click', cleanJunk);
}

/** The file browser frame (toolbar stays put while the list below it reloads, so typing in search isn't interrupted). */
function filesShell(c) {
  const v = state.junk.view;
  const isBin = c.id === 'recycle-bin';
  return `
    <div class="files">
      <div class="files-toolbar">
        <input class="search small" type="search" id="fileSearch" placeholder="Filter by name or folder" value="${esc(v.query)}" aria-label="Filter files">
        <select class="small" id="fileSort" aria-label="Sort files">
          ${[['size', 'Largest first'], ['newest', 'Newest first'], ['oldest', 'Oldest first'], ['name', 'Name'], ['folder', 'Folder']]
            .map(([k, label]) => `<option value="${k}" ${v.sort === k ? 'selected' : ''}>${label}</option>`).join('')}
        </select>
        <span class="grow"></span>
        <span class="meta" id="fileCount"></span>
        <button class="link" data-files="none">Untick all</button>
        <button class="link" data-files="all">Tick all</button>
      </div>
      ${isBin ? '<p class="hint files-hint">Untick anything you still want back. Only the ticked items are deleted for good.</p>' : ''}
      <div class="file-list" id="fileList"></div>
      <button class="more" id="fileMore" hidden></button>
    </div>`;
}

function wireFiles() {
  const j = state.junk;
  let timer;
  const search = $('#fileSearch');
  search?.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => { j.view.query = search.value; loadFiles(0); }, 250);
  });
  $('#fileSort')?.addEventListener('change', (e) => { j.view.sort = e.target.value; loadFiles(0); });
  $$('[data-files]').forEach((b) => b.addEventListener('click', () => {
    const id = j.view.id;
    j.excluded.delete(id);
    b.dataset.files === 'all' ? j.selected.add(id) : j.selected.delete(id);
    renderJunk();
    loadFiles(0);
  }));
  $('#fileMore')?.addEventListener('click', () => loadFiles(j.view.page ? j.view.page.files.length : 0, true));
  renderFileList();
}

async function loadFiles(offset, append = false) {
  const v = state.junk.view;
  if (!v) return;
  v.loading = true;
  renderFileList();
  try {
    const page = await call('junk.files', { id: v.id, offset, limit: PAGE, query: v.query, sort: v.sort });
    if (state.junk.view !== v) return; // closed or switched meanwhile
    if (append && v.page) page.files = v.page.files.concat(page.files);
    v.page = page;
  } catch (err) {
    toast(`Couldn't list files: ${err.message}`, true);
  } finally {
    v.loading = false;
    if (state.junk.view === v) renderFileList();
  }
}

function renderFileList() {
  const j = state.junk;
  const v = j.view;
  const list = $('#fileList');
  if (!v || !list) return;
  const p = v.page;
  const catOn = j.selected.has(v.id);
  const ex = j.excluded.get(v.id) ?? new Map();

  $('#fileCount').textContent = p ? `${plural(p.total, 'file')} · ${fmtBytes(p.totalBytes)}` : '';
  if (!p) { list.innerHTML = `<div class="file-empty meta">${v.loading ? 'Listing files…' : ''}</div>`; return; }
  if (!p.files.length) { list.innerHTML = `<div class="file-empty meta">${v.query ? 'No files match.' : 'Nothing here.'}</div>`; return; }

  list.innerHTML = p.files.map((f) => {
    const folder = f.origin || f.path.slice(0, Math.max(0, f.path.lastIndexOf('\\')));
    return `
    <label class="file-row" title="${esc(f.origin ? `${f.origin}\\${f.name}` : f.path)}">
      <input type="checkbox" data-path="${esc(f.path)}" data-bytes="${f.bytes}" ${catOn && !ex.has(f.path) ? 'checked' : ''} ${catOn ? '' : 'disabled'}>
      <span class="stack">
        <span class="fname">${esc(f.name)}</span>
        <span class="path">${f.origin ? 'from ' : ''}${esc(folder)}</span>
      </span>
      <span class="meta">${esc(fmtDate(f.modified))}</span>
      <span class="num">${fmtBytes(f.bytes) === '0 MB' ? '&lt; 0.1 MB' : fmtBytes(f.bytes)}</span>
      <button class="icon-btn" data-reveal-file="${esc(f.path)}" title="Show in folder" aria-label="Show ${esc(f.name)} in its folder">${FOLDER_ICON}</button>
    </label>`;
  }).join('') + (catOn ? '' : '<div class="file-empty hint">Tick this category to choose which of these files get cleaned.</div>');

  const more = $('#fileMore');
  const left = p.total - p.files.length;
  more.hidden = left <= 0;
  more.textContent = v.loading ? 'Loading…' : `Show ${Math.min(PAGE, left)} more`;
  more.disabled = v.loading;

  $$('input[data-path]', list).forEach((cb) => cb.addEventListener('change', () => {
    let m = j.excluded.get(v.id);
    if (!m) j.excluded.set(v.id, (m = new Map()));
    cb.checked ? m.delete(cb.dataset.path) : m.set(cb.dataset.path, Number(cb.dataset.bytes));
    updateJunkTotals();
  }));
  $$('[data-reveal-file]', list).forEach((b) => b.addEventListener('click', (e) => {
    e.preventDefault();
    call('junk.reveal', { path: b.dataset.revealFile }).catch((err) => toast(err.message, true));
  }));
}

/** Refresh the numbers without rebuilding the file list (keeps scroll position while ticking files). */
function updateJunkTotals() {
  const j = state.junk;
  for (const c of j.cats) {
    const item = $(`#junk input[data-id="${CSS.escape(c.id)}"]`)?.closest('.junk-item');
    if (!item) continue;
    const ex = j.excluded.get(c.id)?.size ?? 0;
    const cb = item.querySelector('input[data-id]');
    cb.indeterminate = cb.checked && ex > 0;
    item.querySelector('.row.junk .num').textContent = c.bytes ? fmtBytes(Math.max(0, c.bytes - (j.selected.has(c.id) ? excludedBytes(c.id) : 0))) : 'Empty';
    const hint = item.querySelector('.row.junk .hint');
    if (hint) hint.textContent = `${plural(c.files, 'file')}${ex ? `, ${ex} kept by you` : ''}`;
  }
  const sel = j.cats.filter((c) => j.selected.has(c.id));
  const total = sel.reduce((s, c) => s + Math.max(0, c.bytes - excludedBytes(c.id)), 0);
  const kept = sel.reduce((s, c) => s + (j.excluded.get(c.id)?.size ?? 0), 0);
  $('#junk .footer-bar .total').innerHTML = `<strong>${fmtBytes(total)}</strong> selected${kept ? ` · ${plural(kept, 'file')} kept` : ''}`;
  $('#junk [data-act="clean"]').disabled = !total || j.scanning;
}

async function cleanJunk(e) {
  const button = e.currentTarget; // currentTarget is null once we've awaited the confirm dialog
  const j = state.junk;
  const ids = [...j.selected].filter((id) => j.cats.find((c) => c.id === id)?.bytes);
  const exclude = ids.flatMap((id) => [...(j.excluded.get(id)?.keys() ?? [])]);
  if (ids.includes('recycle-bin')) {
    const keptInBin = j.excluded.get('recycle-bin')?.size ?? 0;
    const ok = await confirmBox(keptInBin ? 'Delete the ticked Recycle Bin items?' : 'Empty the Recycle Bin?',
      keptInBin ? `They'll be gone for good. The ${plural(keptInBin, 'item')} you unticked stay in the Recycle Bin.`
                : 'Files in it will be gone for good. Use View files to keep some, or untick Recycle Bin.',
      keptInBin ? 'Delete and clean' : 'Empty and clean', true);
    if (!ok) return;
  }
  await withBusy(button, 'Cleaning…', async () => {
    try {
      const r = await call('junk.clean', { ids, exclude });
      toast(`Cleaned ${fmtBytes(r.freedBytes)}.${r.skipped ? ` ${plural(r.skipped, 'file was', 'files were')} in use and left alone.` : ''}${exclude.length ? ` Kept the ${plural(exclude.length, 'file')} you unticked.` : ''}`);
    } catch (err) { toast(err.message, true); }
  });
  scanJunk();
}

/* ============================================================
   Startup
   ============================================================ */

$('#startupSearch').addEventListener('input', (e) => { state.startup.query = e.target.value; renderStartup(); });

async function loadStartup() {
  try { state.startup.items = await call('startup.list'); }
  catch (err) { toast(`Couldn't read startup apps: ${err.message}`, true); state.startup.items = []; }
  summarizeStartup();
  if (state.page === 'startup') renderStartup();
}

function renderStartup() {
  const items = state.startup.items;
  const el = $('#startup');
  if (!items) { el.innerHTML = empty('Reading startup apps…', ''); return; }
  if (!items.length) { el.innerHTML = empty('Nothing starts with Windows', 'Sign-in is as quick as it gets.'); return; }

  const on = items.filter((i) => i.enabled).length;
  $('#startupLede').textContent = `${on} of ${plural(items.length, 'app')} open when you sign in. Turning one off doesn't uninstall it, and you can turn it back on any time.`;

  const q = state.startup.query.toLowerCase();
  const list = items.filter((i) => !q || `${i.name} ${i.publisher}`.toLowerCase().includes(q));
  el.innerHTML = `<div class="rows">
    ${list.map((i) => `
      <div class="row startup">
        ${i.icon ? `<img class="app-icon" src="${i.icon}" alt="">` : '<span class="app-icon"></span>'}
        <span class="stack">
          <span class="name">${esc(i.name)}</span>
          <span class="meta">${esc(i.publisher || 'Unknown publisher')}</span>
        </span>
        <span class="stack">
          <span class="meta">${esc(i.scope)}</span>
          <button class="link" data-reveal="${esc(i.id)}">Show file</button>
        </span>
        <button class="switch" role="switch" aria-checked="${i.enabled}" aria-label="Start ${esc(i.name)} with Windows" data-id="${esc(i.id)}"></button>
      </div>`).join('')}
  </div>`;

  $$('.switch', el).forEach((sw) => sw.addEventListener('click', async () => {
    const item = items.find((i) => i.id === sw.dataset.id);
    const enabled = !item.enabled;
    sw.setAttribute('aria-checked', String(enabled));
    try {
      await call('startup.set', { id: item.id, enabled });
      item.enabled = enabled;
      toast(enabled ? `${item.name} will open when you sign in.` : `${item.name} won't open when you sign in.`);
      summarizeStartup();
      renderStartup();
    } catch (err) {
      sw.setAttribute('aria-checked', String(item.enabled));
      toast(err.message, true);
    }
  }));
  $$('[data-reveal]', el).forEach((b) => b.addEventListener('click', () =>
    call('startup.reveal', { id: b.dataset.reveal }).catch((err) => toast(err.message, true))));
}

/* ============================================================
   Performance
   ============================================================ */

const HISTORY = 80; // 2 minutes at one reading every 1.5 s

function pushHistory(s) {
  const h = state.history;
  h.cpu.push(s.cpu);
  h.gpu.push(s.gpu);
  h.ram.push(s.ramPercent);
  for (const k of ['cpu', 'gpu', 'ram']) if (h[k].length > HISTORY) h[k].shift();
}

function drawChart(canvas, data, color) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight || 140;
  if (!w) return;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const g = canvas.getContext('2d');
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);

  const pad = 10; // room for the glow and the live dot
  const plotW = w - pad;

  // Oscilloscope grid: dashed horizontals, faint verticals every 15 seconds.
  g.lineWidth = 1;
  g.setLineDash([2, 4]);
  g.strokeStyle = 'rgba(148, 163, 184, 0.16)';
  for (const p of [25, 50, 75]) {
    const y = Math.round(h - (p / 100) * h) + 0.5;
    g.beginPath(); g.moveTo(0, y); g.lineTo(plotW, y); g.stroke();
  }
  g.setLineDash([]);
  g.strokeStyle = 'rgba(148, 163, 184, 0.06)';
  for (let i = 0; i < HISTORY; i += 10) {
    const x = Math.round(plotW - i * (plotW / (HISTORY - 1))) + 0.5;
    g.beginPath(); g.moveTo(x, 0); g.lineTo(x, h); g.stroke();
  }
  if (data.length < 2) return;

  const step = plotW / (HISTORY - 1);
  const x0 = plotW - (data.length - 1) * step;
  const pts = data.map((v, i) => [x0 + i * step, h - (Math.max(0, Math.min(100, v)) / 100) * (h - 8) - 4]);

  // Smooth curve through the points.
  const trace = () => {
    g.beginPath();
    g.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length - 1; i++) {
      const mx = (pts[i][0] + pts[i + 1][0]) / 2, my = (pts[i][1] + pts[i + 1][1]) / 2;
      g.quadraticCurveTo(pts[i][0], pts[i][1], mx, my);
    }
    const last = pts[pts.length - 1];
    g.lineTo(last[0], last[1]);
  };

  trace();
  g.lineTo(pts[pts.length - 1][0], h);
  g.lineTo(x0, h);
  g.closePath();
  const grad = g.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + '66');
  grad.addColorStop(0.7, color + '10');
  grad.addColorStop(1, color + '00');
  g.fillStyle = grad;
  g.fill();

  trace();
  g.shadowColor = color;
  g.shadowBlur = 14;
  g.strokeStyle = color;
  g.lineWidth = 2.2;
  g.lineJoin = 'round';
  g.stroke();

  // Live dot with a halo at the newest reading.
  const [lx, ly] = pts[pts.length - 1];
  g.shadowBlur = 18;
  g.fillStyle = color;
  g.beginPath(); g.arc(lx, ly, 3.6, 0, Math.PI * 2); g.fill();
  g.shadowBlur = 0;
  g.strokeStyle = color + '55';
  g.lineWidth = 1.5;
  g.beginPath(); g.arc(lx, ly, 7, 0, Math.PI * 2); g.stroke();
}

function drawCharts() {
  if (state.page !== 'performance') return;
  const last = (a) => a[a.length - 1] ?? 0;
  drawChart($('#cpuChart'), state.history.cpu, metricColor('cpu', last(state.history.cpu)));
  drawChart($('#gpuChart'), state.history.gpu, metricColor('gpu', last(state.history.gpu)));
  drawChart($('#ramChart'), state.history.ram, metricColor('ram', last(state.history.ram)));
}

window.addEventListener('resize', drawCharts);

$('#btnBoost').addEventListener('click', (e) => withBusy(e.currentTarget, 'Freeing memory…', async () => {
  try {
    const r = await call('memory.optimize');
    toast(r.note ? `${r.note}. ${fmtMb(r.availableMb)} is available.` : `Freed ${fmtMb(r.freedMb)}. ${fmtMb(r.availableMb)} is now available.`);
  } catch (err) { toast(err.message, true); }
}));

/* ---- Temperatures ---- */

function tempUnit() { return state.info?.settings?.tempUnit === 'F' ? 'F' : 'C'; }
function toUnit(c) { return tempUnit() === 'F' ? c * 9 / 5 + 32 : c; }
function fmtTemp(c) { return c == null ? '' : `${Math.round(toUnit(c))}°${tempUnit()}`; }
/** Amber from 80 °C and red from 90 °C, where processors and graphics cards start slowing themselves down. */
function tempLevel(c, group) {
  if (group === 'Drives') return c >= 70 ? 'bad' : c >= 60 ? 'warn' : '';
  return c >= 90 ? 'bad' : c >= 80 ? 'warn' : '';
}

async function loadTemps() {
  try { state.temps.report = await call('sensors.read'); } catch { return; }
  renderTemps();
}

const TEMP_GROUPS = ['Processor', 'Graphics', 'Motherboard', 'Drives'];

function renderTemps() {
  const el = $('#tempPanel');
  const t = state.temps;
  const r = t.report;
  const u = tempUnit();
  const head = `
    <div class="panel-head">
      <h2 class="panel-title">Temperatures</h2>
      <div class="seg" role="radiogroup" aria-label="Temperature unit">
        <button role="radio" aria-checked="${u === 'C'}" data-unit="C">°C</button>
        <button role="radio" aria-checked="${u === 'F'}" data-unit="F">°F</button>
      </div>
    </div>`;
  if (!r) { el.innerHTML = head + '<p class="meta">Reading sensors…</p>'; bindUnit(el); return; }

  const temps = r.sensors.filter((x) => x.kind === 'temp');
  const fans = r.sensors.filter((x) => x.kind === 'fan');
  let hidden = 0;
  const groups = TEMP_GROUPS.map((g) => {
    let list = temps.filter((x) => x.group === g);
    // Processors report every core separately; the summary readings are enough unless you ask for all.
    if (!t.showAll && list.length > 6) {
      const keep = list.filter((x) => !/#\d+/.test(x.name));
      hidden += list.length - keep.length;
      list = keep.length ? keep : list.slice(0, 6);
    }
    if (!list.length) return '';
    return `<div class="temp-group">
      <div class="temp-group-title">${esc(g)}</div>
      <div class="temp-tiles">${list.map((x) => `
        <div class="temp-tile ${tempLevel(x.value, g)}" title="${esc(x.device)}">
          <span class="tv">${Math.round(toUnit(x.value))}<small>°${u}</small></span>
          <span class="tn">${esc(g === 'Drives' ? x.device : x.name)}</span>
        </div>`).join('')}</div>
    </div>`;
  }).join('');

  const fanHtml = fans.length ? `<div class="temp-group">
      <div class="temp-group-title">Fans</div>
      <div class="temp-tiles">${fans.map((x) => `
        <div class="temp-tile" title="${esc(x.device)}">
          <span class="tv">${Math.round(x.value)}<small>RPM</small></span>
          <span class="tn">${esc(x.name)}</span>
        </div>`).join('')}</div>
    </div>` : '';

  let driver = '';
  if (r.cpuNeedsDriver) {
    driver = `<div class="callout">
      <div>
        <strong>CPU and motherboard temperatures need a sensor driver</strong>
        <p>Windows doesn't share them with apps. SystemForge can install <b>PawnIO</b>, a small signed, open-source driver used by LibreHardwareMonitor and Fan Control. You can remove it any time from Windows Settings › Apps.</p>
        ${t.progress ? `<p class="meta">${esc(t.progress)}</p>` : ''}
      </div>
      <button class="btn small" id="btnSensorDriver" ${t.installing ? 'disabled' : ''}>${t.installing ? 'Installing…' : 'Install sensor driver'}</button>
    </div>`;
  } else if (r.cpuC == null && r.driverInstalled) {
    driver = '<p class="hint">The sensor driver is installed, but this processor\'s temperature couldn\'t be read yet. If you just installed it, restart your PC.</p>';
  }

  el.innerHTML = head + (groups || '<p class="meta">No temperature sensors answered.</p>') + fanHtml + driver +
    (hidden || t.showAll ? `<button class="link" id="btnTempAll">${t.showAll ? 'Show fewer' : `Show all ${temps.length} readings`}</button>` : '');

  bindUnit(el);
  $('#btnTempAll', el)?.addEventListener('click', () => { t.showAll = !t.showAll; renderTemps(); });
  $('#btnSensorDriver', el)?.addEventListener('click', installSensorDriver);
}

function bindUnit(el) {
  $$('[data-unit]', el).forEach((b) => b.addEventListener('click', async () => {
    if (b.dataset.unit === tempUnit()) return;
    try {
      state.info.settings = await call('settings.unit', { unit: b.dataset.unit });
      renderTemps();
      renderSnapshot();
    } catch (err) { toast(err.message, true); }
  }));
}

async function installSensorDriver() {
  const t = state.temps;
  t.installing = true;
  t.progress = 'Waiting for your OK in the Windows dialog…';
  renderTemps();
  try {
    const r = await call('sensors.installDriver');
    toast(r.message);
  } catch (err) { toast(err.message, true); }
  t.installing = false;
  t.progress = null;
  await loadTemps();
}

on('sensors.driverProgress', (p) => {
  state.temps.progress = p.percent >= 0 ? `${p.phase} ${p.percent}%` : `${p.phase}…`;
  if (state.page === 'performance') renderTemps();
});

/* ---- Game Mode ---- */

const GAMEPAD_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.3 7h9.4c2.2 0 3.6 1.9 4 4.4l.6 4c.3 2-1.6 3.4-3.2 2.2L15.6 16H8.4l-2.5 1.6c-1.6 1.2-3.5-.2-3.2-2.2l.6-4C3.7 8.9 5.1 7 7.3 7Z"/><path d="M7 10.5v3M5.5 12h3"/><circle cx="15.5" cy="11" r=".6"/><circle cx="17.5" cy="13" r=".6"/></svg>';

const GAME_OPTIONS = [
  { key: 'auto', title: 'Turn on by itself when a game starts', desc: 'Spots Steam, Epic, Riot, Xbox, GOG, EA, Ubisoft and Battle.net games, Roblox, Minecraft, anything in exclusive full screen, and games you add below. Turns off when the game closes.' },
  { key: 'power', title: 'Best performance power', desc: 'Switches Windows to its Best performance power mode while you play and puts your setting back afterwards. Skipped on battery.' },
  { key: 'priority', title: 'Put the game first', desc: 'Gives the game above-normal CPU priority so background apps wait their turn. Some anti-cheat doesn\'t allow it.' },
  { key: 'memory', title: 'Free up memory when it starts', desc: 'Trims background apps once, never the game itself.' },
];

async function loadGame() {
  try { state.game.status = await call('gamemode.status'); } catch { return; }
  renderGameChip();
  renderGame();
}

on('gamemode.changed', (s) => {
  state.game.status = s;
  renderGameChip();
  if (state.page === 'performance') renderGame();
});

function renderGameChip() {
  const s = state.game.status;
  const chip = $('#gameChip');
  chip.hidden = !s?.active;
  if (s?.active) $('#gameChipName').textContent = s.game || 'Power and priority boosted';
}
$('#gameChip').addEventListener('click', () => go('performance'));

function gameRow(g, list) {
  return `<div class="game-row">
    ${g.icon ? `<img class="app-icon" src="${g.icon}" alt="">` : '<span class="app-icon"></span>'}
    <span class="stack"><span class="name">${esc(g.name)}</span><span class="meta" title="${esc(g.path)}">${esc(g.path)}</span></span>
    <button class="icon-btn" data-remove="${esc(g.path)}" data-list="${list}" aria-label="Remove ${esc(g.name)}">✕</button>
  </div>`;
}

function renderGame() {
  const el = $('#gamePanel');
  const g = state.game;
  const s = g.status;
  if (!s) { el.innerHTML = '<h2 class="panel-title">Game Mode</h2><p class="meta">Loading…</p>'; return; }

  const since = s.sinceUtc ? new Date(s.sinceUtc) : null;
  const status = s.active
    ? `On${s.game ? ` for <b>${esc(s.game)}</b>` : ''}${since ? `, since ${since.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}` : ''}`
    : s.auto ? 'Off. Turns on by itself when a game starts.' : 'Off.';

  const cands = g.picking ? `<div class="game-pick">
      ${g.candidates == null ? '<p class="meta">Looking at open apps…</p>'
        : !g.candidates.length ? '<p class="meta">No open apps to add. Start the game, then come back here.</p>'
        : g.candidates.map((c) => `<div class="game-row">
            ${c.icon ? `<img class="app-icon" src="${c.icon}" alt="">` : '<span class="app-icon"></span>'}
            <span class="stack"><span class="name">${esc(c.name)}</span><span class="meta" title="${esc(c.path)}">${esc(c.path)}</span></span>
            <button class="btn small" data-add="${esc(c.path)}">Add</button>
          </div>`).join('')}
    </div>` : '';

  el.innerHTML = `
    <div class="game-head">
      <span class="game-icon${s.active ? ' on' : ''}">${s.gameIcon ? `<img src="${s.gameIcon}" alt="">` : GAMEPAD_SVG}</span>
      <div class="stack">
        <h2 class="panel-title">Game Mode</h2>
        <span class="meta">${status}</span>
      </div>
      <button class="switch" role="switch" id="gameSwitch" aria-checked="${s.active}" aria-label="Game Mode"></button>
    </div>
    ${s.active && s.changes.length ? `<ul class="game-changes">${s.changes.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>` : ''}
    ${s.active && !s.manual && s.gamePath ? `<button class="link" id="btnNotGame">${esc(s.game || 'This')} isn't a game</button>` : ''}

    <div class="mini-settings">
      ${GAME_OPTIONS.map((o) => `<div class="setting">
        <div><div class="title">${esc(o.title)}</div><div class="desc">${esc(o.desc)}</div></div>
        <button class="switch" role="switch" aria-checked="${!!s[o.key]}" aria-label="${esc(o.title)}" data-gopt="${o.key}"></button>
      </div>`).join('')}
    </div>

    <div class="game-list">
      <div class="game-list-head">
        <span class="temp-group-title">Your games</span>
        <button class="btn small" id="btnPickGame">${g.picking ? 'Done' : 'Add an open app'}</button>
      </div>
      ${cands}
      ${s.games.length ? s.games.map((x) => gameRow(x, 'games')).join('') : (g.picking ? '' : '<p class="meta">Most games are found by themselves. Add one here if Game Mode doesn\'t notice it.</p>')}
      ${s.ignored.length ? `<span class="temp-group-title">Never treated as games</span>${s.ignored.map((x) => gameRow(x, 'ignored')).join('')}` : ''}
    </div>

    <p class="hint">${s.windowsGameMode ? 'Windows\' own Game Mode is on too. It works alongside this.' : 'Windows\' own Game Mode is off. <button class="link" id="btnWinGame">Turn it on in Settings</button>'}</p>
    <p class="hint">Game Mode doesn't stop services or close apps. Other "boosters" do that, and it breaks things like audio and Wi-Fi for gains too small to notice.</p>`;

  $('#gameSwitch', el).addEventListener('click', async () => {
    try { state.game.status = await call('gamemode.set', { on: !s.active }); renderGame(); }
    catch (err) { toast(err.message, true); }
  });
  $$('[data-gopt]', el).forEach((b) => b.addEventListener('click', async () => {
    try { state.game.status = await call('gamemode.option', { key: b.dataset.gopt, value: !s[b.dataset.gopt] }); renderGame(); }
    catch (err) { toast(err.message, true); }
  }));
  $('#btnPickGame', el).addEventListener('click', async () => {
    g.picking = !g.picking;
    g.candidates = null;
    renderGame();
    if (g.picking) {
      try { g.candidates = await call('gamemode.candidates'); } catch (err) { g.candidates = []; toast(err.message, true); }
      renderGame();
    }
  });
  $$('[data-add]', el).forEach((b) => b.addEventListener('click', async () => {
    try {
      state.game.status = await call('gamemode.game', { path: b.dataset.add, list: 'games', add: true });
      g.picking = false;
      renderGame();
      toast('Added. Game Mode turns on whenever it starts.');
    } catch (err) { toast(err.message, true); }
  }));
  $$('[data-remove]', el).forEach((b) => b.addEventListener('click', async () => {
    try { state.game.status = await call('gamemode.game', { path: b.dataset.remove, list: b.dataset.list, add: false }); renderGame(); }
    catch (err) { toast(err.message, true); }
  }));
  $('#btnNotGame', el)?.addEventListener('click', async () => {
    try {
      await call('gamemode.game', { path: s.gamePath, list: 'ignored', add: true });
      state.game.status = await call('gamemode.set', { on: false });
      renderGame();
      toast('Got it. Game Mode won\'t turn on for it again.');
    } catch (err) { toast(err.message, true); }
  });
  $('#btnWinGame', el)?.addEventListener('click', () => call('gamemode.openWindowsSettings').catch((err) => toast(err.message, true)));
}

async function loadApps() {
  try { state.apps.list = await call('apps.top'); } catch { return; }
  renderApps();
}

function renderApps() {
  const a = state.apps;
  const el = $('#apps');
  if (!a.list) { el.innerHTML = '<div class="row"><span class="meta">Reading open apps…</span></div>'; return; }
  el.innerHTML = `<div class="rows">
    <div class="row head apps"><span></span><span>App</span><span class="num">Memory</span><span class="num">CPU</span><span></span></div>
    ${a.list.map((p) => `
      <div class="row apps">
        ${p.icon ? `<img class="app-icon" src="${p.icon}" alt="">` : '<span class="app-icon"></span>'}
        <span class="stack">
          <span class="name">${esc(p.displayName)}</span>
          <span class="meta">${p.count > 1 ? `${p.count} processes` : esc(p.name)}</span>
        </span>
        <span class="num">${fmtMb(p.ramMb)}</span>
        <span class="num">${p.cpu.toFixed(p.cpu < 10 ? 1 : 0)}%</span>
        ${p.protected
          ? '<span class="meta" style="text-align:right">Windows</span>'
          : `<button class="btn small danger${a.armed === p.name ? ' armed' : ''}" data-end="${esc(p.name)}" data-label="${esc(p.displayName)}">${a.armed === p.name ? 'End app?' : 'End'}</button>`}
      </div>`).join('')}
  </div>`;

  $$('[data-end]', el).forEach((b) => b.addEventListener('click', async () => {
    const name = b.dataset.end;
    if (a.armed !== name) {
      a.armed = name;
      clearTimeout(a.armedTimer);
      a.armedTimer = setTimeout(() => { a.armed = null; renderApps(); }, 3000);
      renderApps();
      return;
    }
    a.armed = null;
    clearTimeout(a.armedTimer);
    try { toast((await call('apps.end', { name })).message); }
    catch (err) { toast(err.message, true); }
    loadApps();
  }));
}

/* ============================================================
   Apps (program updates through winget)
   ============================================================ */

$('#btnAppsCheck').addEventListener('click', () => checkApps());
$$('#appTabs .tab').forEach((t) => t.addEventListener('click', () => {
  state.apps2.tab = t.dataset.apptab;
  $$('#appTabs .tab').forEach((x) => x.setAttribute('aria-selected', String(x === t)));
  $('#apps-updates').hidden = t.dataset.apptab !== 'updates';
  $('#apps-programs').hidden = t.dataset.apptab !== 'programs';
  renderApps2();
}));

const initials = (name) => (name.match(/[A-Za-z0-9]/g) || ['?']).slice(0, 2).join('').toUpperCase();

/** Show the background check's result right away if there is one; otherwise run a check. */
async function loadLastApps() {
  try {
    const last = await call('apps.last');
    if (last) { setAppsResult(last); return; }
  } catch { /* fall through */ }
  checkApps();
}

function setAppsResult(check) {
  const a = state.apps2;
  const firstLoad = !a.check;
  a.check = check;
  const live = check.updates.filter((u) => !u.ignored && !u.skipped);
  if (firstLoad || !a.selected.size) a.selected = new Set(live.map((u) => u.id));
  else a.selected = new Set([...a.selected].filter((id) => live.some((u) => u.id === id)));
  summarizeApps();
  if (state.page === 'apps') renderApps2();
}

async function checkApps() {
  const a = state.apps2;
  if (a.checking || a.installing) return;
  a.checking = true;
  a.results = null;
  $('#btnAppsCheck').disabled = true;
  summarizeApps();
  if (state.page === 'apps') renderApps2();
  try {
    setAppsResult(await call('apps.check'));
  } catch (err) {
    toast(`Couldn't check apps: ${err.message}`, true);
  } finally {
    a.checking = false;
    $('#btnAppsCheck').disabled = false;
    summarizeApps();
    if (state.page === 'apps') renderApps2();
  }
}

on('apps.updated', (check) => { if (!state.apps2.installing) setAppsResult(check); });
on('apps.progress', (p) => { state.apps2.progress = p; if (state.page === 'apps') renderApps2(); });
on('nav', (m) => { if (m?.page) go(m.page); });

function summarizeApps() {
  const a = state.apps2;
  const badge = $('#navAppsBadge');
  if (a.checking) return setCheck('apps', 'busy', 'Checking your programs…');
  if (!a.check) return setCheck('apps', '', 'Not checked yet.');
  const n = a.check.updates.filter((u) => !u.ignored && !u.skipped).length;
  badge.hidden = n === 0;
  badge.textContent = n;
  const tracked = a.check.programs.filter((p) => p.source).length;
  setCheck('apps', n ? 'attn' : 'ok', n ? `${plural(n, 'app update')} available. ${tracked} programs tracked.` : `All ${tracked} tracked programs are up to date.`);
}

function renderApps2() {
  if (state.apps2.tab === 'programs') renderPrograms(); else renderAppUpdates();
}

function renderAppUpdates() {
  const a = state.apps2;
  const el = $('#apps-updates');
  if (a.installing && a.progress) {
    el.innerHTML = progressCard(a.progress, 'Getting ready…');
    return;
  }
  let html = '';
  if (a.results) {
    html += `<div class="rows results">${a.results.map((i) => `
      <div class="row result-row"><span class="name">${esc(i.title)}</span><span class="${i.success ? 'result-ok' : 'result-bad'}">${esc(i.message)}</span></div>`).join('')}</div>`;
  }
  if (a.checking && !a.check) { el.innerHTML = html + empty('Checking your programs…', 'winget is comparing what you have installed with its catalog. This takes up to a minute.'); return; }
  if (!a.check) {
    el.innerHTML = html + empty('Not checked yet', 'Find out which of your programs have newer versions.', '<button class="btn primary" data-act="check">Check for updates</button>');
    el.querySelector('[data-act="check"]')?.addEventListener('click', checkApps);
    return;
  }

  const live = a.check.updates.filter((u) => !u.ignored && !u.skipped);
  const held = a.check.updates.filter((u) => u.ignored || u.skipped);
  if (!live.length) {
    html += empty('Your apps are up to date', `Checked ${fmtDateTime(a.check.checkedAt)}.${held.length ? ` ${plural(held.length, 'update')} hidden by you.` : ''}`);
  } else {
    html += `<div class="rows">
      <div class="row head appup"><span></span><span></span><span>App</span><span>Version</span><span></span></div>
      ${live.map((u) => appRow(u, a.selected.has(u.id))).join('')}
    </div>
    <div class="footer-bar">
      <span class="total"><strong>${a.selected.size}</strong> selected</span>
      <button class="btn primary" data-act="update" ${a.selected.size && !a.checking ? '' : 'disabled'}>${a.checking ? 'Checking…' : 'Update selected'}</button>
    </div>`;
  }
  if (held.length) {
    html += `<section class="group" data-open="${a.showIgnored}" style="margin-top:22px">
      <header class="group-head"><span></span>
        <button class="group-toggle" data-held aria-expanded="${a.showIgnored}"><span class="group-title">Hidden updates</span><span class="count">${held.length}</span>
        <svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg></button>
      </header>
      <div class="rows" ${a.showIgnored ? '' : 'hidden'}>
        ${held.map((u) => `
          <div class="row appup held">
            <span></span><span class="dev-icon app-mono">${esc(initials(u.name))}</span>
            <span class="stack"><span class="name">${esc(u.name)}</span><span class="meta">${esc(u.id)}</span></span>
            <span class="stack"><span class="meta">${esc(u.version)} → ${esc(u.available)}</span><span class="hint">${u.ignored ? 'Never offered' : 'This version skipped'}</span></span>
            <span class="row-actions"><button class="link" data-unhide="${esc(u.id)}" data-kind="${u.ignored ? 'ignore' : 'skip'}">Show again</button></span>
          </div>`).join('')}
      </div>
    </section>`;
  }
  el.innerHTML = html;

  $$('input[data-app]', el).forEach((cb) => cb.addEventListener('change', () => {
    cb.checked ? a.selected.add(cb.dataset.app) : a.selected.delete(cb.dataset.app);
    renderAppUpdates();
  }));
  el.querySelector('[data-act="update"]')?.addEventListener('click', updateApps);
  el.querySelector('[data-held]')?.addEventListener('click', () => { a.showIgnored = !a.showIgnored; renderAppUpdates(); });
  $$('[data-skip]', el).forEach((b) => b.addEventListener('click', (e) => { e.preventDefault(); hideApp(b.dataset.skip, 'skip', b.dataset.version); }));
  $$('[data-ignore]', el).forEach((b) => b.addEventListener('click', (e) => { e.preventDefault(); hideApp(b.dataset.ignore, 'ignore'); }));
  $$('[data-unhide]', el).forEach((b) => b.addEventListener('click', () => unhideApp(b.dataset.unhide, b.dataset.kind)));
}

function appRow(u, checked) {
  return `
    <label class="row appup">
      <input type="checkbox" data-app="${esc(u.id)}" ${checked ? 'checked' : ''}>
      <span class="dev-icon app-mono">${esc(initials(u.name))}</span>
      <span class="stack"><span class="name">${esc(u.name)}</span><span class="meta">${esc(u.id)}</span></span>
      <span class="stack"><span class="meta">Installed ${esc(u.version)}</span><span class="meta version-new">New ${esc(u.available)}</span></span>
      <span class="row-actions">
        <button class="link" data-skip="${esc(u.id)}" data-version="${esc(u.available)}" title="Don't offer this version again">Skip version</button>
        <button class="link" data-ignore="${esc(u.id)}" title="Never offer updates for this app">Ignore</button>
      </span>
    </label>`;
}

async function hideApp(id, kind, version) {
  try {
    state.info.settings = kind === 'skip' ? await call('apps.skip', { id, version }) : await call('apps.ignore', { id, ignore: true });
    const u = state.apps2.check.updates.find((x) => x.id === id);
    if (u) { if (kind === 'skip') u.skipped = true; else u.ignored = true; }
    state.apps2.selected.delete(id);
    summarizeApps();
    renderApps2();
    toast(kind === 'skip' ? `Skipped this version of ${u?.name || id}.` : `${u?.name || id} won't be offered again.`);
  } catch (err) { toast(err.message, true); }
}

async function unhideApp(id, kind) {
  try {
    state.info.settings = kind === 'skip' ? await call('apps.skip', { id, version: '' }) : await call('apps.ignore', { id, ignore: false });
    const u = state.apps2.check.updates.find((x) => x.id === id);
    if (u) { u.skipped = false; u.ignored = false; }
    const p = state.apps2.check.programs.find((x) => x.id === id);
    if (p) p.ignored = false;
    summarizeApps();
    renderApps2();
  } catch (err) { toast(err.message, true); }
}

async function updateApps() {
  const a = state.apps2;
  const ids = [...a.selected];
  if (!ids.length) return;
  const ok = await confirmBox(`Update ${plural(ids.length, 'app')}?`,
    'Close the apps you are updating first. Each installer comes from the publisher and is checked against winget\'s hash before it runs.', 'Update');
  if (!ok) return;
  a.installing = true;
  a.progress = { phase: 'Starting', index: 0, total: ids.length, title: '', percent: -1 };
  renderApps2();
  try {
    a.results = await call('apps.update', { ids });
    const okCount = a.results.filter((r) => r.success).length;
    toast(okCount === a.results.length ? `Updated ${plural(okCount, 'app')}.` : `Updated ${okCount} of ${a.results.length}. See the list for details.`, okCount < a.results.length);
  } catch (err) {
    toast(`Update stopped: ${err.message}`, true);
  } finally {
    a.installing = false;
    a.progress = null;
    renderApps2();
    checkApps();
  }
}

function renderPrograms() {
  const a = state.apps2;
  const el = $('#apps-programs');
  if (!a.check) { el.innerHTML = empty(a.checking ? 'Reading your programs…' : 'Not checked yet', ''); return; }
  const q = a.query.toLowerCase();
  const all = a.check.programs;
  const list = all.filter((p) => !q || `${p.name} ${p.id}`.toLowerCase().includes(q));
  const tracked = all.filter((p) => p.source).length;
  el.innerHTML = `
    <div class="toolbar">
      <input class="search" type="search" id="progSearch" placeholder="Find a program" value="${esc(a.query)}" aria-label="Find a program">
      <span class="grow"></span>
      <span class="meta">${tracked} of ${plural(all.length, 'program')} can be updated by SystemForge</span>
    </div>
    <div class="rows">
      <div class="row head programs"><span></span><span>Program</span><span>Version</span><span>Updates</span><span></span></div>
      ${list.map((p) => `
        <div class="row programs">
          <span class="dev-icon app-mono">${esc(initials(p.name))}</span>
          <span class="stack"><span class="name">${esc(p.name)}</span><span class="meta">${p.source ? esc(p.id) : 'Not in winget\'s catalog'}</span></span>
          <span class="meta">${esc(p.version)}</span>
          <span>${p.ignored ? '<span class="tag soft">Ignored</span>' : p.hasUpdate ? '<span class="tag accent">Update available</span>' : p.source ? '<span class="tag ok">Tracked</span>' : '<span class="tag soft">Updates itself</span>'}</span>
          <span class="row-actions">${p.source ? `<button class="link" data-prog-ignore="${esc(p.id)}" data-on="${!p.ignored}">${p.ignored ? 'Track again' : 'Ignore'}</button>` : ''}</span>
        </div>`).join('') || '<div class="row"><span class="meta">No programs match.</span></div>'}
    </div>`;

  const search = $('#progSearch');
  search.addEventListener('input', () => {
    a.query = search.value;
    const pos = search.selectionStart;
    renderPrograms();
    const s2 = $('#progSearch');
    s2.focus();
    s2.setSelectionRange(pos, pos);
  });
  $$('[data-prog-ignore]', el).forEach((b) => b.addEventListener('click', async () => {
    const id = b.dataset.progIgnore;
    const ignore = b.dataset.on === 'true';
    try {
      state.info.settings = await call('apps.ignore', { id, ignore });
      const p = a.check.programs.find((x) => x.id === id);
      if (p) p.ignored = ignore;
      const u = a.check.updates.find((x) => x.id === id);
      if (u) u.ignored = ignore;
      if (ignore) a.selected.delete(id);
      summarizeApps();
      renderPrograms();
    } catch (err) { toast(err.message, true); }
  }));
}

/* ============================================================
   Security (Microsoft Defender + SystemForge's own checks)
   Checks and safety model inspired by PC Health Scan by TCPeep.
   ============================================================ */

$('#btnSecScan').addEventListener('click', () => runSecurityScan());
$$('#secTabs .tab').forEach((t) => t.addEventListener('click', () => {
  state.sec.tab = t.dataset.sectab;
  $$('#secTabs .tab').forEach((x) => x.setAttribute('aria-selected', String(x === t)));
  for (const id of ['findings', 'autoruns', 'history']) $(`#sec-${id}`).hidden = id !== t.dataset.sectab;
  if (t.dataset.sectab === 'history') loadSecurityHistory();
  renderSecurity();
}));
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-credit]')) call('system.openCredit').catch(() => {});
});

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const RISK_LABEL = { safe: 'Setting', caution: 'Changes things', guided: 'Opens Windows' };

async function loadSecurityStatus() {
  try {
    state.sec.status = await call('security.status');
  } catch (err) {
    state.sec.status = { defender: { available: false, message: err.message, otherAntivirus: [], exclusions: [] }, threats: [] };
  }
  summarizeSecurity();
  if (state.page === 'security') renderSecurity();
}

async function loadLastSecurityScan() {
  try { const last = await call('security.last'); if (last) { setSecurityScan(last); } } catch { /* none yet */ }
}

function setSecurityScan(scan) {
  const sec = state.sec;
  sec.scan = scan;
  sec.selected = new Set(scan.findings.flatMap((f) => f.actions.filter((a) => a.recommended && a.risk !== 'guided').map((a) => a.id)));
  summarizeSecurity();
  if (state.page === 'security') renderSecurity();
}

async function runSecurityScan() {
  const sec = state.sec;
  if (sec.scanning || sec.applying) return;
  sec.scanning = true;
  sec.results = null;
  sec.progress = { step: 'Starting', percent: 0 };
  $('#btnSecScan').disabled = true;
  renderSecurity();
  try {
    loadSecurityStatus();
  call('gamemode.status').then((g) => { state.game.status = g; renderGameChip(); }).catch(() => {});
    setSecurityScan(await call('security.scan'));
  } catch (err) {
    toast(`The scan stopped: ${err.message}`, true);
  } finally {
    sec.scanning = false;
    $('#btnSecScan').disabled = false;
    renderSecurity();
  }
}

on('security.progress', (p) => { state.sec.progress = p; if (state.page === 'security' && state.sec.tab === 'findings') renderSecurity(); });
on('security.fixProgress', (p) => { state.sec.applyProgress = p; if (state.page === 'security') renderSecurity(); });

function summarizeSecurity() {
  const sec = state.sec;
  const d = sec.status?.defender;
  const badge = $('#navSecurityBadge');
  const serious = sec.scan ? sec.scan.findings.filter((f) => ['Critical', 'High'].includes(f.severity)).length : 0;
  const threats = (sec.status?.threats || []).filter((t) => t.active).length;
  const n = serious + threats;
  badge.hidden = n === 0;
  badge.textContent = n;
  if (!d) return setCheck('security', 'busy', 'Checking protection…');
  const protectedNow = (d.available && d.realTime) || (d.otherAntivirus || []).some((a) => a.enabled);
  if (!protectedNow) return setCheck('security', 'bad', 'No antivirus is protecting this PC right now.');
  if (threats) return setCheck('security', 'bad', `Defender found ${plural(threats, 'threat')} that still need removing.`);
  if (sec.scan) return setCheck('security', serious ? 'attn' : 'ok', serious ? `${plural(serious, 'serious issue')} found by the last security scan.` : 'Protected, and the last security scan found nothing serious.');
  setCheck('security', 'ok', 'Protected. Run a security scan for adware and hijacks.');
}

function renderSecurity() {
  renderProtection();
  const tab = state.sec.tab;
  if (tab === 'findings') renderFindings();
  else if (tab === 'autoruns') renderAutoruns();
  else renderSecurityHistory();
}

function renderProtection() {
  const el = $('#secProtection');
  const st = state.sec.status;
  if (!st) { el.innerHTML = '<div class="panel protection"><span class="meta">Checking Microsoft Defender…</span></div>'; return; }
  const d = st.defender;
  const other = (d.otherAntivirus || []).filter((a) => a.enabled);
  const busy = state.sec.busy;
  const ago = (dt) => (dt ? fmtDate(dt) : 'Never');
  const tile = (ok, num, label, title = '') => `<div class="stat ${ok === true ? 'is-ok' : ok === false ? 'is-bad' : ''}" ${title ? `title="${esc(title)}"` : ''}><span class="stat-num small">${esc(num)}</span><span class="stat-label">${esc(label)}</span></div>`;
  const active = (st.threats || []).filter((t) => t.active);

  el.innerHTML = `
    <div class="panel protection">
      <div class="protection-head">
        <div>
          <div class="panel-title">Microsoft Defender</div>
          <p class="meta">${d.available
            ? `${d.mode === 'Normal' ? 'Running' : esc(d.mode)}${other.length ? ` · ${esc(other.map((o) => o.name).join(', '))} is also installed` : ''}`
            : esc(d.message || 'Not available')}</p>
        </div>
        <div class="protection-actions">
          <button class="btn small" data-def="update" ${busy || !d.available ? 'disabled' : ''}>${busy === 'update' ? 'Updating…' : 'Update definitions'}</button>
          <button class="btn small" data-def="quick" ${busy || !d.available ? 'disabled' : ''}>${busy === 'quick' ? 'Scanning…' : 'Quick scan'}</button>
          <button class="btn small" data-def="full" ${busy || !d.available ? 'disabled' : ''}>${busy === 'full' ? 'Scanning…' : 'Full scan'}</button>
          <button class="btn small" data-def="offline" ${busy || !d.available ? 'disabled' : ''} title="Restarts the PC and scans before Windows starts">Offline scan</button>
        </div>
      </div>
      ${d.available ? `<div class="drv-stats protection-stats">
        ${tile(d.realTime, d.realTime ? 'On' : 'Off', 'Real-time protection')}
        ${tile(d.definitionAgeDays >= 0 && d.definitionAgeDays <= 3, d.definitionAgeDays <= 0 ? 'Today' : `${d.definitionAgeDays} day${d.definitionAgeDays === 1 ? '' : 's'} old`, 'Virus definitions')}
        ${tile(null, ago(d.lastQuickScan || d.lastFullScan), 'Last scan')}
        ${tile(d.tamper, d.tamper ? 'On' : 'Off', 'Tamper protection')}
      </div>` : other.length ? `<p class="hint">${esc(other[0].name)} is protecting this PC${other[0].upToDate ? '' : ', but its definitions are out of date'}.</p>` : ''}
      ${active.length ? `
        <div class="threats">
          <div class="threats-head"><strong>${plural(active.length, 'active threat')}</strong><button class="btn danger small" data-def="remove" ${busy ? 'disabled' : ''}>${busy === 'remove' ? 'Removing…' : 'Remove all threats'}</button></div>
          ${active.map((t) => `<div class="threat"><span class="sev sev-${t.severity === 'Severe' || t.severity === 'High' ? 'high' : 'medium'}">${esc(t.severity)}</span><span class="stack"><span class="name">${esc(t.name)}</span><span class="meta">${esc(t.category)}${t.executed ? ' · it ran' : ''}${t.detected ? ` · found ${esc(fmtDate(t.detected))}` : ''}</span>${t.resources.slice(0, 2).map((r) => `<span class="path">${esc(r)}</span>`).join('')}</span></div>`).join('')}
        </div>` : ''}
    </div>`;

  $$('[data-def]', el).forEach((b) => b.addEventListener('click', () => defenderAction(b.dataset.def)));
}

async function defenderAction(kind) {
  const sec = state.sec;
  if (sec.busy) return;
  if (kind === 'offline') {
    const ok = await confirmBox('Restart into Microsoft Defender Offline?',
      'Your PC restarts now and Defender scans before Windows starts, which catches malware that hides while Windows is running. It takes about 15 minutes. Save your work first.',
      'Restart and scan', true);
    if (!ok) return;
  }
  if (kind === 'full') {
    const ok = await confirmBox('Run a full scan?', 'It checks every file and can take an hour or more. You can keep using the PC, but it may be slower.', 'Start full scan');
    if (!ok) return;
  }
  sec.busy = kind;
  renderProtection();
  try {
    const cmd = { update: ['defender.update'], quick: ['defender.scan', { full: false }], full: ['defender.scan', { full: true }], offline: ['defender.offline'], remove: ['defender.removeThreats'] }[kind];
    toast((await call(...cmd)).message);
  } catch (err) {
    toast(err.message, true);
  } finally {
    sec.busy = '';
    await loadSecurityStatus();
  }
}

function renderFindings() {
  const sec = state.sec;
  const el = $('#sec-findings');
  if (sec.applying) {
    const p = sec.applyProgress || { label: 'Starting', index: 0, total: 1 };
    el.innerHTML = `<div class="progress" role="status"><div class="step">Applying fixes · ${p.index} of ${p.total}</div><div class="detail">${esc(p.label)}</div><div class="bar"><span style="width:${Math.max(4, Math.round((p.index / Math.max(1, p.total)) * 100))}%"></span></div></div>`;
    return;
  }
  if (sec.scanning) {
    const p = sec.progress || { step: 'Starting', percent: 0 };
    el.innerHTML = `<div class="progress" role="status"><div class="step">Scanning · ${p.percent}%</div><div class="detail">${esc(p.step)}…</div><div class="bar"><span style="width:${Math.max(4, p.percent)}%"></span></div></div>`;
    return;
  }

  let html = '';
  if (sec.results) {
    html += `<div class="rows results">${sec.results.map((r) => `
      <div class="row result-row"><span class="name">${esc(r.label)}</span><span class="${r.ok ? 'result-ok' : 'result-bad'}">${esc(r.message)}</span></div>`).join('')}
      <div class="row result-row"><span class="meta">Every change is listed under History &amp; undo, where you can put it back.</span><button class="btn small" data-act="rescan">Scan again</button></div>
    </div>`;
  }
  if (!sec.scan) {
    el.innerHTML = html + empty('Not scanned yet', 'The scan only looks; nothing changes until you pick fixes. It takes about a minute.',
      '<button class="btn primary" data-act="rescan">Scan this PC</button>');
    $$('[data-act="rescan"]', el).forEach((b) => b.addEventListener('click', runSecurityScan));
    return;
  }

  const f = sec.scan.findings;
  const count = (sev) => f.filter((x) => x.severity === sev).length;
  html += `
    <div class="drv-stats sec-stats">
      <div class="stat ${count('Critical') + count('High') ? 'is-bad' : 'is-ok'}"><span class="stat-num">${count('Critical') + count('High')}</span><span class="stat-label">Serious</span></div>
      <div class="stat"><span class="stat-num">${count('Medium')}</span><span class="stat-label">Worth checking</span></div>
      <div class="stat"><span class="stat-num">${count('Low') + count('Info')}</span><span class="stat-label">For your information</span></div>
      <div class="stat is-ok"><span class="stat-num">${sec.scan.passed.length}</span><span class="stat-label">Checks passed</span></div>
    </div>
    <p class="hint">Scanned ${esc(fmtDateTime(sec.scan.scannedAt))} in ${sec.scan.seconds} s · ${sec.scan.filesChecked} recent files and ${sec.scan.autoruns.length} auto-start items checked.</p>`;

  if (!f.length) html += empty('Nothing suspicious found', 'Every check passed. Keep Microsoft Defender on and run this scan now and then.');

  for (const sev of SEV_ORDER) {
    const list = f.filter((x) => x.severity === sev);
    if (!list.length) continue;
    html += `<div class="sev-group"><div class="sev-group-title">${{ Critical: 'Critical', High: 'Serious', Medium: 'Worth checking', Low: 'Minor', Info: 'For your information' }[sev]}</div>
      ${list.map(findingCard).join('')}</div>`;
  }

  if (sec.scan.passed.length) {
    html += `<details class="passed"><summary>${plural(sec.scan.passed.length, 'check')} passed</summary><ul>${sec.scan.passed.map((p) => `<li>${esc(p)}</li>`).join('')}</ul></details>`;
  }
  if (sec.scan.notes.length) html += sec.scan.notes.map((n) => `<p class="hint">${esc(n)}</p>`).join('');

  const fixable = f.some((x) => x.actions.some((a) => a.risk !== 'guided'));
  if (fixable) {
    const picked = f.flatMap((x) => x.actions).filter((a) => sec.selected.has(a.id));
    html += `<div class="footer-bar">
      <span class="total"><strong>${picked.length}</strong> ${picked.length === 1 ? 'fix' : 'fixes'} selected</span>
      <button class="btn primary" data-act="apply" ${picked.length ? '' : 'disabled'}>Apply selected fixes</button>
    </div>`;
  }
  el.innerHTML = html;

  $$('input[data-fix]', el).forEach((cb) => cb.addEventListener('change', () => {
    cb.checked ? sec.selected.add(cb.dataset.fix) : sec.selected.delete(cb.dataset.fix);
    renderFindings();
  }));
  $$('[data-guided]', el).forEach((b) => b.addEventListener('click', async () => {
    try { const r = await call('security.fix', { ids: [b.dataset.guided] }); toast(r[0]?.message || 'Done.', r[0] && !r[0].ok); } catch (err) { toast(err.message, true); }
  }));
  $$('[data-trust]', el).forEach((b) => b.addEventListener('click', () => trustFinding(b.dataset.trust, b.dataset.title)));
  $$('[data-evidence]', el).forEach((b) => b.addEventListener('click', () => {
    const id = b.dataset.evidence;
    sec.open.has(id) ? sec.open.delete(id) : sec.open.add(id);
    renderFindings();
  }));
  $$('[data-act="rescan"]', el).forEach((b) => b.addEventListener('click', runSecurityScan));
  el.querySelector('[data-act="apply"]')?.addEventListener('click', applySecurityFixes);
}

function findingCard(x) {
  const sec = state.sec;
  const open = sec.open.has(x.id);
  const evidence = x.evidence.filter(Boolean);
  const fixes = x.actions.filter((a) => a.risk !== 'guided');
  const guided = x.actions.filter((a) => a.risk === 'guided');
  return `
    <article class="finding sev-${x.severity.toLowerCase()}">
      <header class="finding-head">
        <span class="sev sev-${x.severity.toLowerCase()}">${esc(x.severity === 'Info' ? 'Info' : x.severity)}</span>
        <span class="stack">
          <span class="name">${esc(x.title)}</span>
          ${x.detail ? `<span class="meta">${esc(x.detail)}</span>` : ''}
        </span>
        <span class="tag soft">${esc(x.category)}</span>
      </header>
      <p class="why">${esc(x.why)}</p>
      ${x.fix ? `<p class="fix-text"><strong>What to do:</strong> ${esc(x.fix)}</p>` : ''}
      ${fixes.length ? `<div class="fixes">${fixes.map((a) => `
        <label class="fix-row">
          <input type="checkbox" data-fix="${esc(a.id)}" ${sec.selected.has(a.id) ? 'checked' : ''}>
          <span>${esc(a.label)}</span>
          <span class="risk risk-${a.risk}">${esc(RISK_LABEL[a.risk] || a.risk)}</span>
        </label>`).join('')}</div>` : ''}
      <div class="finding-foot">
        ${guided.map((a) => `<button class="btn small" data-guided="${esc(a.id)}">${esc(a.label)}</button>`).join('')}
        ${evidence.length ? `<button class="link" data-evidence="${esc(x.id)}" aria-expanded="${open}">${open ? 'Hide details' : `Show details (${evidence.length})`}</button>` : ''}
        <span class="grow"></span>
        ${x.trustKey && x.severity !== 'Critical' ? `<button class="link" data-trust="${esc(x.trustKey)}" data-title="${esc(x.title)}">I recognise it — trust it</button>` : ''}
      </div>
      ${open ? `<ul class="evidence">${evidence.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}
    </article>`;
}

async function trustFinding(key, title) {
  const ok = await confirmBox('Trust this?', `"${title}" won't be flagged again. Only do this if you know what it is. You can undo it under History & undo.`, 'Trust it');
  if (!ok) return;
  try {
    state.info.settings = await call('security.trust', { key, trust: true });
    const sec = state.sec;
    sec.scan.findings = sec.scan.findings.filter((f) => f.trustKey !== key);
    sec.scan.autoruns.forEach((a) => { if (`path:${a.target || a.command}` === key) { a.trustedByYou = true; a.severity = ''; a.reasons = 'Trusted by you'; } });
    summarizeSecurity();
    renderSecurity();
    toast('Trusted. It won\'t be flagged again.');
  } catch (err) { toast(err.message, true); }
}

async function applySecurityFixes() {
  const sec = state.sec;
  const actions = sec.scan.findings.flatMap((f) => f.actions).filter((a) => sec.selected.has(a.id));
  if (!actions.length) return;
  const caution = actions.filter((a) => a.risk === 'caution');
  const offline = actions.some((a) => /Offline/.test(a.label));
  const ok = await confirmBox(`Apply ${plural(actions.length, 'fix', 'fixes')}?`,
    [
      caution.length ? `${plural(caution.length, 'of them changes', 'of them change')} things on your PC, so SystemForge makes a restore point first. Files are moved to quarantine, not deleted, and you can put everything back under History & undo.` : 'These only change settings, and you can put them back under History & undo.',
      actions.some((a) => /uninstaller/.test(a.label)) ? 'Uninstalling can\'t be undone from here.' : '',
      offline ? 'The offline scan restarts your PC at the end. Save your work first.' : '',
    ].filter(Boolean).join(' '),
    'Apply fixes', caution.length > 0);
  if (!ok) return;
  sec.applying = true;
  sec.applyProgress = { label: 'Starting', index: 0, total: actions.length };
  renderSecurity();
  try {
    sec.results = await call('security.fix', { ids: actions.map((a) => a.id) });
    const good = sec.results.filter((r) => r.ok).length;
    toast(good === sec.results.length ? `Applied ${plural(good, 'fix', 'fixes')}.` : `Applied ${good} of ${sec.results.length}. See the list for details.`, good < sec.results.length);
    // Applied fixes disappear from the list; the next scan confirms they worked.
    const done = new Set(sec.results.filter((r) => r.ok).map((r) => r.id));
    sec.scan.findings = sec.scan.findings.filter((f) => !f.actions.some((a) => done.has(a.id) && a.risk !== 'guided'));
    sec.selected = new Set([...sec.selected].filter((id) => !done.has(id)));
  } catch (err) {
    toast(err.message, true);
  } finally {
    sec.applying = false;
    sec.history = null;
    summarizeSecurity();
    renderSecurity();
    loadSecurityStatus();
  }
}

function renderAutoruns() {
  const sec = state.sec;
  const el = $('#sec-autoruns');
  if (!sec.scan) { el.innerHTML = empty('Not scanned yet', 'Scan this PC to list everything that starts automatically.'); return; }
  const q = sec.query.toLowerCase();
  const all = sec.scan.autoruns;
  const list = all.filter((a) => (!sec.onlyConcerning || a.severity) && (!q || `${a.name} ${a.command} ${a.signer} ${a.location}`.toLowerCase().includes(q)));
  el.innerHTML = `
    <div class="toolbar">
      <input class="search" type="search" id="autoSearch" placeholder="Find a program, task or service" value="${esc(sec.query)}" aria-label="Find">
      <label class="check-inline"><input type="checkbox" id="autoOnly" ${sec.onlyConcerning ? 'checked' : ''}> Only ones worth a look</label>
      <span class="grow"></span>
      <span class="meta">${list.length} of ${all.length} shown</span>
    </div>
    <div class="rows">
      <div class="row head autoruns"><span></span><span>What starts</span><span>Signed by</span><span>Why it's listed</span></div>
      ${list.map((a) => `
        <div class="row autoruns">
          <span>${a.severity ? `<span class="sev sev-${a.severity.toLowerCase()}">${esc(a.severity)}</span>` : a.trustedByYou ? '<span class="tag ok">Trusted</span>' : ''}</span>
          <span class="stack"><span class="name">${esc(a.name)}</span><span class="meta">${esc(a.type)} · ${esc(a.location)}</span><span class="path">${esc(a.command)}</span></span>
          <span class="meta">${a.signed ? esc(a.signer) : '<span class="warn-text">Not signed</span>'}</span>
          <span class="meta wrap">${esc(a.reasons || 'Looks normal')}</span>
        </div>`).join('') || `<div class="row"><span class="meta">${sec.onlyConcerning ? 'Nothing here looks unusual. Untick "Only ones worth a look" to see everything.' : 'Nothing matches.'}</span></div>`}
    </div>`;
  const search = $('#autoSearch');
  search.addEventListener('input', () => {
    sec.query = search.value;
    const pos = search.selectionStart;
    renderAutoruns();
    const s2 = $('#autoSearch'); s2.focus(); s2.setSelectionRange(pos, pos);
  });
  $('#autoOnly').addEventListener('change', (e) => { sec.onlyConcerning = e.target.checked; renderAutoruns(); });
}

async function loadSecurityHistory() {
  try { state.sec.history = await call('security.history'); } catch { state.sec.history = []; }
  if (state.page === 'security' && state.sec.tab === 'history') renderSecurityHistory();
}

function renderSecurityHistory() {
  const sec = state.sec;
  const el = $('#sec-history');
  const trustedList = (state.info?.settings?.securityTrusted || []);
  if (!sec.history) { el.innerHTML = empty('Loading…', ''); return; }
  el.innerHTML = `
    ${sec.history.length ? `<div class="rows">
      <div class="row head history"><span>When</span><span>Change</span><span></span></div>
      ${sec.history.map((h) => `
        <div class="row history">
          <span class="meta">${esc(fmtDateTime(h.when))}</span>
          <span class="stack"><span class="name">${esc(h.label)}</span><span class="meta">${h.undone ? 'Put back' : h.canUndo ? (h.kind === 'Quarantine' ? 'In quarantine' : 'Can be put back') : 'Can\'t be undone automatically'}</span></span>
          <span class="row-actions">
            ${h.canUndo && !h.undone ? `<button class="btn small" data-undo="${esc(h.id)}">Undo</button>` : ''}
            ${h.kind === 'Quarantine' && h.canUndo && !h.undone ? `<button class="link" data-purge="${esc(h.id)}">Delete for good</button>` : ''}
          </span>
        </div>`).join('')}
    </div>` : empty('No changes yet', 'Fixes you apply on the Findings tab are listed here, and most can be put back.')}
    ${trustedList.length ? `
      <div class="panel trusted-panel">
        <div class="panel-title">Things you trust</div>
        ${trustedList.map((k) => `<div class="trusted-row"><span class="path">${esc(k.replace(/^\w+:/, ''))}</span><button class="link" data-untrust="${esc(k)}">Stop trusting</button></div>`).join('')}
      </div>` : ''}`;

  $$('[data-undo]', el).forEach((b) => b.addEventListener('click', async () => {
    await withBusy(b, 'Undoing…', async () => {
      try { toast((await call('security.undo', { id: b.dataset.undo })).message); } catch (err) { toast(err.message, true); }
    });
    loadSecurityHistory();
  }));
  $$('[data-purge]', el).forEach((b) => b.addEventListener('click', async () => {
    const ok = await confirmBox('Delete for good?', 'The quarantined files are deleted permanently and this can\'t be undone. Only do this once you\'re sure nothing stopped working.', 'Delete for good', true);
    if (!ok) return;
    try { toast((await call('security.deleteQuarantined', { id: b.dataset.purge })).message); } catch (err) { toast(err.message, true); }
    loadSecurityHistory();
  }));
  $$('[data-untrust]', el).forEach((b) => b.addEventListener('click', async () => {
    try { state.info.settings = await call('security.trust', { key: b.dataset.untrust, trust: false }); toast('It will be checked again on the next scan.'); renderSecurityHistory(); }
    catch (err) { toast(err.message, true); }
  }));
}

/* ============================================================
   Settings
   ============================================================ */

const SETTINGS = [
  { key: 'overlayEnabled', title: 'Overlay', desc: () => `${state.info?.hotkey || 'Ctrl + Alt + O'} shows a small panel over any app or game (windowed or borderless) to free memory and close stuck apps. It never steals focus from what you're doing.` },
  { key: 'startWithWindows', title: 'Start with Windows', desc: () => 'Opens quietly in the tray when you sign in, so the overlay hotkey is ready right away.' },
  { key: 'appUpdateChecks', title: 'Track app updates', desc: () => 'Checks your programs for updates once a day and right after you install something new, and lets you know from the tray.' },
  { key: 'advancedDrivers', title: 'Advanced driver options', confirm: true, desc: () => 'For experienced users. Shows driver updates for storage controllers, chipset, firmware (BIOS) and unplugged devices, allows rolling back those drivers, and turns the plugged-in and pending-restart checks into warnings. Leave this off if you share SystemForge with someone who isn\'t sure.' },
  { key: 'minimizeToTray', title: 'Keep running when closed', desc: () => 'Closing the window leaves SystemForge in the tray instead of quitting.' },
];

function renderSettings() {
  const s = state.info?.settings;
  if (!s) return;
  $('#versionLine').textContent = `SystemForge ${state.info.version}${state.info.isAdmin ? ', running as administrator.' : '.'}`;
  const opacity = Math.max(40, Math.min(100, s.overlayOpacity ?? 96));
  $('#settings').innerHTML = SETTINGS.map((x) => `
    <div class="setting">
      <div>
        <div class="title">${esc(x.title)}</div>
        <div class="desc">${esc(x.desc())}</div>
      </div>
      <button class="switch" role="switch" aria-checked="${!!s[x.key]}" aria-label="${esc(x.title)}" data-key="${x.key}"></button>
    </div>${x.key === 'overlayEnabled' ? `
    <div class="setting sub">
      <div>
        <div class="title">Overlay transparency</div>
        <div class="desc">How see-through the overlay is. Lower lets more of the game show through it.</div>
      </div>
      <div class="slider-wrap">
        <input type="range" id="opacitySlider" min="40" max="100" step="1" value="${opacity}" aria-label="Overlay opacity" ${s.overlayEnabled ? '' : 'disabled'}>
        <output for="opacitySlider" id="opacityOut">${opacity}%</output>
      </div>
    </div>` : ''}`).join('');

  const slider = $('#opacitySlider');
  let opacityTimer = null;
  slider.addEventListener('input', () => {
    $('#opacityOut').textContent = `${slider.value}%`;
    slider.style.setProperty('--pct', `${(slider.value - 40) / 60 * 100}%`);
    clearTimeout(opacityTimer);
    opacityTimer = setTimeout(async () => {
      try { state.info.settings = await call('settings.opacity', { value: Number(slider.value) }); }
      catch (err) { toast(err.message, true); }
    }, 120);
  });
  slider.style.setProperty('--pct', `${(opacity - 40) / 60 * 100}%`);

  $$('#settings .switch').forEach((sw) => sw.addEventListener('click', async () => {
    const key = sw.dataset.key;
    const value = !state.info.settings[key];
    if (value && SETTINGS.find((x) => x.key === key)?.confirm) {
      const ok = await confirmBox('Turn on Advanced driver options?',
        'Drivers for storage controllers, chipset and firmware are what Windows needs to start. If one of them goes wrong, the PC can fail to boot and need System Restore from the recovery screen to fix. Only turn this on if you know how to do that.',
        'Turn on', true);
      if (!ok) return;
    }
    sw.setAttribute('aria-checked', String(value));
    try {
      state.info.settings = await call('settings.set', { key, value });
    } catch (err) {
      toast(err.message, true);
    }
    renderSettings();
    if (key === 'advancedDrivers') { summarizeDrivers(); if (state.drivers.check) renderDrivers(); }
  }));
}

/* ---- SystemForge's own updates ---- */

state.selfUpdate = { check: null, checking: false, installing: false, progress: null };

function renderUpdates() {
  const u = state.selfUpdate;
  const r = u.check;
  const el = $('#updatesPanel');
  let body;
  if (u.installing) body = `<p class="meta">${esc(u.progress || 'Starting…')}</p>`;
  else if (!r) body = '<p class="meta">Not checked yet.</p>';
  else if (r.update) {
    const d = r.update.published ? new Date(r.update.published).toLocaleDateString() : '';
    body = `<div class="update-card">
      <div><strong>SystemForge ${esc(r.update.version)}</strong> <span class="meta">${d ? `released ${esc(d)}` : ''}${r.update.sizeBytes ? ` · ${fmtBytes(r.update.sizeBytes)}` : ''}</span>
        ${r.update.notes ? `<pre class="notes">${esc(r.update.notes.slice(0, 1200))}</pre>` : ''}</div>
      <button class="btn primary" id="btnInstallUpdate">Install update</button>
    </div>`;
  } else body = `<p class="meta">${esc(r.message)}</p>`;
  el.innerHTML = `
    <div class="panel-head">
      <div><div class="panel-title">Updates</div><p class="meta">SystemForge ${esc(state.info?.version || '')}${r?.checkedAt ? ` · checked ${new Date(r.checkedAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}` : ''}</p></div>
      <button class="btn small" id="btnCheckUpdate" ${u.checking || u.installing ? 'disabled' : ''}>${u.checking ? 'Checking…' : 'Check for updates'}</button>
    </div>
    ${body}`;
  $('#btnCheckUpdate', el).addEventListener('click', checkSelfUpdate);
  $('#btnInstallUpdate', el)?.addEventListener('click', async () => {
    u.installing = true; u.progress = 'Downloading…'; renderUpdates();
    try { const res = await call('app.installUpdate'); toast(res.message); }
    catch (err) { toast(err.message, true); u.installing = false; renderUpdates(); }
  });
}

async function checkSelfUpdate() {
  const u = state.selfUpdate;
  u.checking = true; renderUpdates();
  try { u.check = await call('app.checkUpdate'); }
  catch (err) { u.check = { message: `Couldn't check: ${err.message}`, checkedAt: new Date().toISOString() }; }
  u.checking = false; renderUpdates();
}

on('app.update', (r) => { state.selfUpdate.check = r; if (state.page === 'settings') renderUpdates(); });
on('app.updateProgress', (p) => { state.selfUpdate.progress = p.percent >= 0 ? `${p.phase} ${p.percent}%` : `${p.phase}…`; if (state.page === 'settings') renderUpdates(); });

$('#overlayChip').addEventListener('click', () => {
  if (state.info && !state.info.settings.overlayEnabled) {
    toast('The overlay is turned off. Turn it on in Settings.');
    return;
  }
  call('overlay.toggle').catch((err) => toast(err.message, true));
});

/* ============================================================
   Start
   ============================================================ */

async function tick() {
  try {
    state.snap = await call('health.snapshot');
    pushHistory(state.snap);
    renderSnapshot();
    drawCharts();
  } catch { /* host not ready */ }
}

let appsCounter = 0;
setInterval(() => {
  tick();
  if (state.page === 'performance' && ++appsCounter % 2 === 0) { loadApps(); loadTemps(); }
}, 1500);

async function start() {
  renderChecks();
  sweepGauges();
  if (!hasHost) {
    $('#ovGreeting').textContent = 'Open this page inside SystemForge to see live readings.';
    return;
  }
  try {
    state.info = await call('app.info');
    $('#adminWarning').hidden = state.info.isAdmin;
    const keys = (state.info.hotkey || 'Ctrl + Alt + O').split('+').map((k) => `<kbd>${esc(k.trim())}</kbd>`).join('');
    $('#hotkeyKeys').innerHTML = keys;
    renderSpecs();
  } catch (err) {
    toast(`Couldn't read system info: ${err.message}`, true);
  }
  tick();
  loadDisks();
  loadStartup();
  scanJunk();
  // Show the last background app check (if one ran) without starting a new one.
  call('apps.last').then((r) => { if (r) setAppsResult(r); }).catch(() => {});
  loadSecurityStatus();
}

start();
