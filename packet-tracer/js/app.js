import { CanvasView } from './canvas.js';
import { DEVICE_MODELS, modelsByGroup, ROUTING_PROTOCOLS } from './device-catalog.js';
import { finalizeLab, getLabDefaults, LABS } from './labs.js';
import { getDevice } from './models.js';
import { RouterCliSession, routerPrompt } from './router-cli.js';
import { simulatePing } from './simulator.js';
import { buildArpTable, buildDnsTable, buildMacTable, buildRoutingTable } from './tables.js';

const svg = /** @type {SVGSVGElement} */ (document.getElementById('canvas'));
const labList = document.getElementById('labList');
const labGoal = document.getElementById('labGoal');
const labsModal = document.getElementById('labsModal');
const propsPanel = document.getElementById('propsPanel');
const cliOutput = document.getElementById('cliOutput');
const cliInput = /** @type {HTMLInputElement} */ (document.getElementById('cliInput'));
const cliSection = document.getElementById('cliSection');
const cliEmpty = document.getElementById('cliEmpty');
const simLog = document.getElementById('simLog');
const simStatus = document.getElementById('simStatus');
const pingDest = /** @type {HTMLInputElement} */ (document.getElementById('pingDest'));
const pingSource = /** @type {HTMLSelectElement} */ (document.getElementById('pingSource'));

/** @type {CanvasView} */
let canvas;
/** @type {RouterCliSession | null} */
let cliSession = null;
/** @type {string | null} */
let cliDeviceId = null;
/** @type {string | null} */
let selectedDeviceId = null;
/** @type {string} */
let activeLabId = 'star-lan';
/** @type {string} */
let activeTab = 'config';

function init() {
  setupDesktopShell();

  canvas = new CanvasView(
    svg,
    () => {
      refreshPingSources();
      syncCliRouter();
      if (selectedDeviceId) refreshInspector(selectedDeviceId);
    },
    (deviceId) => {
      selectedDeviceId = deviceId;
      renderProps(deviceId);
      setupCli(deviceId);
      refreshInspector(deviceId);
    },
  );

  renderDevicePalette();
  renderLabs();
  loadLab('star-lan');
  bindToolbar();
  bindInspectorTabs();
  bindLabsModal();
}

function bindToolbar() {
  document.getElementById('btnSelect').addEventListener('click', () => setTool('select'));
  document.getElementById('btnPan').addEventListener('click', () => setTool('pan'));
  document.getElementById('btnConnect').addEventListener('click', () => setTool('connect'));
  document.getElementById('btnDelete').addEventListener('click', () => canvas.deleteSelected());
  document.getElementById('btnResetView').addEventListener('click', () => canvas.resetView());
  document.getElementById('btnPing').addEventListener('click', () => runPing());
  document.getElementById('btnClearLog').addEventListener('click', () => {
    simLog.innerHTML = '';
    simStatus.textContent = 'Log cleared.';
  });

  cliInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      submitCli(cliInput.value);
      cliInput.value = '';
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (cliSession) cliInput.value = cliSession.prevHistory();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (cliSession) cliInput.value = cliSession.nextHistory();
    }
  });
}

function bindInspectorTabs() {
  document.querySelectorAll('.insp-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeTab = btn.dataset.tab ?? 'config';
      document.querySelectorAll('.insp-tab').forEach((b) => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.insp-panel').forEach((p) => {
        p.classList.toggle('active', p.id === `panel${capitalize(activeTab)}`);
      });
      if (selectedDeviceId) refreshInspector(selectedDeviceId);
    });
  });
}

function bindLabsModal() {
  document.getElementById('btnLabs').addEventListener('click', openLabsModal);
  document.getElementById('btnCloseLabs').addEventListener('click', closeLabsModal);
  document.getElementById('labsBackdrop').addEventListener('click', closeLabsModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeLabsModal();
  });
}

function openLabsModal() {
  labsModal.classList.remove('hidden');
  labsModal.setAttribute('aria-hidden', 'false');
  renderLabs();
}

function closeLabsModal() {
  labsModal.classList.add('hidden');
  labsModal.setAttribute('aria-hidden', 'true');
}

function renderDevicePalette() {
  const root = document.getElementById('devicePalette');
  root.replaceChildren();

  for (const group of [
    { key: 'pc', label: '+ Host' },
    { key: 'switch', label: '+ Switch' },
    { key: 'router', label: '+ Router' },
  ]) {
    const sel = document.createElement('select');
    sel.className = 'tb-select';
    sel.setAttribute('aria-label', `Add ${group.label.replace('+ ', '')}`);
    const ph = document.createElement('option');
    ph.value = '';
    ph.textContent = group.label;
    sel.appendChild(ph);
    for (const [key, spec] of modelsByGroup(group.key)) {
      const opt = document.createElement('option');
      opt.value = key;
      opt.textContent = `${spec.icon} ${spec.label}`;
      sel.appendChild(opt);
    }
    sel.addEventListener('change', () => {
      if (sel.value) {
        canvas.addDevice(sel.value);
        sel.value = '';
      }
    });
    root.appendChild(sel);
  }
}

function setTool(tool) {
  canvas.setMode(tool);
  document.querySelectorAll('.tool-btn').forEach((b) => b.classList.remove('active'));
  const map = { select: 'btnSelect', pan: 'btnPan', connect: 'btnConnect' };
  document.getElementById(map[tool] ?? 'btnSelect')?.classList.add('active');
}

function renderLabs() {
  labList.replaceChildren();
  const categories = [...new Set(LABS.map((l) => l.category))];
  for (const cat of categories) {
    const label = document.createElement('div');
    label.className = 'lab-category';
    label.textContent = cat;
    labList.appendChild(label);

    for (const lab of LABS.filter((l) => l.category === cat)) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'lab-card' + (lab.id === activeLabId ? ' active' : '');
      btn.innerHTML = `<strong>${lab.title}</strong><span>${lab.description}</span><em>Goal: ${lab.goal}</em>`;
      btn.addEventListener('click', () => {
        loadLab(lab.id);
        closeLabsModal();
      });
      labList.appendChild(btn);
    }
  }
}

function loadLab(labId) {
  const lab = LABS.find((l) => l.id === labId);
  if (!lab) return;
  activeLabId = labId;
  canvas.load(finalizeLab(lab.build()));
  canvas.resetView();
  simLog.innerHTML = '';
  simStatus.textContent = lab.goal;
  labGoal.textContent = `📋 ${lab.goal}`;
  pingDest.value = getLabDefaults(labId).pingDest;
  refreshPingSources();
  selectedDeviceId = null;
  renderProps(null);
  setupCli(null);
  renderLabs();
  switchTab('log');
}

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.insp-tab').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  document.querySelectorAll('.insp-panel').forEach((p) => {
    p.classList.toggle('active', p.id === `panel${capitalize(tab)}`);
  });
}

function refreshPingSources() {
  const topo = canvas.getTopology();
  const pcs = topo.devices.filter((d) => d.type === 'pc' && d.role !== 'dns');
  pingSource.replaceChildren();
  for (const pc of pcs) {
    const opt = document.createElement('option');
    opt.value = pc.id;
    opt.textContent = `${pc.name} (${pc.ip})`;
    pingSource.appendChild(opt);
  }
  if (pcs.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No PC';
    pingSource.appendChild(opt);
  }
}

/** @param {string | null} deviceId */
function refreshInspector(deviceId) {
  renderTables(deviceId);
}

/** @param {string | null} deviceId */
function renderTables(deviceId) {
  const topo = canvas.getTopology();
  const dev = deviceId ? getDevice(topo, deviceId) : null;

  renderTable(
    'routingTable',
    ['Network', 'Next hop', 'Iface', 'Proto', 'Source'],
    dev?.type === 'router'
      ? buildRoutingTable(topo, dev).map((r) => [r.network, r.nextHop, r.iface, r.protocol, r.admin])
      : [],
    dev?.type === 'router' ? null : 'Select a router to view its routing table.',
  );

  renderTable(
    'arpTable',
    ['IP address', 'MAC address', 'Type', 'Interface'],
    dev && (dev.type === 'pc' || dev.type === 'router')
      ? buildArpTable(topo, dev).map((r) => [r.ip, r.mac, r.type, r.iface])
      : [],
    dev ? (dev.type === 'switch' ? 'ARP is used by PCs and routers, not switches.' : null) : 'Select a PC or router.',
  );

  renderTable(
    'macTable',
    ['MAC address', 'Port', 'Type', 'Device'],
    dev && (dev.type === 'switch' || dev.type === 'router')
      ? buildMacTable(topo, dev).map((r) => [r.mac, r.port, r.type, r.vendor])
      : [],
    dev ? (dev.type === 'pc' ? 'MAC tables live on switches and routers.' : null) : 'Select a switch or router.',
  );

  const dnsRows = buildDnsTable(topo);
  renderTable(
    'dnsTable',
    ['Hostname', 'IP', 'Type', 'Server'],
    dnsRows.map((r) => [r.name, r.ip, r.type, r.server]),
    dnsRows.length ? null : 'Add a DNS Server device or load Lab 6.',
  );
}

function renderTable(containerId, headers, rows, emptyMsg) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<p class="empty-table">${esc(emptyMsg ?? 'No entries yet.')}</p>`;
    return;
  }
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join('');
  const body = rows.map((row) => `<tr>${row.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('');
  el.innerHTML = `<table class="data-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

/** @param {string | null} deviceId */
function renderProps(deviceId) {
  if (!deviceId) {
    propsPanel.innerHTML = '<p class="muted">Click a device on the canvas to configure it and view routing, ARP, MAC, and DNS tables in the tabs above.</p>';
    return;
  }
  const dev = getDevice(canvas.getTopology(), deviceId);
  if (!dev) return;

  const modelInfo = dev.modelLabel
    ? `<span class="model-badge">${esc(dev.modelLabel)}</span>`
    : '';

  if (dev.type === 'pc') {
    const dnsEdit =
      dev.role === 'dns'
        ? `<label>DNS records (name=ip, one per line)<textarea data-field="dnsRecordsText" rows="4">${esc(dnsRecordsToText(dev.dnsRecords))}</textarea></label>`
        : '';
    propsPanel.innerHTML = `
      <h3>${esc(dev.name)} <span class="badge">PC</span> ${modelInfo}</h3>
      <div class="info-box">PCs use <strong>ARP</strong> to find MAC addresses, <strong>DNS</strong> for names, and a <strong>default gateway</strong> to reach other subnets.</div>
      <label>Name<input data-field="name" value="${esc(dev.name)}" /></label>
      <label>IP address<input data-field="ip" value="${esc(dev.ip ?? '')}" /></label>
      <label>Subnet mask<input data-field="mask" value="${esc(dev.mask ?? '')}" /></label>
      <label>Default gateway<input data-field="gateway" value="${esc(dev.gateway ?? '')}" /></label>
      <label>DNS server<input data-field="dnsServer" value="${esc(dev.dnsServer ?? '')}" placeholder="192.168.1.53" /></label>
      <label>MAC<input data-field="mac" value="${esc(dev.mac)}" readonly /></label>
      ${dnsEdit}
    `;
  } else if (dev.type === 'switch') {
    const ports = (dev.ports ?? [])
      .map((p) => `<li>${p.name} — ${p.linkId ? '🔗 connected' : 'free'}</li>`)
      .join('');
    propsPanel.innerHTML = `
      <h3>${esc(dev.name)} <span class="badge">Switch</span> ${modelInfo}</h3>
      <div class="info-box"><strong>MAC learning:</strong> the switch builds a MAC table (see MAC tab) and forwards frames only to the correct port — unlike a hub that floods everywhere.</div>
      <label>Name<input data-field="name" value="${esc(dev.name)}" /></label>
      <ul class="port-list">${ports}</ul>
    `;
  } else {
    const protoOpts = ROUTING_PROTOCOLS.map(
      (p) =>
        `<option value="${p.id}"${dev.routingProtocol === p.id ? ' selected' : ''}>${p.label} — ${p.desc}</option>`,
    ).join('');
    const ifaces = (dev.ports ?? [])
      .map(
        (p, i) => `
      <label>${p.name} IP<input data-rport="${i}" data-field="ip" value="${esc(p.ip ?? '')}" /></label>
      <label>${p.name} Mask<input data-rport="${i}" data-field="mask" value="${esc(p.mask ?? '')}" /></label>
      <label>${p.name} Status<input readonly value="${p.shutdown ? 'admin down' : 'up/up'}" /></label>
    `,
      )
      .join('');
    propsPanel.innerHTML = `
      <h3>${esc(dev.hostname ?? dev.name)} <span class="badge">Router</span> ${modelInfo}</h3>
      <div class="info-box">Routers route between networks using a <strong>routing table</strong>. Use static routes, or enable <strong>RIP</strong>/<strong>OSPF</strong> to learn routes automatically (simulated).</div>
      <label>Hostname<input data-field="hostname" value="${esc(dev.hostname ?? dev.name)}" /></label>
      <label>Routing protocol<select data-field="routingProtocol">${protoOpts}</select></label>
      ${ifaces}
    `;
  }

  propsPanel.querySelectorAll('input[data-field], select[data-field], textarea[data-field]').forEach((input) => {
    input.addEventListener('change', () => applyProps(deviceId));
  });
}

function applyProps(deviceId) {
  const topo = canvas.getTopology();
  const dev = getDevice(topo, deviceId);
  if (!dev) return;

  propsPanel.querySelectorAll('input[data-field], select[data-field], textarea[data-field]').forEach((input) => {
    const el = /** @type {HTMLInputElement} */ (input);
    const field = el.dataset.field;
    const rport = el.dataset.rport;
    if (!field) return;

    if (field === 'dnsRecordsText' && dev.role === 'dns') {
      dev.dnsRecords = textToDnsRecords(el.value);
      return;
    }
    if (dev.type === 'router' && rport !== undefined) {
      const port = dev.ports?.[Number(rport)];
      if (port) port[field] = el.value;
    } else if (field === 'hostname' && dev.type === 'router') {
      dev.hostname = el.value;
      dev.name = el.value;
    } else if (field === 'routingProtocol' && dev.type === 'router') {
      dev.routingProtocol = el.value;
    } else if (field !== 'mac') {
      dev[field] = el.value;
    }
  });

  canvas.load(topo);
  refreshPingSources();
  syncCliRouter();
  refreshInspector(deviceId);
}

function dnsRecordsToText(records) {
  if (!records) return '';
  return Object.entries(records)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
}

function textToDnsRecords(text) {
  const out = {};
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const [name, ip] = t.split('=').map((s) => s.trim());
    if (name && ip) out[name] = ip;
  }
  return out;
}

/** @param {string | null} deviceId */
function setupCli(deviceId) {
  if (!deviceId) {
    cliSection.classList.remove('active');
    cliEmpty.style.display = 'block';
    cliSession = null;
    cliDeviceId = null;
    return;
  }
  const dev = getDevice(canvas.getTopology(), deviceId);
  if (!dev || dev.type !== 'router') {
    cliSection.classList.remove('active');
    cliEmpty.style.display = 'block';
    cliSession = null;
    cliDeviceId = null;
    return;
  }

  cliSection.classList.add('active');
  cliEmpty.style.display = 'none';

  if (cliDeviceId !== deviceId) {
    cliDeviceId = deviceId;
    cliOutput.innerHTML = '';
    appendCliLine(`Connected to ${dev.hostname ?? dev.name}. Type <code>enable</code> to begin.`, 'system');
    cliSession = new RouterCliSession(dev, () => {
      canvas.load(canvas.getTopology());
      refreshPingSources();
      renderProps(deviceId);
      refreshInspector(deviceId);
    });
  }
  updateCliPrompt();
}

function syncCliRouter() {
  if (!cliDeviceId || !cliSession) return;
  const dev = getDevice(canvas.getTopology(), cliDeviceId);
  if (dev?.type === 'router') {
    cliSession.router = dev;
    updateCliPrompt();
  }
}

function submitCli(line) {
  if (!cliSession) return;
  appendCliLine(`${routerPrompt(cliSession.router, cliSession.mode, null)} ${line}`, 'input');
  for (const ln of cliSession.exec(line)) appendCliLine(ln, 'output');
  updateCliPrompt();
  if (selectedDeviceId) refreshInspector(selectedDeviceId);
}

function updateCliPrompt() {
  if (!cliSession) return;
  document.getElementById('cliPrompt').textContent = routerPrompt(cliSession.router, cliSession.mode, null);
}

function appendCliLine(text, kind) {
  const div = document.createElement('div');
  div.className = `cli-line cli-${kind}`;
  div.innerHTML = text;
  cliOutput.appendChild(div);
  cliOutput.scrollTop = cliOutput.scrollHeight;
}

async function runPing() {
  const srcId = pingSource.value;
  const dest = pingDest.value.trim();
  if (!srcId || !dest) {
    simStatus.textContent = 'Choose a source PC and destination.';
    return;
  }

  simLog.innerHTML = '';
  simStatus.textContent = 'Simulating…';
  switchTab('log');

  const result = simulatePing(canvas.getTopology(), srcId, dest);

  if (!result.ok) {
    for (const step of result.steps) appendStep(step);
    simStatus.textContent = result.error ?? 'Simulation failed.';
    if (selectedDeviceId) refreshInspector(selectedDeviceId);
    return;
  }

  simStatus.textContent = `Animating ${result.steps.length} hops…`;

  await canvas.animateSteps(result.steps, (step, hop, total) => {
    appendStep(step);
    highlightActiveStep();
    simStatus.textContent = `Hop ${hop}/${total} · ${step.layer} — ${step.title}`;
  });

  simLog.querySelectorAll('.sim-step').forEach((el) => {
    el.classList.remove('sim-step-active');
    el.classList.add('sim-step-done');
  });

  simStatus.textContent = `✓ Ping path complete → ${result.resolvedIp ?? dest}`;
  if (selectedDeviceId) refreshInspector(selectedDeviceId);
}

function highlightActiveStep() {
  const entries = simLog.querySelectorAll('.sim-step');
  entries.forEach((el, i) => {
    const active = i === entries.length - 1;
    el.classList.toggle('sim-step-active', active);
    el.classList.toggle('sim-step-done', !active);
  });
  simLog.scrollTop = simLog.scrollHeight;
}

function appendStep(step) {
  const div = document.createElement('div');
  div.className = 'sim-step sim-step-pending';
  div.dataset.layer = step.layer;
  div.innerHTML = `
    <span class="layer">${esc(step.layer)}</span>
    <strong>${esc(step.title)}</strong>
    <p>${esc(step.detail)}</p>
  `;
  simLog.appendChild(div);
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setupDesktopShell() {
  if (!window.pktanaDesktop?.isDesktop) return;

  document.body.classList.add('desktop-app');
  document.querySelector('.learn-link')?.remove();
  const brand = document.querySelector('.brand');
  if (brand) {
    brand.removeAttribute('href');
    brand.style.cursor = 'default';
  }

  // ── File operation helpers ─────────────────────────────────────────────────
  // Note: canvas is initialized after this function returns; closures are safe
  // because these callbacks only fire on user action, after init() completes.

  const doNew = () => {
    canvas.load({ devices: [], links: [] });
    canvas.resetView();
    simLog.innerHTML = '';
    simStatus.textContent = 'New topology — add devices from the palette.';
    selectedDeviceId = null;
    renderProps(null);
    setupCli(null);
    refreshPingSources();
  };

  const doOpen = async () => {
    const result = await window.pktanaDesktop.openFile();
    if (!result) return;
    try {
      const topo = JSON.parse(result.content);
      canvas.load(topo);
      canvas.resetView();
      refreshPingSources();
      simStatus.textContent = `Opened: ${result.path.split(/[/\\]/).pop()}`;
    } catch {
      simStatus.textContent = 'Failed to open file — not a valid lab JSON.';
    }
  };

  const doSave = async () => {
    const json = JSON.stringify(canvas.getTopology(), null, 2);
    const saved = await window.pktanaDesktop.saveFile(json, 'lab.json');
    if (saved) simStatus.textContent = `Saved: ${String(saved).split(/[/\\]/).pop()}`;
  };

  // ── Menu event listeners (sent from Electron main process) ────────────────
  window.pktanaDesktop.onNew(doNew);
  window.pktanaDesktop.onOpen(doOpen);
  window.pktanaDesktop.onSave(doSave);
  window.pktanaDesktop.onPrint(() => window.pktanaDesktop.print());

  // ── Keyboard shortcuts (Ctrl/Cmd + N/O/S/P) ──────────────────────────────
  document.addEventListener('keydown', (e) => {
    if (!e.ctrlKey && !e.metaKey) return;
    switch (e.key.toLowerCase()) {
      case 'n': e.preventDefault(); doNew(); break;
      case 'o': e.preventDefault(); doOpen(); break;
      case 's': e.preventDefault(); doSave(); break;
      case 'p': e.preventDefault(); window.pktanaDesktop.print(); break;
    }
  });

  // ── Toolbar buttons: New / Open / Save ────────────────────────────────────
  const firstGroup = document.querySelector('.toolbar-group');
  if (firstGroup) {
    const sep = document.createElement('span');
    sep.className = 'tb-sep';

    const btnNew = document.createElement('button');
    btnNew.type = 'button';
    btnNew.className = 'tb-btn';
    btnNew.title = 'New empty topology (Ctrl+N)';
    btnNew.innerHTML = '<span class="tb-icon" aria-hidden="true">🗋</span><span class="tb-label">New</span>';
    btnNew.addEventListener('click', doNew);

    const btnOpen = document.createElement('button');
    btnOpen.type = 'button';
    btnOpen.className = 'tb-btn';
    btnOpen.title = 'Open saved lab (Ctrl+O)';
    btnOpen.innerHTML = '<span class="tb-icon" aria-hidden="true">📂</span><span class="tb-label">Open</span>';
    btnOpen.addEventListener('click', doOpen);

    const btnSave = document.createElement('button');
    btnSave.type = 'button';
    btnSave.className = 'tb-btn';
    btnSave.title = 'Save topology as JSON (Ctrl+S)';
    btnSave.innerHTML = '<span class="tb-icon" aria-hidden="true">💾</span><span class="tb-label">Save</span>';
    btnSave.addEventListener('click', doSave);

    firstGroup.append(sep, btnNew, btnOpen, btnSave);
  }
}

init();
