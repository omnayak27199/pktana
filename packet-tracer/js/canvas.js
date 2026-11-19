import { DEVICE_MODELS } from './device-catalog.js';
import {
  arriveLabel,
  deviceCenter,
  easeInOut,
  layerColor,
  sleep,
} from './flow-animation.js';
import {
  linkDrawPoints,
  linkRoutePoints,
  pointOnPolyline,
  pointsToPathD,
} from './link-routing.js';
import { createDevice, getDevice, uid } from './models.js';

function iconFor(dev) {
  if (dev.modelKey && DEVICE_MODELS[dev.modelKey]) return DEVICE_MODELS[dev.modelKey].icon;
  if (dev.type === 'pc') return '🖥️';
  if (dev.type === 'switch') return '🔀';
  return '📡';
}

/** @param {import('./models.js').Topology} topo */
export class CanvasView {
  /** @param {SVGElement} svg @param {(topo: import('./models.js').Topology) => void} onChange @param {(deviceId: string | null) => void} onSelect */
  constructor(svg, onChange, onSelect) {
    this.svg = svg;
    this.onChange = onChange;
    this.onSelect = onSelect;
    /** @type {import('./models.js').Topology} */
    this.topo = { devices: [], links: [] };
    this.selectedId = null;
    this.connectFrom = null;
    /** @type {'select' | 'connect' | 'pan'} */
    this.mode = 'select';
    this.drag = null;
    this.pan = null;
    this.view = { x: 0, y: 0, scale: 1 };

    this.viewport = mkGroup('canvas-viewport');
    this.layers = {
      links: mkGroup('links-layer'),
      linkFx: mkGroup('link-fx-layer'),
      devices: mkGroup('devices-layer'),
      deviceFx: mkGroup('device-fx-layer'),
      packet: mkGroup('packet-layer'),
      callouts: mkGroup('callout-layer'),
    };
    this.viewport.append(...Object.values(this.layers));
    svg.appendChild(this.viewport);

    svg.addEventListener('pointerdown', (e) => this.onPointerDown(e));
    svg.addEventListener('pointermove', (e) => this.onPointerMove(e));
    svg.addEventListener('pointerup', (e) => this.onPointerUp(e));
    svg.addEventListener('pointercancel', (e) => this.onPointerUp(e));
    svg.addEventListener('wheel', (e) => this.onWheel(e), { passive: false });

    this.applyViewTransform();
  }

  /** @param {'select' | 'connect' | 'pan'} mode */
  setMode(mode) {
    this.mode = mode;
    this.connectFrom = null;
    this.svg.classList.toggle('mode-pan', mode === 'pan');
    this.svg.classList.toggle('mode-connect', mode === 'connect');
    this.render();
  }

  resetView() {
    this.view = { x: 0, y: 0, scale: 1 };
    this.applyViewTransform();
  }

  applyViewTransform() {
    this.viewport.setAttribute(
      'transform',
      `translate(${this.view.x} ${this.view.y}) scale(${this.view.scale})`,
    );
  }

  /** @param {import('./models.js').Topology} topo */
  load(topo) {
    this.topo = structuredClone(topo);
    this.selectedId = null;
    this.connectFrom = null;
    this.render();
  }

  getTopology() {
    return structuredClone(this.topo);
  }

  select(deviceId) {
    this.selectedId = deviceId;
    this.onSelect(deviceId);
    this.render();
  }

  /** @param {string} modelKey */
  addDevice(modelKey) {
    const center = this.viewCenterWorld();
    const dev = createDevice(modelKey, center.x - 40, center.y - 36);
    this.topo.devices.push(dev);
    this.onChange(this.getTopology());
    this.select(dev.id);
    this.render();
  }

  viewCenterWorld() {
    const rect = this.svg.getBoundingClientRect();
    return this.screenToWorld(rect.left + rect.width / 2, rect.top + rect.height / 2);
  }

  deleteSelected() {
    if (!this.selectedId) return;
    const id = this.selectedId;
    const removedLinkIds = new Set(
      this.topo.links.filter((l) => l.aDeviceId === id || l.bDeviceId === id).map((l) => l.id),
    );
    this.topo.links = this.topo.links.filter((l) => l.aDeviceId !== id && l.bDeviceId !== id);
    for (const d of this.topo.devices) {
      for (const p of d.ports ?? []) {
        if (p.linkId && removedLinkIds.has(p.linkId)) p.linkId = null;
      }
    }
    this.topo.devices = this.topo.devices.filter((d) => d.id !== id);
    this.selectedId = null;
    this.onChange(this.getTopology());
    this.onSelect(null);
    this.render();
  }

  async animateSteps(steps, onStep) {
    this.clearFlowFx();
    let hop = 0;
    for (const step of steps) {
      hop += 1;
      if (onStep) onStep(step, hop, steps.length);

      const from = step.fromDeviceId ? getDevice(this.topo, step.fromDeviceId) : null;
      const to = step.toDeviceId ? getDevice(this.topo, step.toDeviceId) : null;
      const at = step.atDeviceId ? getDevice(this.topo, step.atDeviceId) : null;
      const colors = layerColor(step.layer);
      const label = step.packetLabel ?? step.layer;

      if (from) this.ensureVisible(from);
      if (to) this.ensureVisible(to);
      if (at) this.ensureVisible(at);

      // ── Phase A: show what happens at the source / processing node ──
      const processDev = from ?? at;
      if (processDev) {
        this.drawDeviceHighlight(processDev, colors, 'pulse');
        const detail = step.detail.length > 72 ? `${step.detail.slice(0, 72)}…` : step.detail;
        this.drawCallout(processDev, hop, step.layer, step.title, detail, colors);
        if (step.title.toLowerCase().includes('arp')) {
          this.drawBroadcast(processDev, colors);
        }
        await sleep(1100);
      }

      // ── Phase B: travel to next hop ──
      if (from && to) {
        this.drawLinkHighlight(from, to, colors);
        await this.animateTravel(from, to, label, colors);
        this.clearLayer('packet');

        // ── Phase C: arrived — explain what the device does ──
        this.drawDeviceHighlight(to, colors, 'arrive');
        this.drawCallout(to, hop, step.layer, arriveLabel(step, to), step.detail.slice(0, 72) + (step.detail.length > 72 ? '…' : ''), colors);
        await sleep(1400);
      } else if (!from && !to && at) {
        await sleep(600);
      }

      this.clearFlowFx();
    }
  }

  ensureVisible(dev) {
    const c = deviceCenter(dev);
    const rect = this.svg.getBoundingClientRect();
    const pt = this.svg.createSVGPoint();
    pt.x = c.x;
    pt.y = c.y;
    const ctm = this.viewport.getScreenCTM();
    if (!ctm) return;
    const screen = pt.matrixTransform(ctm);
    const margin = 80;
    let dx = 0;
    let dy = 0;
    if (screen.x < rect.left + margin) dx = rect.left + margin - screen.x;
    if (screen.x > rect.right - margin) dx = rect.right - margin - screen.x;
    if (screen.y < rect.top + margin) dy = rect.top + margin - screen.y;
    if (screen.y > rect.bottom - margin) dy = rect.bottom - margin - screen.y;
    if (dx || dy) {
      this.view.x += dx;
      this.view.y += dy;
      this.applyViewTransform();
    }
  }

  drawDeviceHighlight(dev, colors, kind) {
    const c = deviceCenter(dev);
    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    ring.setAttribute('cx', String(c.x));
    ring.setAttribute('cy', String(c.y));
    ring.setAttribute('r', kind === 'arrive' ? '52' : '46');
    ring.setAttribute('fill', 'none');
    ring.setAttribute('stroke', colors.stroke);
    ring.setAttribute('stroke-width', kind === 'arrive' ? '3' : '2');
    ring.setAttribute('class', kind === 'arrive' ? 'fx-ring fx-ring-arrive' : 'fx-ring fx-ring-pulse');
    ring.style.filter = `drop-shadow(0 0 8px ${colors.glow})`;

    const badge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    badge.setAttribute('x', String(dev.x + 40));
    badge.setAttribute('y', String(dev.y - 8));
    badge.setAttribute('text-anchor', 'middle');
    badge.setAttribute('class', 'fx-device-badge');
    badge.textContent = dev.name;

    this.layers.deviceFx.append(ring, badge);
  }

  drawLinkHighlight(from, to, colors) {
    const points = linkRoutePoints(from, to);
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', pointsToPathD(points));
    path.setAttribute('fill', 'none');
    path.setAttribute('class', 'fx-link-active');
    path.setAttribute('stroke', colors.stroke);
    this.layers.linkFx.appendChild(path);
  }

  drawBroadcast(dev, colors) {
    const c = deviceCenter(dev);
    for (let i = 0; i < 3; i++) {
      const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      ring.setAttribute('cx', String(c.x));
      ring.setAttribute('cy', String(c.y));
      ring.setAttribute('r', String(20 + i * 18));
      ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', colors.stroke);
      ring.setAttribute('stroke-width', '1.5');
      ring.setAttribute('class', `fx-broadcast fx-broadcast-${i}`);
      ring.style.opacity = String(0.7 - i * 0.2);
      this.layers.deviceFx.appendChild(ring);
    }
  }

  drawCallout(dev, hop, layer, title, subtitle, colors) {
    const flip = dev.x > 1100;
    const x = flip ? dev.x - 208 : dev.x + 88;
    const y = dev.y + 4;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('class', 'fx-callout');
    g.setAttribute('transform', `translate(${x}, ${y})`);

    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bg.setAttribute('x', '0');
    bg.setAttribute('y', '0');
    bg.setAttribute('width', '200');
    bg.setAttribute('height', '58');
    bg.setAttribute('rx', '8');
    bg.setAttribute('class', 'fx-callout-bg');
    bg.setAttribute('stroke', colors.stroke);

    const hopT = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    hopT.setAttribute('x', '8');
    hopT.setAttribute('y', '14');
    hopT.setAttribute('class', 'fx-callout-hop');
    hopT.textContent = `Hop ${hop} · ${layer}`;

    const titleT = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    titleT.setAttribute('x', '8');
    titleT.setAttribute('y', '30');
    titleT.setAttribute('class', 'fx-callout-title');
    titleT.textContent = title.length > 28 ? `${title.slice(0, 28)}…` : title;

    const subT = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    subT.setAttribute('x', '8');
    subT.setAttribute('y', '46');
    subT.setAttribute('class', 'fx-callout-sub');
    subT.textContent = subtitle.length > 38 ? `${subtitle.slice(0, 38)}…` : subtitle;

    g.append(bg, hopT, titleT, subT);
    this.layers.callouts.appendChild(g);
  }

  animateTravel(from, to, label, colors) {
    return new Promise((resolve) => {
      const points = linkRoutePoints(from, to);
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', 'fx-packet');

      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      dot.setAttribute('r', '10');
      dot.setAttribute('fill', colors.fill);
      dot.setAttribute('stroke', '#fff');
      dot.setAttribute('stroke-width', '2');
      dot.style.filter = `drop-shadow(0 0 6px ${colors.glow})`;

      const trail = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      trail.setAttribute('r', '16');
      trail.setAttribute('fill', colors.glow);
      trail.setAttribute('class', 'fx-packet-trail');

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('class', 'fx-packet-label');
      text.textContent = label.slice(0, 14);

      g.append(trail, dot, text);
      this.layers.packet.appendChild(g);

      const start = performance.now();
      const duration = Math.max(900, Math.min(1600, polylineLength(points) * 2.2));
      const tick = (now) => {
        const t = easeInOut(Math.min(1, (now - start) / duration));
        const pos = pointOnPolyline(points, t);
        dot.setAttribute('cx', String(pos.x));
        dot.setAttribute('cy', String(pos.y));
        trail.setAttribute('cx', String(pos.x));
        trail.setAttribute('cy', String(pos.y));
        text.setAttribute('x', String(pos.x + 14));
        text.setAttribute('y', String(pos.y + 4));
        if (t < 1) requestAnimationFrame(tick);
        else resolve();
      };
      requestAnimationFrame(tick);
    });
  }

  clearLayer(name) {
    const key = name === 'packet' ? 'packet' : name;
    if (this.layers[key]) this.layers[key].replaceChildren();
  }

  clearFlowFx() {
    this.layers.linkFx.replaceChildren();
    this.layers.deviceFx.replaceChildren();
    this.layers.packet.replaceChildren();
    this.layers.callouts.replaceChildren();
  }

  clearPacket() {
    this.clearFlowFx();
  }

  render() {
    this.renderLinks();
    this.renderDevices();
  }

  renderLinks() {
    this.layers.links.replaceChildren();
    for (const link of this.topo.links) {
      const a = getDevice(this.topo, link.aDeviceId);
      const b = getDevice(this.topo, link.bDeviceId);
      if (!a || !b) continue;
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', pointsToPathD(linkDrawPoints(a, b)));
      path.setAttribute('fill', 'none');
      path.setAttribute('class', 'topology-link');
      this.layers.links.appendChild(path);
    }
  }

  renderDevices() {
    this.layers.devices.replaceChildren();
    for (const dev of this.topo.devices) {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', `device device-${dev.type}${dev.id === this.selectedId ? ' selected' : ''}`);
      g.setAttribute('transform', `translate(${dev.x}, ${dev.y})`);
      g.dataset.deviceId = dev.id;

      const body = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      body.setAttribute('width', '80');
      body.setAttribute('height', '72');
      body.setAttribute('rx', '10');
      body.setAttribute('class', 'device-body');

      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      icon.setAttribute('x', '40');
      icon.setAttribute('y', '32');
      icon.setAttribute('text-anchor', 'middle');
      icon.setAttribute('class', 'device-icon');
      icon.textContent = iconFor(dev);

      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', '40');
      label.setAttribute('y', '52');
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('class', 'device-name');
      label.textContent = dev.name;

      const sub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      sub.setAttribute('x', '40');
      sub.setAttribute('y', '66');
      sub.setAttribute('text-anchor', 'middle');
      sub.setAttribute('class', 'device-sub');
      sub.textContent =
        dev.modelLabel ?? (dev.type === 'pc' ? dev.ip ?? '' : dev.type === 'router' ? 'L3' : 'L2');

      g.append(body, icon, label, sub);

      if (this.mode === 'connect') {
        const port = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        port.setAttribute('cx', '40');
        port.setAttribute('cy', '72');
        port.setAttribute('r', '7');
        port.setAttribute('class', 'device-port');
        port.dataset.deviceId = dev.id;
        port.dataset.portId = dev.ports?.[0]?.id ?? `${dev.id}-p0`;
        g.appendChild(port);
      }

      this.layers.devices.appendChild(g);
    }
  }

  /** @param {PointerEvent} e */
  onPointerDown(e) {
    const target = /** @type {SVGElement} */ (e.target);
    const onDevice = target.closest('[data-device-id]');

    if (this.mode === 'connect' && target.classList.contains('device-port')) {
      const devId = target.dataset.deviceId;
      const portId = target.dataset.portId;
      if (!this.connectFrom) {
        this.connectFrom = { devId, portId };
      } else if (this.connectFrom.devId !== devId) {
        this.createLink(this.connectFrom.devId, this.connectFrom.portId, devId, portId);
        this.connectFrom = null;
        this.render();
      }
      e.preventDefault();
      return;
    }

    const startPan =
      this.mode === 'pan' ||
      (this.mode === 'select' && !onDevice && (e.button === 1 || e.altKey || e.buttons === 4));

    if (startPan) {
      this.pan = { sx: e.clientX, sy: e.clientY, ox: this.view.x, oy: this.view.y };
      this.svg.setPointerCapture(e.pointerId);
      e.preventDefault();
      return;
    }

    if (onDevice && this.mode === 'select') {
      const id = onDevice.dataset.deviceId;
      this.select(id);
      const dev = getDevice(this.topo, id);
      if (dev) {
        const pt = this.screenToWorld(e.clientX, e.clientY);
        this.drag = { id, ox: pt.x - dev.x, oy: pt.y - dev.y, pointerId: e.pointerId };
        onDevice.setPointerCapture(e.pointerId);
      }
      e.preventDefault();
      return;
    }

    if (!onDevice && this.mode === 'select') {
      this.select(null);
    }
  }

  /** @param {PointerEvent} e */
  onPointerMove(e) {
    if (this.pan) {
      this.view.x = this.pan.ox + (e.clientX - this.pan.sx);
      this.view.y = this.pan.oy + (e.clientY - this.pan.sy);
      this.applyViewTransform();
      return;
    }
    if (!this.drag) return;
    const dev = getDevice(this.topo, this.drag.id);
    if (!dev) return;
    const pt = this.screenToWorld(e.clientX, e.clientY);
    dev.x = pt.x - this.drag.ox;
    dev.y = pt.y - this.drag.oy;
    this.render();
  }

  /** @param {PointerEvent} e */
  onPointerUp(e) {
    if (this.pan) {
      this.pan = null;
      try {
        this.svg.releasePointerCapture(e.pointerId);
      } catch {
        /* ignore */
      }
    }
    if (this.drag) {
      this.onChange(this.getTopology());
      this.drag = null;
    }
  }

  /** @param {WheelEvent} e */
  onWheel(e) {
    e.preventDefault();
    this.view.scale = clamp(this.view.scale * (e.deltaY < 0 ? 1.08 : 1 / 1.08), 0.35, 2.5);
    this.applyViewTransform();
  }

  screenToWorld(clientX, clientY) {
    const pt = this.svg.createSVGPoint();
    pt.x = clientX;
    pt.y = clientY;
    const ctm = this.viewport.getScreenCTM();
    if (!ctm) return { x: clientX, y: clientY };
    const sp = pt.matrixTransform(ctm.inverse());
    return { x: sp.x, y: sp.y };
  }

  createLink(aDevId, aPortId, bDevId, bPortId) {
    const aDev = getDevice(this.topo, aDevId);
    const bDev = getDevice(this.topo, bDevId);
    const aPort = aDev?.ports?.find((p) => p.id === aPortId);
    const bPort = bDev?.ports?.find((p) => p.id === bPortId);
    if (!aPort || !bPort || aPort.linkId || bPort.linkId) return;

    const id = uid('link');
    aPort.linkId = id;
    bPort.linkId = id;
    this.topo.links.push({ id, aDeviceId: aDevId, aPortId, bDeviceId: bDevId, bPortId });
    this.onChange(this.getTopology());
  }
}

function mkGroup(className) {
  const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  g.setAttribute('class', className);
  return g;
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

/** @param {{ x: number, y: number }[]} points */
function polylineLength(points) {
  let len = 0;
  for (let i = 0; i < points.length - 1; i++) {
    len += Math.hypot(points[i + 1].x - points[i].x, points[i + 1].y - points[i].y);
  }
  return len;
}

/** @typedef {import('./simulator.js').SimStep} SimStep */

export { mkGroup };
