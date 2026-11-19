/** Layer colors for packet flow visualization */
export const LAYER_COLORS = {
  L7: { fill: '#a78bfa', stroke: '#7c3aed', glow: 'rgba(167,139,250,0.55)' },
  L3: { fill: '#38bdf8', stroke: '#0284c7', glow: 'rgba(56,189,248,0.55)' },
  L2: { fill: '#4ade80', stroke: '#16a34a', glow: 'rgba(74,222,128,0.55)' },
  default: { fill: '#fb923c', stroke: '#ea580c', glow: 'rgba(251,146,60,0.55)' },
};

export function layerColor(layer) {
  return LAYER_COLORS[layer] ?? LAYER_COLORS.default;
}

export function deviceCenter(dev) {
  return { x: dev.x + 40, y: dev.y + 36 };
}

export function easeInOut(t) {
  return t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Short action verb for hop callout */
export function hopActionLabel(step) {
  if (step.toDeviceId && step.fromDeviceId) return 'Packet traveling →';
  if (step.layer === 'L2' && step.title.toLowerCase().includes('arp')) return 'Broadcasting ARP →';
  if (step.layer === 'L3') return 'Routing decision ↻';
  if (step.layer === 'L7') return 'Application layer ✦';
  return 'Processing…';
}

export function arriveLabel(step, toDev) {
  if (!toDev) return 'Done';
  const name = toDev.name;
  if (toDev.type === 'switch') {
    return `At ${name} — learns MAC, checks table, forwards`;
  }
  if (toDev.type === 'router') {
    return `At ${name} — receives frame, routes IP packet`;
  }
  if (toDev.type === 'pc') {
    return `At ${name} — NIC delivers to network stack`;
  }
  return `At ${name}`;
}
