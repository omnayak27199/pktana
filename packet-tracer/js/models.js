/** @typedef {'pc' | 'switch' | 'router'} DeviceType */

import { DEVICE_MODELS } from './device-catalog.js';

/**
 * @typedef {Object} Device
 * @property {string} id
 * @property {DeviceType} type
 * @property {string} name
 * @property {number} x
 * @property {number} y
 * @property {string} [ip]
 * @property {string} [mask]
 * @property {string} [gateway]
 * @property {string} mac
 * @property {{ id: string, name: string, linkId: string | null }[]} [ports]
 */

/**
 * @typedef {Object} Link
 * @property {string} id
 * @property {string} aDeviceId
 * @property {string} aPortId
 * @property {string} bDeviceId
 * @property {string} bPortId
 */

/**
 * @typedef {Object} Topology
 * @property {Device[]} devices
 * @property {Link[]} links
 */

let _id = 0;
export function uid(prefix = 'id') {
  _id += 1;
  return `${prefix}${_id}`;
}

export function defaultMac(seed) {
  const n = (seed * 17 + 11) % 256;
  return `00:1A:2B:${pad(n)}:${pad((n + 7) % 256)}:${pad((n + 13) % 256)}`;
}

function pad(n) {
  return n.toString(16).padStart(2, '0').toUpperCase();
}

/** @param {string} modelKey @param {number} x @param {number} y */
export function createDevice(modelKey, x, y) {
  const spec = DEVICE_MODELS[modelKey] ?? DEVICE_MODELS.pc;
  const type = /** @type {DeviceType} */ (spec.type);
  const id = uid(type);
  const base = {
    id,
    type,
    modelKey,
    modelLabel: spec.label,
    name: defaultName(type, spec),
    x,
    y,
    mac: defaultMac(_id),
  };

  if (type === 'pc') {
    const dev = {
      ...base,
      ip: '192.168.1.10',
      mask: '255.255.255.0',
      gateway: '192.168.1.1',
      arpCache: {},
      ports: [{ id: `${id}-fe0`, name: 'FastEthernet0', linkId: null }],
    };
    if (spec.role) dev.role = spec.role;
    if (spec.role === 'dns') {
      dev.ip = '192.168.1.53';
      dev.dnsRecords = { 'web.server': '192.168.1.100', 'mail.local': '192.168.1.101' };
    }
    if (spec.role === 'server') dev.ip = '192.168.1.100';
    if (spec.role === 'dns') dev.name = `DNS${_id}`;
    if (spec.role === 'server') dev.name = `Server${_id}`;
    return dev;
  }

  if (type === 'switch') {
    const n = spec.portCount ?? 8;
    return {
      ...base,
      switchModel: spec.switchModel ?? 'managed',
      macTable: {},
      ports: Array.from({ length: n }, (_, i) => ({
        id: `${id}-p${i}`,
        name: `Fa0/${i + 1}`,
        linkId: null,
      })),
    };
  }

  const nPorts = spec.portCount ?? 2;
  const ports = Array.from({ length: nPorts }, (_, i) => ({
    id: `${id}-g${i}`,
    name: `Gigabit0/${i}`,
    linkId: null,
    ip: i === 0 ? '192.168.1.1' : i === 1 ? '192.168.2.1' : undefined,
    mask: i <= 1 ? '255.255.255.0' : undefined,
    shutdown: false,
  }));

  return {
    ...base,
    name: spec.label.split(' ')[0] + _id,
    hostname: spec.label.split(' ')[0] + _id,
    routerModel: spec.routerModel ?? 'isr',
    routingProtocol: 'static',
    staticRoutes: [],
    ports,
  };
}

/** @param {DeviceType} type @param {{ label?: string }} spec */
function defaultName(type, spec) {
  if (type === 'pc') return spec.label?.includes('DNS') ? `DNS${_id}` : spec.label?.includes('Server') ? `Server${_id}` : `PC${_id}`;
  if (type === 'switch') return `Switch${_id}`;
  return `Router${_id}`;
}

/** @returns {Topology} */
export function emptyTopology() {
  return { devices: [], links: [] };
}

/** @param {string} ip @param {string} mask */
export function ipInSubnet(ip, networkIp, mask) {
  const a = ipv4ToInt(ip);
  const n = ipv4ToInt(networkIp);
  const m = ipv4ToInt(mask);
  return (a & m) === (n & m);
}

/** @param {string} ip @param {string} mask */
export function networkAddress(ip, mask) {
  const a = ipv4ToInt(ip);
  const m = ipv4ToInt(mask);
  return intToIpv4(a & m);
}

/** @param {string} ip */
export function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

/** @param {number} n */
export function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** @param {Topology} topo @param {string} deviceId */
export function getDevice(topo, deviceId) {
  return topo.devices.find((d) => d.id === deviceId) ?? null;
}

/** @param {Topology} topo @param {string} linkId */
export function getLink(topo, linkId) {
  return topo.links.find((l) => l.id === linkId) ?? null;
}

/** @param {Topology} topo @param {string} deviceId @param {string} portId */
export function getPort(topo, deviceId, portId) {
  const dev = getDevice(topo, deviceId);
  if (!dev?.ports) return null;
  return dev.ports.find((p) => p.id === portId) ?? null;
}

/** @param {Topology} topo @param {string} deviceId @param {string} portId */
export function neighborOnPort(topo, deviceId, portId) {
  const port = getPort(topo, deviceId, portId);
  if (!port?.linkId) return null;
  const link = getLink(topo, port.linkId);
  if (!link) return null;
  if (link.aDeviceId === deviceId && link.aPortId === portId) {
    return { deviceId: link.bDeviceId, portId: link.bPortId };
  }
  return { deviceId: link.aDeviceId, portId: link.aPortId };
}

/** @param {Topology} topo @param {string} fromDeviceId */
export function connectedDevices(topo, fromDeviceId) {
  const dev = getDevice(topo, fromDeviceId);
  if (!dev?.ports) return [];
  const out = [];
  for (const port of dev.ports) {
    const nb = neighborOnPort(topo, fromDeviceId, port.id);
    if (nb) {
      const other = getDevice(topo, nb.deviceId);
      if (other) out.push({ device: other, localPort: port, remotePort: getPort(topo, nb.deviceId, nb.portId) });
    }
  }
  return out;
}

/** @param {Topology} topo @param {string} ip */
export function findDeviceByIp(topo, ip) {
  for (const d of topo.devices) {
    if (d.type === 'pc' && d.ip === ip) return d;
    if (d.type === 'router' && d.ports) {
      for (const p of d.ports) {
        if (p.ip === ip) return d;
      }
    }
  }
  return null;
}

/** @param {Topology} topo @param {string} ip @param {string} mask */
export function findGatewayForIp(topo, ip, mask) {
  for (const d of topo.devices) {
    if (d.type !== 'router' || !d.ports) continue;
    for (const p of d.ports) {
      if (p.shutdown) continue;
      if (p.ip && p.mask && ipInSubnet(ip, p.ip, p.mask)) {
        return { router: d, port: p };
      }
    }
  }
  return null;
}

/** @param {Topology} topo @param {string} destIp */
export function findRouteToNetwork(topo, destIp) {
  for (const d of topo.devices) {
    if (d.type !== 'router' || !d.ports) continue;
    for (const p of d.ports) {
      if (p.shutdown || !p.ip || !p.mask) continue;
      if (ipInSubnet(destIp, p.ip, p.mask)) {
        return { router: d, port: p, via: 'connected' };
      }
    }
    for (const r of d.staticRoutes ?? []) {
      if (ipInSubnet(destIp, r.network, r.mask)) {
        return { router: d, nextHop: r.nextHop, via: 'static' };
      }
    }
  }
  return null;
}

/** @param {Topology} topo */
export function findDnsServer(topo) {
  return topo.devices.find((d) => d.type === 'pc' && d.role === 'dns') ?? null;
}

/** @param {import('./models.js').Device} dnsPc @param {string} hostname */
export function resolveDns(dnsPc, hostname) {
  const host = hostname.toLowerCase();
  const records = dnsPc.dnsRecords ?? {};
  for (const [name, ip] of Object.entries(records)) {
    if (name.toLowerCase() === host) return ip;
  }
  return null;
}
