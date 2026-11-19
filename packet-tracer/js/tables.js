import {
  connectedDevices,
  findDeviceByIp,
  getDevice,
  ipInSubnet,
  neighborOnPort,
} from './models.js';

/** Build learner-friendly network tables from current topology */

/** @param {import('./models.js').Topology} topo @param {import('./models.js').Device} dev */
export function buildArpTable(topo, dev) {
  const rows = [];
  if (dev.type === 'pc') {
    if (dev.gateway) {
      rows.push({
        ip: dev.gateway,
        mac: resolveMacForIp(topo, dev, dev.gateway) ?? '(pending — run ping to learn)',
        type: 'dynamic',
        iface: 'FastEthernet0',
      });
    }
    for (const conn of connectedDevices(topo, dev.id)) {
      const n = conn.device;
      if (n.type === 'pc' && n.ip && n.ip !== dev.ip) {
        rows.push({ ip: n.ip, mac: n.mac, type: 'dynamic', iface: 'FastEthernet0' });
      }
    }
  }
  if (dev.type === 'router') {
    for (const p of dev.ports ?? []) {
      if (p.ip) {
        rows.push({ ip: p.ip, mac: dev.mac, type: 'static', iface: p.name, note: 'Own interface' });
      }
    }
    for (const conn of connectedDevices(topo, dev.id)) {
      const n = conn.device;
      if (n.type === 'pc' && n.ip) {
        rows.push({ ip: n.ip, mac: n.mac, type: 'dynamic', iface: conn.localPort?.name ?? '—' });
      }
    }
  }
  return rows;
}

/** @param {import('./models.js').Topology} topo @param {import('./models.js').Device} dev */
export function buildMacTable(topo, dev) {
  if (dev.type !== 'switch' && dev.type !== 'router') return [];
  const rows = [];
  for (const conn of connectedDevices(topo, dev.id)) {
    const n = conn.device;
    const portName = conn.localPort?.name ?? '—';
    rows.push({
      mac: n.mac,
      port: portName,
      type: 'dynamic',
      vendor: deviceLabel(n),
    });
  }
  rows.push({ mac: dev.mac, port: 'CPU', type: 'static', vendor: 'Local' });
  return rows;
}

/** @param {import('./models.js').Topology} topo @param {import('./models.js').Device} dev */
export function buildRoutingTable(topo, dev) {
  if (dev.type !== 'router') return [];
  const rows = [];
  const proto = dev.routingProtocol ?? 'static';

  for (const p of dev.ports ?? []) {
    if (p.shutdown || !p.ip || !p.mask) continue;
    const net = networkOf(p.ip, p.mask);
    rows.push({
      network: `${net}/${maskBits(p.mask)}`,
      nextHop: 'direct',
      iface: p.name,
      protocol: 'C',
      admin: 'connected',
    });
  }

  for (const r of dev.staticRoutes ?? []) {
    rows.push({
      network: `${r.network}/${maskBits(r.mask)}`,
      nextHop: r.nextHop,
      iface: '—',
      protocol: 'S',
      admin: 'static',
    });
  }

  if (proto === 'rip' || proto === 'ospf') {
    for (const other of topo.devices) {
      if (other.type !== 'router' || other.id === dev.id) continue;
      if (!isNeighborRouter(topo, dev.id, other.id)) continue;
      for (const p of other.ports ?? []) {
        if (p.shutdown || !p.ip || !p.mask) continue;
        const net = networkOf(p.ip, p.mask);
        const exists = rows.some((row) => row.network.startsWith(net));
        if (!exists) {
          rows.push({
            network: `${net}/${maskBits(p.mask)}`,
            nextHop: p.ip,
            iface: findFacingIface(topo, dev.id, other.id) ?? '—',
            protocol: proto === 'rip' ? 'R' : 'O',
            admin: proto === 'rip' ? 'RIP (simulated)' : 'OSPF (simulated)',
          });
        }
      }
    }
  }

  return rows;
}

/** @param {import('./models.js').Topology} topo */
export function buildDnsTable(topo) {
  const rows = [];
  for (const d of topo.devices) {
    if (d.role !== 'dns') continue;
    for (const [name, ip] of Object.entries(d.dnsRecords ?? {})) {
      rows.push({ name, ip, type: 'A', server: d.name });
    }
    if (!d.dnsRecords || Object.keys(d.dnsRecords).length === 0) {
      rows.push({ name: '(no records)', ip: '—', type: '—', server: d.name });
    }
  }
  return rows;
}

function resolveMacForIp(topo, fromDev, ip) {
  const target = findDeviceByIp(topo, ip);
  if (target) return target.mac;
  for (const conn of connectedDevices(topo, fromDev.id)) {
    if (conn.device.type === 'router') {
      for (const p of conn.device.ports ?? []) {
        if (p.ip === ip) return conn.device.mac;
      }
    }
  }
  return null;
}

function deviceLabel(d) {
  if (d.modelLabel) return d.modelLabel;
  if (d.role === 'dns') return 'DNS Server';
  if (d.role === 'server') return 'Server';
  if (d.type === 'pc') return 'PC';
  if (d.type === 'switch') return d.switchModel ?? 'Switch';
  return d.routerModel ?? 'Router';
}

function networkOf(ip, mask) {
  const a = ip.split('.').map(Number);
  const m = mask.split('.').map(Number);
  return a.map((o, i) => o & m[i]).join('.');
}

function maskBits(mask) {
  return mask.split('.').reduce((acc, o) => acc + Number(o).toString(2).replace(/0/g, '').length, 0);
}

function isNeighborRouter(topo, aId, bId) {
  const seen = new Set();
  const q = [aId];
  while (q.length) {
    const id = q.shift();
    for (const c of connectedDevices(topo, id)) {
      if (c.device.type === 'router') {
        if (c.device.id === bId) return true;
      } else if (c.device.type === 'switch' && !seen.has(c.device.id)) {
        seen.add(c.device.id);
        q.push(c.device.id);
      }
    }
  }
  return false;
}

function findFacingIface(topo, routerId, otherRouterId) {
  for (const conn of connectedDevices(topo, routerId)) {
    if (conn.device.id === otherRouterId) return conn.localPort?.name;
    if (conn.device.type === 'switch') {
      for (const c2 of connectedDevices(topo, conn.device.id)) {
        if (c2.device.id === otherRouterId) return conn.localPort?.name;
      }
    }
  }
  return null;
}

export { maskBits, networkOf };
