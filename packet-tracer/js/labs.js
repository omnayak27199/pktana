/** @typedef {import('./models.js').Topology} Topology */

/** @type {{ id: string, category: string, title: string, description: string, goal: string, pingDest?: string, build: () => Topology }[]} */
export const LABS = [
  {
    id: 'star-lan',
    category: 'Basics',
    title: 'Lab 1 — Star LAN',
    description: 'Three PCs on one switch. Same-subnet ping, ARP, and switch flooding.',
    goal: 'Ping PC1 (192.168.1.10) → PC2 (192.168.1.20). No router needed.',
    pingDest: '192.168.1.20',
    build: () => ({
      devices: [
        pc('pc1', 'PC1', 120, 280, '192.168.1.10', '255.255.255.0', '192.168.1.1', '00:1A:2B:01:01:01'),
        pc('pc2', 'PC2', 520, 120, '192.168.1.20', '255.255.255.0', '192.168.1.1', '00:1A:2B:01:02:02'),
        pc('pc3', 'PC3', 520, 440, '192.168.1.30', '255.255.255.0', '192.168.1.1', '00:1A:2B:01:03:03'),
        switchDev('sw1', 'Switch1', 320, 280),
      ],
      links: [
        link('l1', 'pc1', 'pc1-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'pc2', 'pc2-fe0', 'sw1', 'sw1-p1'),
        link('l3', 'pc3', 'pc3-fe0', 'sw1', 'sw1-p2'),
      ],
    }),
  },
  {
    id: 'two-subnets',
    category: 'Routing',
    title: 'Lab 2 — Router between subnets',
    description: 'Two LANs + router. Default gateway and inter-subnet routing.',
    goal: 'Ping PC-A (192.168.1.10) → PC-B (192.168.2.10). Traffic crosses Router1.',
    pingDest: '192.168.2.10',
    build: () => ({
      devices: [
        pc('pca', 'PC-A', 80, 260, '192.168.1.10', '255.255.255.0', '192.168.1.1', '00:1A:2B:02:01:01'),
        pc('pcb', 'PC-B', 640, 260, '192.168.2.10', '255.255.255.0', '192.168.2.1', '00:1A:2B:02:02:02'),
        switchDev('sw1', 'Switch-LAN1', 240, 260),
        switchDev('sw2', 'Switch-LAN2', 480, 260),
        routerDev('r1', 'Router1', 360, 260),
      ],
      links: [
        link('l1', 'pca', 'pca-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'sw1', 'sw1-p1', 'r1', 'r1-g0'),
        link('l3', 'r1', 'r1-g1', 'sw2', 'sw2-p0'),
        link('l4', 'pcb', 'pcb-fe0', 'sw2', 'sw2-p1'),
      ],
    }),
  },
  {
    id: 'router-cli',
    category: 'Router CLI',
    title: 'Lab 3 — Configure the router (CLI)',
    description: 'Router interfaces are shutdown with no IP. Use IOS-style CLI to bring the network up.',
    goal: 'On Router1: enable → conf t → configure Gi0/0 and Gi0/1 → no shutdown. Then ping across subnets.',
    pingDest: '192.168.2.10',
    build: () => ({
      devices: [
        pc('pca', 'PC-A', 80, 260, '192.168.1.10', '255.255.255.0', '192.168.1.1', '00:1A:2B:03:01:01'),
        pc('pcb', 'PC-B', 640, 260, '192.168.2.10', '255.255.255.0', '192.168.2.1', '00:1A:2B:03:02:02'),
        switchDev('sw1', 'Switch-LAN1', 240, 260),
        switchDev('sw2', 'Switch-LAN2', 480, 260),
        routerDev('r1', 'Router1', 360, 260, {
          shutdownAll: true,
          clearIps: true,
        }),
      ],
      links: [
        link('l1', 'pca', 'pca-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'sw1', 'sw1-p1', 'r1', 'r1-g0'),
        link('l3', 'r1', 'r1-g1', 'sw2', 'sw2-p0'),
        link('l4', 'pcb', 'pcb-fe0', 'sw2', 'sw2-p1'),
      ],
    }),
  },
  {
    id: 'wrong-gateway',
    category: 'Troubleshooting',
    title: 'Lab 4 — Wrong default gateway',
    description: 'PC-A has an incorrect gateway. Ping fails until you fix the PC or router config.',
    goal: 'Fix PC-A gateway (should be 192.168.1.1) or configure Router1 Gi0/0, then ping PC-B.',
    pingDest: '192.168.2.10',
    build: () => ({
      devices: [
        pc('pca', 'PC-A', 80, 260, '192.168.1.10', '255.255.255.0', '192.168.1.99', '00:1A:2B:04:01:01'),
        pc('pcb', 'PC-B', 640, 260, '192.168.2.10', '255.255.255.0', '192.168.2.1', '00:1A:2B:04:02:02'),
        switchDev('sw1', 'Switch-LAN1', 240, 260),
        switchDev('sw2', 'Switch-LAN2', 480, 260),
        routerDev('r1', 'Router1', 360, 260),
      ],
      links: [
        link('l1', 'pca', 'pca-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'sw1', 'sw1-p1', 'r1', 'r1-g0'),
        link('l3', 'r1', 'r1-g1', 'sw2', 'sw2-p0'),
        link('l4', 'pcb', 'pcb-fe0', 'sw2', 'sw2-p1'),
      ],
    }),
  },
  {
    id: 'three-site-wan',
    category: 'Routing',
    title: 'Lab 5 — Three-site WAN (static routes)',
    description: 'Three routers in a chain. Configure static routes via CLI so Site C is reachable.',
    goal: 'Configure R1/R2 static routes (or use pre-set routes). Ping PC-C (192.168.3.10) from PC-A.',
    pingDest: '192.168.3.10',
    build: () => ({
      devices: [
        pc('pca', 'PC-A', 40, 280, '192.168.1.10', '255.255.255.0', '192.168.1.1', '00:1A:2B:05:01:01'),
        pc('pcc', 'PC-C', 820, 280, '192.168.3.10', '255.255.255.0', '192.168.3.1', '00:1A:2B:05:03:03'),
        switchDev('sw1', 'Switch-A', 160, 280),
        switchDev('sw3', 'Switch-C', 700, 280),
        routerDev('r1', 'R1', 280, 280, {
          interfaces: [
            { id: 'r1-g0', name: 'Gigabit0/0', ip: '192.168.1.1', mask: '255.255.255.0', shutdown: false },
            { id: 'r1-g1', name: 'Gigabit0/1', ip: '10.0.12.1', mask: '255.255.255.252', shutdown: false },
          ],
          staticRoutes: [
            { network: '192.168.3.0', mask: '255.255.255.0', nextHop: '10.0.12.2' },
          ],
        }),
        routerDev('r2', 'R2', 430, 280, {
          interfaces: [
            { id: 'r2-g0', name: 'Gigabit0/0', ip: '10.0.12.2', mask: '255.255.255.252', shutdown: false },
            { id: 'r2-g1', name: 'Gigabit0/1', ip: '10.0.23.1', mask: '255.255.255.252', shutdown: false },
          ],
          staticRoutes: [
            { network: '192.168.1.0', mask: '255.255.255.0', nextHop: '10.0.12.1' },
            { network: '192.168.3.0', mask: '255.255.255.0', nextHop: '10.0.23.2' },
          ],
        }),
        routerDev('r3', 'R3', 580, 280, {
          interfaces: [
            { id: 'r3-g0', name: 'Gigabit0/0', ip: '10.0.23.2', mask: '255.255.255.252', shutdown: false },
            { id: 'r3-g1', name: 'Gigabit0/1', ip: '192.168.3.1', mask: '255.255.255.0', shutdown: false },
          ],
          staticRoutes: [
            { network: '192.168.1.0', mask: '255.255.255.0', nextHop: '10.0.23.1' },
          ],
        }),
      ],
      links: [
        link('l1', 'pca', 'pca-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'sw1', 'sw1-p1', 'r1', 'r1-g0'),
        link('l3', 'r1', 'r1-g1', 'r2', 'r2-g0'),
        link('l4', 'r2', 'r2-g1', 'r3', 'r3-g0'),
        link('l5', 'r3', 'r3-g1', 'sw3', 'sw3-p0'),
        link('l6', 'pcc', 'pcc-fe0', 'sw3', 'sw3-p1'),
      ],
    }),
  },
  {
    id: 'dns-lab',
    category: 'Application',
    title: 'Lab 6 — DNS resolution',
    description: 'PC queries DNS-Server before ping. See how names map to IP addresses (Layer 7).',
    goal: 'Ping web.server from PC-User. DNS resolves to 192.168.1.100 (Server-1).',
    pingDest: 'web.server',
    build: () => ({
      devices: [
        pc('pcuser', 'PC-User', 100, 280, '192.168.1.10', '255.255.255.0', '192.168.1.1', '00:1A:2B:06:01:01', {
          dnsServer: '192.168.1.53',
        }),
        pc('pcdns', 'DNS-Server', 320, 120, '192.168.1.53', '255.255.255.0', '192.168.1.1', '00:1A:2B:06:53:53', {
          role: 'dns',
          dnsRecords: { 'web.server': '192.168.1.100' },
        }),
        pc('pcweb', 'Server-1', 520, 280, '192.168.1.100', '255.255.255.0', '192.168.1.1', '00:1A:2B:06:64:64', {
          role: 'server',
        }),
        switchDev('sw1', 'Switch1', 320, 280),
        routerDev('r1', 'Router1', 320, 400, {
          interfaces: [
            { id: 'r1-g0', name: 'Gigabit0/0', ip: '192.168.1.1', mask: '255.255.255.0', shutdown: false },
            { id: 'r1-g1', name: 'Gigabit0/1', shutdown: true },
          ],
        }),
      ],
      links: [
        link('l1', 'pcuser', 'pcuser-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'pcdns', 'pcdns-fe0', 'sw1', 'sw1-p1'),
        link('l3', 'pcweb', 'pcweb-fe0', 'sw1', 'sw1-p2'),
        link('l4', 'sw1', 'sw1-p3', 'r1', 'r1-g0'),
      ],
    }),
  },
  {
    id: 'dhcp-concept',
    category: 'Application',
    title: 'Lab 7 — DHCP concept',
    description: 'Learn DORA: Discover, Offer, Request, Ack. PCs expect addresses from router gateway.',
    goal: 'Read simulation notes when pinging. Optional: set PC IPs to match DHCP pool 192.168.10.x.',
    pingDest: '192.168.10.20',
    build: () => ({
      devices: [
        pc('pc1', 'PC1', 120, 200, '192.168.10.10', '255.255.255.0', '192.168.10.1', '00:1A:2B:07:01:01', {
          dhcp: true,
        }),
        pc('pc2', 'PC2', 520, 200, '192.168.10.20', '255.255.255.0', '192.168.10.1', '00:1A:2B:07:02:02', {
          dhcp: true,
        }),
        switchDev('sw1', 'Switch1', 320, 200),
        routerDev('r1', 'Router1', 320, 360, {
          hostname: 'GW-Router',
          dhcpPool: { network: '192.168.10.0', mask: '255.255.255.0', gateway: '192.168.10.1', range: '192.168.10.10-50' },
          interfaces: [
            { id: 'r1-g0', name: 'Gigabit0/0', ip: '192.168.10.1', mask: '255.255.255.0', shutdown: false },
            { id: 'r1-g1', name: 'Gigabit0/1', shutdown: true },
          ],
        }),
      ],
      links: [
        link('l1', 'pc1', 'pc1-fe0', 'sw1', 'sw1-p0'),
        link('l2', 'pc2', 'pc2-fe0', 'sw1', 'sw1-p1'),
        link('l3', 'sw1', 'sw1-p2', 'r1', 'r1-g0'),
      ],
    }),
  },
  {
    id: 'blank',
    category: 'Freeform',
    title: 'Blank canvas',
    description: 'Empty workspace — build any topology and practice CLI on routers.',
    goal: 'Drag devices, cable them, configure routers via CLI, then run ping.',
    build: () => ({ devices: [], links: [] }),
  },
];

function pc(id, name, x, y, ip, mask, gateway, mac, extra = {}) {
  return {
    id,
    type: 'pc',
    name,
    x,
    y,
    ip,
    mask,
    gateway,
    mac,
    ports: [{ id: `${id}-fe0`, name: 'FastEthernet0', linkId: null }],
    ...extra,
  };
}

function switchDev(id, name, x, y) {
  return {
    id,
    type: 'switch',
    name,
    x,
    y,
    mac: '00:1A:2B:FF:FF:01',
    macTable: {},
    ports: Array.from({ length: 8 }, (_, i) => ({
      id: `${id}-p${i}`,
      name: `Fa0/${i + 1}`,
      linkId: null,
    })),
  };
}

function routerDev(id, name, x, y, opts = {}) {
  const defaultIfaces = [
    { id: `${id}-g0`, name: 'Gigabit0/0', linkId: null, ip: '192.168.1.1', mask: '255.255.255.0', shutdown: false },
    { id: `${id}-g1`, name: 'Gigabit0/1', linkId: null, ip: '192.168.2.1', mask: '255.255.255.0', shutdown: false },
  ];
  let ports = opts.interfaces ?? defaultIfaces.map((p) => ({ ...p, linkId: null }));

  if (opts.shutdownAll) {
    ports = ports.map((p) => ({ ...p, shutdown: true }));
  }
  if (opts.clearIps) {
    ports = ports.map((p) => ({ ...p, ip: undefined, mask: undefined }));
  }

  return {
    id,
    type: 'router',
    name,
    hostname: opts.hostname ?? name,
    x,
    y,
    mac: '00:1A:2B:AA:BB:01',
    staticRoutes: opts.staticRoutes ?? [],
    dhcpPool: opts.dhcpPool,
    ports,
  };
}

function link(id, aDev, aPort, bDev, bPort) {
  return { id, aDeviceId: aDev, aPortId: aPort, bDeviceId: bDev, bPortId: bPort };
}

/** Wire linkIds on ports after lab build */
export function finalizeLab(topology) {
  for (const l of topology.links) {
    setPortLink(topology, l.aDeviceId, l.aPortId, l.id);
    setPortLink(topology, l.bDeviceId, l.bPortId, l.id);
  }
  return topology;
}

function setPortLink(topo, devId, portId, linkId) {
  const dev = topo.devices.find((d) => d.id === devId);
  const port = dev?.ports?.find((p) => p.id === portId);
  if (port) port.linkId = linkId;
}

/** @param {string} labId */
export function getLabDefaults(labId) {
  const lab = LABS.find((l) => l.id === labId);
  return { pingDest: lab?.pingDest ?? '192.168.1.20' };
}
