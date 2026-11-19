/** Device model catalog — easy labels for learners */

/** @type {Record<string, { type: string, label: string, icon: string, desc: string, tier?: string }>} */
export const DEVICE_MODELS = {
  pc: {
    type: 'pc',
    label: 'PC / Laptop',
    icon: '🖥️',
    desc: 'End host — IP, gateway, DNS, ARP cache',
  },
  'pc-server': {
    type: 'pc',
    label: 'Server',
    icon: '🗄️',
    desc: 'Web or file server on the LAN',
    role: 'server',
  },
  'pc-dns': {
    type: 'pc',
    label: 'DNS Server',
    icon: '📋',
    desc: 'Resolves hostnames to IP (UDP/53)',
    role: 'dns',
  },
  'switch-unmanaged': {
    type: 'switch',
    label: 'Unmanaged Switch',
    icon: '🔌',
    desc: 'Basic L2 — plug and play, no config',
    switchModel: 'unmanaged',
    portCount: 4,
  },
  'switch-managed': {
    type: 'switch',
    label: 'Managed L2 Switch',
    icon: '🔀',
    desc: 'Learns MAC addresses, forwards frames',
    switchModel: 'managed',
    portCount: 8,
  },
  'switch-l3': {
    type: 'switch',
    label: 'L3 Switch',
    icon: '🧠',
    desc: 'Switch + basic routing between VLANs',
    switchModel: 'l3',
    portCount: 8,
  },
  'router-home': {
    type: 'router',
    label: 'Home Router',
    icon: '🏠',
    desc: 'NAT gateway — 2 LAN/WAN ports',
    routerModel: 'home',
    portCount: 2,
  },
  'router-isr': {
    type: 'router',
    label: 'ISR Router',
    icon: '📡',
    desc: 'Branch office — static & RIP',
    routerModel: 'isr',
    portCount: 3,
  },
  'router-enterprise': {
    type: 'router',
    label: 'Enterprise Router',
    icon: '🏢',
    desc: 'Core router — static, RIP, OSPF',
    routerModel: 'enterprise',
    portCount: 4,
  },
};

export const ROUTING_PROTOCOLS = [
  { id: 'static', label: 'Static', desc: 'Manual ip route entries' },
  { id: 'rip', label: 'RIP', desc: 'Distance-vector — hop count' },
  { id: 'ospf', label: 'OSPF', desc: 'Link-state — shortest path first' },
];

/** @param {string} group */
export function modelsByGroup(group) {
  if (group === 'pc') {
    return Object.entries(DEVICE_MODELS).filter(([, m]) => m.type === 'pc');
  }
  if (group === 'switch') {
    return Object.entries(DEVICE_MODELS).filter(([, m]) => m.type === 'switch');
  }
  return Object.entries(DEVICE_MODELS).filter(([, m]) => m.type === 'router');
}
