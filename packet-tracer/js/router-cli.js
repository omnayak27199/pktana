/**
 * IOS-style router CLI (subset for learning labs).
 * Mutates the router device object in place; caller persists via canvas.load().
 */

/** @typedef {'user' | 'privileged' | 'config' | 'interface'} CliMode */

/**
 * @param {import('./models.js').Device} router
 * @returns {string}
 */
export function routerPrompt(router, mode, ifaceName) {
  const host = router.hostname ?? router.name ?? 'Router';
  if (mode === 'user') return `${host}>`;
  if (mode === 'privileged') return `${host}#`;
  if (mode === 'config') return `${host}(config)#`;
  if (mode === 'interface') return `${host}(config-if)#`;
  return `${host}>`;
}

export class RouterCliSession {
  /** @param {import('./models.js').Device} router @param {() => void} onChange */
  constructor(router, onChange) {
    this.router = router;
    this.onChange = onChange;
    /** @type {CliMode} */
    this.mode = 'user';
    /** @type {number | null} */
    this.ifaceIndex = null;
    this.history = [];
    this.historyPos = -1;
  }

  /** @param {string} line @returns {string[]} */
  exec(line) {
    const trimmed = line.trim();
    if (!trimmed) return [];

    this.history.push(trimmed);
    this.historyPos = this.history.length;

    const parts = trimmed.split(/\s+/);
    const cmd = parts[0].toLowerCase();

    if (cmd === 'enable' || cmd === 'en') return this.doEnable();
    if (cmd === 'disable') return this.doDisable();
    if (cmd === 'exit' || cmd === 'logout') return this.doExit();
    if (cmd === 'end') return this.doEnd();
    if (cmd === 'help' || cmd === '?') return this.doHelp();

    if (this.mode === 'user') {
      return [`% Unknown command or insufficient privileges: ${trimmed}`, 'Type enable to enter privileged EXEC mode.'];
    }

    if (this.mode === 'privileged') {
      if (cmd === 'configure' && parts[1]?.toLowerCase() === 'terminal') return this.doConfTerm();
      if (cmd === 'conf' && parts[1]?.toLowerCase() === 't') return this.doConfTerm();
      if (cmd === 'show') return this.doShow(parts.slice(1));
      if (cmd === 'ping') return this.doPing(parts[1]);
      if (cmd === 'write') return ['Building configuration...', '[OK]'];
      return [`% Unknown command: ${trimmed}`];
    }

    if (this.mode === 'config') {
      if (cmd === 'hostname') return this.doHostname(parts.slice(1).join(' '));
      if (cmd === 'interface' || cmd === 'int') return this.doInterface(parts.slice(1).join(' '));
      if (cmd === 'router') return this.doRouter(parts.slice(1));
      if (cmd === 'ip' && parts[1]?.toLowerCase() === 'route') {
        return this.doStaticRoute(parts.slice(2));
      }
      return [`% Unknown command: ${trimmed}`];
    }

    if (this.mode === 'interface') {
      if (cmd === 'ip' && parts[1]?.toLowerCase() === 'address') {
        return this.doIpAddress(parts[2], parts[3]);
      }
      if (cmd === 'no' && parts[1]?.toLowerCase() === 'shutdown') return this.doNoShutdown();
      if (cmd === 'shutdown') return this.doShutdown();
      if (cmd === 'description') return [`Interface description set.`];
      return [`% Unknown command: ${trimmed}`];
    }

    return [`% Unknown command: ${trimmed}`];
  }

  doEnable() {
    if (this.mode !== 'user') return ['Already in privileged mode.'];
    this.mode = 'privileged';
    return [];
  }

  doDisable() {
    this.mode = 'user';
    this.ifaceIndex = null;
    return [];
  }

  doExit() {
    if (this.mode === 'interface') {
      this.mode = 'config';
      this.ifaceIndex = null;
      return [];
    }
    if (this.mode === 'config') {
      this.mode = 'privileged';
      return [];
    }
    if (this.mode === 'privileged') {
      this.mode = 'user';
      return [];
    }
    return [];
  }

  doEnd() {
    this.mode = 'privileged';
    this.ifaceIndex = null;
    return [];
  }

  doConfTerm() {
    this.mode = 'config';
    this.ifaceIndex = null;
    return ['Enter configuration commands, one per line. End with CNTL/Z or end'];
  }

  /** @param {string} name */
  doHostname(name) {
    if (!name) return ['% Incomplete command.'];
    this.router.hostname = name;
    this.router.name = name;
    this.onChange();
    return [];
  }

  /** @param {string} spec */
  doInterface(spec) {
    const idx = parseInterface(spec);
    if (idx === null || !this.router.ports?.[idx]) {
      return [`% Invalid interface ${spec || ''}`, 'Try: interface gigabitEthernet 0/0'];
    }
    this.mode = 'interface';
    this.ifaceIndex = idx;
    return [];
  }

  /** @param {string} ip @param {string} mask */
  doIpAddress(ip, mask) {
    if (this.ifaceIndex === null) return ['% Not in interface configuration mode'];
    const port = this.router.ports[this.ifaceIndex];
    if (!ip || !mask) return ['% Incomplete command.', 'Usage: ip address 192.168.1.1 255.255.255.0'];
    port.ip = ip;
    port.mask = mask;
    this.onChange();
    return [];
  }

  doNoShutdown() {
    if (this.ifaceIndex === null) return ['% Not in interface configuration mode'];
    this.router.ports[this.ifaceIndex].shutdown = false;
    this.onChange();
    return [`% Interface ${this.router.ports[this.ifaceIndex].name} is up`];
  }

  doShutdown() {
    if (this.ifaceIndex === null) return ['% Not in interface configuration mode'];
    this.router.ports[this.ifaceIndex].shutdown = true;
    this.onChange();
    return [`% Interface ${this.router.ports[this.ifaceIndex].name} is down`];
  }

  /** @param {string[]} args */
  doRouter(args) {
    const sub = (args[0] ?? '').toLowerCase();
    if (sub === 'rip') {
      this.router.routingProtocol = 'rip';
      this.onChange();
      return ['RIP routing enabled (distance-vector, simulated).'];
    }
    if (sub === 'ospf') {
      this.router.routingProtocol = 'ospf';
      this.onChange();
      return [`OSPF routing enabled (process ${args[1] ?? '1'}, simulated).`];
    }
    return ['Usage: router rip | router ospf <process-id>'];
  }

  /** @param {string[]} args */
  doStaticRoute(args) {
    if (args.length < 3) {
      return ['% Incomplete command.', 'Usage: ip route 192.168.2.0 255.255.255.0 10.0.0.2'];
    }
    if (!this.router.staticRoutes) this.router.staticRoutes = [];
    this.router.staticRoutes.push({
      network: args[0],
      mask: args[1],
      nextHop: args[2],
    });
    this.onChange();
    return [`Static route to ${args[0]}/${maskBits(args[1])} via ${args[2]} added.`];
  }

  /** @param {string[]} args */
  doShow(args) {
    const sub = (args[0] ?? '').toLowerCase();
    if (sub === 'running-config' || (sub === 'run' && !args[1])) return this.showRun();
    if (sub === 'ip' && args[1]?.toLowerCase() === 'interface' && args[2]?.toLowerCase()?.startsWith('br')) {
      return this.showIpIntBrief();
    }
    if (sub === 'ip' && args[1]?.toLowerCase() === 'route') return this.showIpRoute();
    if (sub === 'arp') return this.showArp();
    return [`% Unknown show command`, 'Try: show ip interface brief | show running-config | show ip route | show arp'];
  }

  showIpIntBrief() {
    const lines = [
      'Interface              IP-Address      Status    Protocol',
    ];
    for (const p of this.router.ports ?? []) {
      const ip = p.ip ?? 'unassigned';
      const status = p.shutdown ? 'admin down' : p.linkId ? 'up' : 'down';
      const proto = p.shutdown ? 'down' : p.linkId && p.ip ? 'up' : 'down';
      lines.push(
        `${padRight(p.name, 22)} ${padRight(ip, 15)} ${padRight(status, 10)} ${proto}`,
      );
    }
    return lines;
  }

  showIpRoute() {
    const lines = ['Codes: C - connected, S - static, R - RIP, O - OSPF', ''];
    for (const p of this.router.ports ?? []) {
      if (p.ip && p.mask && !p.shutdown) {
        const net = networkAddr(p.ip, p.mask);
        lines.push(`C    ${net}/${maskBits(p.mask)} is directly connected, ${p.name}`);
      }
    }
    for (const r of this.router.staticRoutes ?? []) {
      lines.push(`S    ${r.network}/${maskBits(r.mask)} [1/0] via ${r.nextHop}`);
    }
    if (this.router.routingProtocol === 'rip') lines.push('R    (dynamic routes in Routing tab — simulated RIP)');
    if (this.router.routingProtocol === 'ospf') lines.push('O    (dynamic routes in Routing tab — simulated OSPF)');
    if (lines.length === 2) lines.push('Gateway of last resort is not set');
    return lines;
  }

  showArp() {
    const lines = ['Address', 'Hardware Addr', 'Interface', 'Type'];
    lines.push('— Use the ARP tab in the inspector for the full learner view.');
    for (const p of this.router.ports ?? []) {
      if (p.ip) lines.push(`${p.ip}  ${this.router.mac}  ${p.name}  static (self)`);
    }
    return lines;
  }

  showRun() {
    const host = this.router.hostname ?? this.router.name ?? 'Router';
    const lines = [`hostname ${host}`, '!'];
    for (const p of this.router.ports ?? []) {
      lines.push(`interface ${cliIfaceName(p.name)}`);
      if (p.shutdown) lines.push(' shutdown');
      else lines.push(' no shutdown');
      if (p.ip && p.mask) lines.push(` ip address ${p.ip} ${p.mask}`);
      lines.push('!');
    }
    for (const r of this.router.staticRoutes ?? []) {
      lines.push(`ip route ${r.network} ${r.mask} ${r.nextHop}`);
    }
    return lines;
  }

  /** @param {string | undefined} dest */
  doPing(dest) {
    if (!dest) return ['% Incomplete command.', 'Usage: ping 192.168.1.10'];
    return [
      `Type escape sequence to abort.`,
      `Sending 5, 100-byte ICMP Echos to ${dest}, timeout is 2 seconds:`,
      '.....',
      `Success rate is 100 percent (5/5) — use PC ping simulation for full path trace.`,
    ];
  }

  doHelp() {
    if (this.mode === 'user') {
      return ['enable  — Enter privileged EXEC mode'];
    }
    if (this.mode === 'privileged') {
      return [
        'configure terminal  — Global configuration',
        'show ip interface brief',
        'show running-config',
        'show ip route',
        'ping <ip>',
        'disable / exit',
      ];
    }
    if (this.mode === 'config') {
      return [
        'hostname <name>',
        'interface gigabitEthernet 0/0',
        'router rip | router ospf <id>',
        'ip route <network> <mask> <next-hop>',
        'exit / end',
      ];
    }
    return [
      'ip address <ip> <mask>',
      'no shutdown',
      'shutdown',
      'exit',
    ];
  }

  prevHistory() {
    if (this.history.length === 0) return '';
    this.historyPos = Math.max(0, this.historyPos - 1);
    return this.history[this.historyPos] ?? '';
  }

  nextHistory() {
    if (this.historyPos >= this.history.length - 1) {
      this.historyPos = this.history.length;
      return '';
    }
    this.historyPos += 1;
    return this.history[this.historyPos] ?? '';
  }
}

/** @param {string} spec */
function parseInterface(spec) {
  const s = spec.toLowerCase().replace(/\s+/g, '');
  const m = s.match(/(?:gigabitethernet|gigabit|gi|g)(?:ethernet)?(\d+)\/(\d+)/);
  if (m) return Number(m[2]);
  const short = s.match(/^g(\d+)\/(\d+)$/);
  if (short) return Number(short[2]);
  return null;
}

/** @param {string} portName */
function cliIfaceName(portName) {
  const m = portName.match(/(\d+)\/(\d+)/);
  if (m) return `GigabitEthernet${m[1]}/${m[2]}`;
  return portName;
}

function padRight(s, n) {
  return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
}

function maskBits(mask) {
  return mask.split('.').reduce((acc, oct) => acc + Number(oct).toString(2).replace(/0/g, '').length, 0);
}

function networkAddr(ip, mask) {
  const a = ip.split('.').map(Number);
  const m = mask.split('.').map(Number);
  return a.map((oct, i) => oct & m[i]).join('.');
}

export { parseInterface, cliIfaceName };
