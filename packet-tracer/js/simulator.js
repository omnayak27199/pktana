import {
  connectedDevices,
  findDeviceByIp,
  findDnsServer,
  findGatewayForIp,
  findRouteToNetwork,
  getDevice,
  ipInSubnet,
  networkAddress,
  resolveDns,
} from './models.js';

/**
 * @typedef {Object} SimStep
 * @property {string} layer
 * @property {string} title
 * @property {string} detail
 * @property {string} [fromDeviceId]
 * @property {string} [toDeviceId]
 * @property {string} [atDeviceId]
 * @property {string} [packetLabel]
 */

/**
 * @param {import('./models.js').Topology} topo
 * @param {string} srcPcId
 * @param {string} destInput IP or hostname
 * @returns {{ ok: boolean, steps: SimStep[], error?: string, resolvedIp?: string }}
 */
export function simulatePing(topo, srcPcId, destInput) {
  const src = getDevice(topo, srcPcId);
  if (!src || src.type !== 'pc') {
    return { ok: false, steps: [], error: 'Select a PC as the ping source.' };
  }
  if (!src.ip || !src.mask) {
    return { ok: false, steps: [], error: 'Source PC needs an IP address and subnet mask.' };
  }

  const steps = [];
  let destIp = destInput.trim();

  if (!isIpv4(destIp)) {
    const dnsResult = resolveHostname(topo, src, destIp, steps);
    if (!dnsResult.ok) return { ok: false, steps, error: dnsResult.error };
    destIp = dnsResult.ip;
  }

  if (src.dhcp) {
    steps.push({
      layer: 'L7',
      title: 'DHCP — address already assigned',
      detail: `${src.name} uses DHCP. In this lab it already has ${src.ip} (simulated ACK from the router pool). Real DORA: Discover → Offer → Request → Ack.`,
      fromDeviceId: src.id,
    });
  }

  const destPc = findDeviceByIp(topo, destIp);
  const sameSubnet = destPc
    ? ipInSubnet(destPc.ip, src.ip, src.mask)
    : ipInSubnet(destIp, src.ip, src.mask);

  steps.push({
    layer: 'L7',
    title: 'Application — ping requested',
    detail: `${src.name} (${src.ip}) sends ICMP Echo Request to ${destIp}. Ping uses ICMP at Layer 3; the OS must resolve the destination MAC first.`,
    fromDeviceId: src.id,
    packetLabel: 'ICMP Echo Request',
  });

  if (sameSubnet) {
    steps.push({
      layer: 'L3',
      title: 'Same subnet — direct delivery',
      detail: `Destination ${destIp} is in network ${networkAddress(src.ip, src.mask)}/${maskBits(src.mask)}. ${src.name} will ARP for the destination MAC (no gateway needed).`,
      fromDeviceId: src.id,
    });

    const path = traceL2Path(topo, src.id, destPc?.id ?? null, destIp);
    if (!path.ok) {
      return { ok: false, steps: [...steps, ...path.steps], error: path.error, resolvedIp: destIp };
    }
    steps.push(...path.steps);

    steps.push({
      layer: 'L3',
      title: 'ICMP Echo Reply',
      detail: destPc
        ? `${destPc.name} replies with ICMP Echo Reply back to ${src.ip}.`
        : `Host ${destIp} would reply if it existed on this LAN.`,
      fromDeviceId: destPc?.id,
      toDeviceId: src.id,
      packetLabel: 'ICMP Echo Reply',
    });
  } else {
    if (!src.gateway) {
      return {
        ok: false,
        steps,
        error: 'Destination is on another subnet but no default gateway is configured on the PC.',
        resolvedIp: destIp,
      };
    }

    const gw = findGatewayForIp(topo, src.ip, src.mask);
    if (!gw) {
      return {
        ok: false,
        steps: [
          ...steps,
          {
            layer: 'L3',
            title: 'No gateway on local subnet',
            detail: `No router interface (up/up) in ${src.name}'s subnet. Configure router Gi0/0 with ${src.gateway} and no shutdown.`,
            fromDeviceId: src.id,
          },
        ],
        error: `No router interface matches subnet for gateway ${src.gateway}.`,
        resolvedIp: destIp,
      };
    }

    if (gw.port.shutdown) {
      return {
        ok: false,
        steps,
        error: `Gateway interface ${gw.port.name} is administratively down — use "no shutdown" in CLI.`,
        resolvedIp: destIp,
      };
    }

    steps.push({
      layer: 'L3',
      title: 'Different subnet — via default gateway',
      detail: `${destIp} is not in ${src.name}'s subnet. Traffic goes to default gateway ${src.gateway}, then ${gw.router.name} forwards toward ${destIp}.`,
      fromDeviceId: src.id,
    });

    steps.push({
      layer: 'L2',
      title: 'ARP — resolve gateway MAC',
      detail: `${src.name} broadcasts ARP: "Who has ${src.gateway}? Tell ${src.ip}". ${gw.router.name} responds with its MAC.`,
      fromDeviceId: src.id,
      packetLabel: 'ARP Request',
    });

    const toGw = traceL2Path(topo, src.id, gw.router.id, src.gateway);
    if (!toGw.ok) {
      if (src.gateway !== gw.port.ip) {
        return {
          ok: false,
          steps: [
            ...steps,
            ...toGw.steps,
            {
              layer: 'L3',
              title: 'Wrong default gateway',
              detail: `PC gateway is ${src.gateway} but router interface has ${gw.port.ip}. Fix the PC gateway or router IP.`,
              fromDeviceId: src.id,
            },
          ],
          error: `Wrong gateway ${src.gateway} — router is at ${gw.port.ip}.`,
          resolvedIp: destIp,
        };
      }
      return { ok: false, steps: [...steps, ...toGw.steps], error: toGw.error, resolvedIp: destIp };
    }
    steps.push(...toGw.steps);

    const routeHops = traceRouterPath(topo, gw.router.id, destIp, destPc?.id ?? null);
    steps.push(...routeHops.steps);
    if (!routeHops.ok) {
      return { ok: false, steps, error: routeHops.error, resolvedIp: destIp };
    }

    steps.push({
      layer: 'L7',
      title: 'Ping complete (simulated)',
      detail: destPc
        ? `Echo request reached ${destPc.name}; reply returns along the reverse path.`
        : `No PC with IP ${destIp} in the lab — add one or fix the address.`,
      fromDeviceId: destPc?.id,
      toDeviceId: src.id,
      packetLabel: 'ICMP Echo Reply',
    });
  }

  return { ok: true, steps, resolvedIp: destIp };
}

/**
 * @param {import('./models.js').Topology} topo
 * @param {import('./models.js').Device} src
 * @param {string} hostname
 * @param {SimStep[]} steps
 */
function resolveHostname(topo, src, hostname, steps) {
  const dnsPc = findDnsServer(topo);
  const dnsIp = src.dnsServer ?? dnsPc?.ip ?? '192.168.1.53';

  steps.push({
    layer: 'L7',
    title: 'DNS query',
    detail: `${src.name} sends DNS query for "${hostname}" to DNS server ${dnsIp} (UDP/53).`,
    fromDeviceId: src.id,
    toDeviceId: dnsPc?.id,
    packetLabel: 'DNS Query',
  });

  if (!dnsPc) {
    return { ok: false, error: `No DNS server in topology. Add DNS-Server PC or use an IP address.` };
  }

  const ip = resolveDns(dnsPc, hostname);
  if (!ip) {
    steps.push({
      layer: 'L7',
      title: 'DNS NXDOMAIN',
      detail: `DNS-Server has no A record for "${hostname}". Add it in lab config or use the IP directly.`,
      fromDeviceId: dnsPc.id,
    });
    return { ok: false, error: `Unknown host: ${hostname}` };
  }

  steps.push({
    layer: 'L7',
    title: 'DNS response',
    detail: `DNS-Server replies: ${hostname} → ${ip}. ${src.name} caches the answer and starts ICMP.`,
    fromDeviceId: dnsPc.id,
    toDeviceId: src.id,
    packetLabel: 'DNS Reply',
  });

  return { ok: true, ip };
}

/**
 * @param {import('./models.js').Topology} topo
 * @param {string} startRouterId
 * @param {string} destIp
 * @param {string | null} destPcId
 */
function traceRouterPath(topo, startRouterId, destIp, destPcId) {
  const steps = [];
  let currentRouterId = startRouterId;
  const visited = new Set();
  let hops = 0;

  while (hops < 8) {
    hops += 1;
    if (visited.has(currentRouterId)) {
      return { ok: false, steps, error: 'Routing loop detected.' };
    }
    visited.add(currentRouterId);

    const router = getDevice(topo, currentRouterId);
    if (!router || router.type !== 'router') break;

    const route = findRouteToNetwork(topo, destIp);
    const localRoute = router.ports?.find(
      (p) => !p.shutdown && p.ip && p.mask && ipInSubnet(destIp, p.ip, p.mask),
    );

    if (localRoute && destPcId) {
      steps.push({
        layer: 'L3',
        title: `${router.name} — directly connected`,
        detail: `Destination ${destIp} is on ${localRoute.name}. Router forwards out the LAN interface.`,
        fromDeviceId: router.id,
        packetLabel: 'IPv4 forward',
      });
      const toDest = traceL2Path(topo, router.id, destPcId, destIp);
      if (!toDest.ok) return { ok: false, steps: [...steps, ...toDest.steps], error: toDest.error };
      steps.push(...toDest.steps);
      return { ok: true, steps };
    }

    const staticRoute = (router.staticRoutes ?? []).find((r) => ipInSubnet(destIp, r.network, r.mask));
    if (staticRoute) {
      steps.push({
        layer: 'L3',
        title: `${router.name} — static route`,
        detail: `Longest match: ${staticRoute.network}/${maskBits(staticRoute.mask)} via ${staticRoute.nextHop}. Packet forwarded to next router.`,
        fromDeviceId: router.id,
        packetLabel: 'IPv4 forward',
      });

      const nextRouter = findRouterByInterfaceIp(topo, staticRoute.nextHop);
      if (nextRouter) {
        const l2 = traceL2Path(topo, router.id, nextRouter.id, staticRoute.nextHop);
        if (l2.ok) steps.push(...l2.steps);
        currentRouterId = nextRouter.id;
        continue;
      }
    }

    if (route && route.router.id === router.id && route.via === 'connected' && destPcId) {
      const toDest = traceL2Path(topo, router.id, destPcId, destIp);
      if (toDest.ok) {
        steps.push({
          layer: 'L3',
          title: `${router.name} forwarding decision`,
          detail: `${router.name} receives the frame, decapsulates IP, and forwards toward ${destIp}.`,
          fromDeviceId: router.id,
          packetLabel: 'IPv4 forward',
        });
        steps.push(...toDest.steps);
        return { ok: true, steps };
      }
    }

    steps.push({
      layer: 'L3',
      title: `${router.name} forwarding decision`,
      detail: `${router.name} receives the frame on an incoming interface, decapsulates IP, looks up route to ${destIp}, and forwards.`,
      fromDeviceId: router.id,
      packetLabel: 'IPv4 forward',
    });

    if (destPcId) {
      const toDest = traceL2Path(topo, router.id, destPcId, destIp);
      if (toDest.ok) {
        steps.push(...toDest.steps);
        return { ok: true, steps };
      }
    }
    break;
  }

  return { ok: true, steps };
}

/** @param {import('./models.js').Topology} topo @param {string} ip */
function findRouterByInterfaceIp(topo, ip) {
  for (const d of topo.devices) {
    if (d.type !== 'router' || !d.ports) continue;
    for (const p of d.ports) {
      if (p.ip === ip) return d;
    }
  }
  return null;
}

function traceL2Path(topo, startId, endId, destLabel) {
  const steps = [];
  const visited = new Set([startId]);
  let currentId = startId;
  let hops = 0;

  while (endId && currentId !== endId && hops < 12) {
    hops += 1;
    const current = getDevice(topo, currentId);
    if (!current) break;

    const next = bfsNextHop(topo, currentId, endId, visited);
    if (!next) {
      return {
        ok: false,
        steps: [
          ...steps,
          {
            layer: 'L2',
            title: 'Path blocked',
            detail: `No Layer-2 path from ${current.name} toward ${destLabel}. Check cables and that interfaces are up.`,
            fromDeviceId: currentId,
          },
        ],
        error: `No path to reach ${destLabel}.`,
      };
    }

    visited.add(next.device.id);

    if (current.type === 'switch') {
      steps.push({
        layer: 'L2',
        title: 'Switch forwards frame',
        detail: `${current.name} receives the frame on ${next.viaLocalPort?.name ?? 'a port'}. It floods or forwards based on MAC learning toward ${next.device.name}.`,
        fromDeviceId: current.id,
        toDeviceId: next.device.id,
        packetLabel: 'Ethernet frame',
      });
    } else if (current.type === 'pc') {
      steps.push({
        layer: 'L2',
        title: 'Frame sent on wire',
        detail: `${current.name} encapsulates the packet in an Ethernet frame and sends it out FastEthernet0.`,
        fromDeviceId: current.id,
        toDeviceId: next.device.id,
        packetLabel: 'Ethernet frame',
      });
    } else if (current.type === 'router') {
      steps.push({
        layer: 'L2',
        title: 'Router interface transmit',
        detail: `${current.name} sends the frame out ${next.viaLocalPort?.name ?? 'interface'} toward ${next.device.name}.`,
        fromDeviceId: current.id,
        toDeviceId: next.device.id,
        packetLabel: 'Ethernet frame',
      });
    }

    currentId = next.device.id;
  }

  if (endId && currentId !== endId) {
    return {
      ok: false,
      steps,
      error: `Could not reach ${destLabel} — check topology wiring.`,
    };
  }

  return { ok: true, steps };
}

function bfsNextHop(topo, from, to, visited) {
  const queue = [{ id: from, path: [] }];
  const seen = new Set([from]);

  while (queue.length) {
    const { id, path } = queue.shift();
    if (id === to && path.length) return path[0];

    for (const conn of connectedDevices(topo, id)) {
      if (seen.has(conn.device.id)) continue;
      seen.add(conn.device.id);
      const hop = {
        device: conn.device,
        viaLocalPort: conn.localPort,
        viaRemotePort: conn.remotePort,
      };
      if (conn.device.id === to) return hop;
      if (!visited.has(conn.device.id)) {
        queue.push({ id: conn.device.id, path: [...path, hop] });
      }
    }
  }

  for (const conn of connectedDevices(topo, from)) {
    if (!visited.has(conn.device.id)) {
      return {
        device: conn.device,
        viaLocalPort: conn.localPort,
        viaRemotePort: conn.remotePort,
      };
    }
  }
  return null;
}

function maskBits(mask) {
  return mask.split('.').reduce((acc, oct) => acc + Number(oct).toString(2).replace(/0/g, '').length, 0);
}

function isIpv4(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}
