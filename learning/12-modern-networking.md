# Modern Networking

Classical networking — switches, routers, VLANs, and static configs — still underpins everything. But the last decade has transformed how networks are built and operated. Software-Defined Networking, cloud computing, containers, and programmable data planes have fundamentally changed the landscape.

---

## Software-Defined Networking (SDN)

Traditional networks tightly couple the **control plane** (decisions: where should this packet go?) with the **data plane** (execution: actually forwarding packets). Every switch and router is configured individually.

**SDN separates these planes:**

```
┌──────────────────────────────────┐
│     SDN Controller (software)    │  ← Control plane: ONE centralized brain
│   OpenDaylight / ONOS / Ryu      │
└────────────┬─────────────────────┘
             │ OpenFlow / NETCONF / gRPC
    ┌────────┴────────┐
 [Switch1]         [Switch2]        ← Data plane: dumb fast-forward only
```

**Benefits:**
- Centralized visibility — the controller knows the full network topology
- Programmatic control — APIs to add/modify/delete flow rules
- Rapid policy changes — push new rules to all switches simultaneously
- Traffic engineering — route flows for optimal utilization, not just shortest path

**OpenFlow** is the original SDN protocol (southbound API between controller and switches). More modern approaches use **gRPC + P4** (programmable switches) or **NETCONF/YANG**.

---

## Network Function Virtualization (NFV)

Traditionally, network functions — firewall, load balancer, IDS, NAT, VPN gateway — run on specialized physical hardware (**middleboxes**). NFV replaces these with **software running on commodity servers**.

```
Physical world:          Virtual world:
[Firewall appliance]  →  [vFirewall on x86 VM]
[Load balancer]       →  [HAProxy / Nginx container]
[IDS sensor]          →  [Suricata in a pod]
[WAN optimizer]       →  [SD-WAN software]
```

**Benefits:**
- Spin up/down network functions in seconds
- Scale horizontally — add instances under load
- Multi-tenant — separate function instances per customer
- Commodity hardware — no vendor lock-in

**VNF (Virtual Network Function):** a software implementation of a network function.
**SFC (Service Function Chaining):** define an ordered list of VNFs that traffic must traverse.

---

## Cloud Networking

Cloud providers (AWS, Azure, GCP) have built massive virtual networks. Understanding their abstraction is increasingly essential for network engineers.

### VPC (Virtual Private Cloud)

A **VPC** is a logically isolated network within the cloud. You define:
- **CIDR range** for the VPC (e.g. `10.0.0.0/16`)
- **Subnets** within the VPC (public subnets with internet access, private subnets without)
- **Route tables** — which subnet routes traffic where
- **Security groups** — stateful firewall rules per instance
- **Network ACLs** — stateless firewall rules per subnet

### Cloud Load Balancers

- **Layer 4 (NLB/TCP):** ultra-low latency, preserves client IP, handles any TCP/UDP protocol
- **Layer 7 (ALB/HTTP):** understands HTTP, routes by path/host, terminates TLS, sticky sessions, WAF integration

### Direct Connect / ExpressRoute

Dedicated private fiber from your data center to the cloud provider's PoP. Bypasses the public internet for lower latency and more consistent throughput.

### Transit Gateway / Hub VPC

When you have many VPCs (dev, prod, shared services, per-region), a **Transit Gateway** acts as a hub: all VPCs connect to it, and it routes between them. Avoids the N×(N-1)/2 VPC peering explosion.

---

## Container Networking

Containers (Docker, Kubernetes) brought a new networking model. Each container needs network connectivity, isolation, and service discovery.

### Docker Networking

**Bridge mode:** containers on the same host connect via a software bridge (`docker0`). NAT provides internet access. Default for standalone Docker.

**Host mode:** container shares the host's network namespace. No isolation, maximum performance.

**Overlay networks:** spans multiple hosts. Docker Swarm uses VXLAN tunnels to create a virtual Layer 2 network across hosts.

### Kubernetes Networking

K8s has its own networking model with strict rules:
- Every **Pod** gets its own IP address
- Pods can communicate directly (no NAT) across nodes
- **Services** provide a stable virtual IP (ClusterIP) that load-balances to Pods

**CNI (Container Network Interface):** the plugin API for Kubernetes networking. Popular CNI plugins:

| Plugin | Approach | Notable Feature |
|--------|---------|----------------|
| Calico | BGP-based routing | Network policy enforcement |
| Flannel | VXLAN overlay | Simple, widely used |
| Cilium | eBPF-based | Deep observability, L7 network policy |
| WeaveNet | Mesh overlay | Simple setup |

### VXLAN

**VXLAN (Virtual Extensible LAN)** encapsulates Ethernet frames in UDP packets, creating a Layer 2 overlay across a Layer 3 network. A 24-bit VXLAN Network Identifier (VNI) provides 16 million+ tenant segments (vs. VLANs' 4094).

Used extensively in cloud data centers, Kubernetes, and NFV.

---

## eBPF — Programmable Kernel Networking

**eBPF (extended Berkeley Packet Filter)** is arguably the most transformative technology in modern Linux networking. It lets you run verified sandboxed programs **inside the Linux kernel** — attaching to network events, system calls, and hardware offload points — without modifying kernel code.

### What eBPF enables

**XDP (eXpress Data Path):** process packets at the **NIC driver level** before the kernel's network stack. Possible actions:
- `XDP_PASS` — normal processing
- `XDP_DROP` — drop (no kernel stack overhead — world's fastest firewall/DDoS mitigation)
- `XDP_TX` — retransmit (hardware load balancing)
- `XDP_REDIRECT` — redirect to another interface or CPU queue

**tc (Traffic Control) eBPF:** attach at the kernel's traffic control layer. Full socket access, nat, connection tracking.

**Socket filters:** BPF has filtered packet captures since the 1990s. Modern socket filters are eBPF programs.

### eBPF in practice

- **Cilium** (Kubernetes CNI) replaces iptables/kube-proxy entirely with eBPF programs
- **Cloudflare** uses XDP to drop DDoS packets at line rate (hundreds of Gbps) before the kernel sees them
- **Facebook's Katran** is an XDP-based L4 load balancer
- **pktana** uses XDP for packet capture and dataplane analysis at the network interface level

```bash
# Check XDP program attached to an interface
pktana dp m1

# pktana attaches XDP programs for capture and analysis
pktana capture --interface eth0 --count 100
```

---

## SD-WAN

**Software-Defined WAN** applies SDN principles to WAN connectivity. A central orchestrator manages routing policies across multiple underlay transports:

```
Branch Office
├── MPLS link        ┐
├── Internet link    ├── SD-WAN CPE → Policy Engine → Cloud/HQ
└── LTE backup link  ┘
```

SD-WAN dynamically routes traffic based on:
- Application type (voice gets low-latency path, backup over cheap internet)
- Real-time path quality (detect brownout, failover automatically)
- Business policy (SaaS traffic goes direct to internet, not backhaul)

---

## Observability: eBPF + OpenTelemetry

Modern networks are too complex to debug with traditional tools. The new standard:

**OpenTelemetry:** vendor-neutral framework for traces, metrics, and logs. Instruments applications to emit telemetry automatically.

**eBPF observability (Pixie, Hubble, Pyroscope):** attach eBPF probes at the kernel level to capture network flows, HTTP requests, database queries — with zero application code changes.

**Service mesh (Istio, Linkerd):** sidecar proxies inject into each Pod, capturing all network calls. Provides automatic mTLS, traffic shaping, circuit breaking, and deep telemetry.

---

## QUIC and HTTP/3

The web is moving from TCP+TLS to **QUIC** (see [Transport Layer](06-transport-layer.md)):
- HTTP/3 is now the default for Cloudflare, Google, Meta
- QUIC is estimated to carry ~25–30% of all internet traffic
- Future: media (WHIP/WHEP), tunneling, WebTransport

---

## IPv6 Transition

IPv4 addresses ran out (IANA pool exhausted 2011, regional registries 2015–2019). IPv6 deployment:
- ~45% of Google users connect over IPv6 (2024)
- US: ~55%, India: ~75%, Germany: ~70%
- Most ISPs, mobile carriers, and cloud providers support IPv6

Transition mechanisms:
- **Dual-stack:** run IPv4 and IPv6 simultaneously
- **NAT64:** translate IPv6-only clients to IPv4 destinations
- **464XLAT:** combination used by mobile carriers

---

## Network Automation

Modern networks are managed as code:

**Ansible / Nornir:** push configs to network devices via SSH/NETCONF. Declarative: define the desired state, let the tool make it so.

**Terraform:** provision cloud network resources (VPCs, subnets, security groups) from code. Version-controlled, repeatable.

**GitOps:** network config lives in Git. Changes are reviewed via PRs, tested in CI, and deployed automatically.

---

## Try It With pktana

pktana is built on modern networking primitives:

```bash
# XDP dataplane status (eBPF integration)
pktana dp m1

# Full packet analysis with deep inspection
pktana capture --interface eth0 --count 100

# AI-powered analysis via MCP server
pktana mcp --port 3456
# Then ask Claude: "What protocols are most active on eth0?"
```

---

## What's Next

The networking field continues to evolve:

- **In-network computing:** programmable ASICs (P4) doing ML inference, encryption, telemetry at line rate
- **Quantum networking:** quantum key distribution for information-theoretically secure communication
- **Deterministic networking (DetNet):** IEEE 802.1 Time-Sensitive Networking for industrial/real-time flows
- **AI-driven networks:** self-healing, self-optimizing networks that respond to conditions without human intervention
- **6G:** expected 2030, sub-ms latency, terahertz bands, integrated sensing and communication

---

## Summary

- **SDN** separates control and data planes; enables centralized, programmable network management
- **NFV** replaces hardware appliances with software; enables elastic scaling
- **Cloud networking** (VPC, security groups, transit gateways) virtualizes the entire network
- **Container networking** (CNI, Kubernetes, VXLAN) connects ephemeral workloads
- **eBPF/XDP** enables in-kernel, line-rate packet processing and observability
- **SD-WAN** brings intelligence and resilience to WAN links
- The future: programmable everything, AI-driven ops, and inevitable IPv6

---

**You've completed the pktana Networking Learning Center.** Use the reference guide, capture live traffic with pktana, and connect to the MCP server to ask questions about what you're seeing.
