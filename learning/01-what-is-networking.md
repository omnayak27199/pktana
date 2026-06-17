# What Is a Computer Network?

A **computer network** is two or more devices connected so they can share data and resources. Your phone calling a friend, a browser loading a webpage, a factory machine sending telemetry — all of it is networking.

---

## Why Networks Exist

Before networks, every computer worked alone. You moved data by physically carrying a floppy disk from one machine to another (this was sarcastically called "sneakernet"). Networks replaced sneakernet with instant, automatic data movement.

Modern networks let you:
- Share files and printers across an office
- Access the internet from any device
- Stream video, make calls, run cloud apps
- Monitor and control remote systems

---

## Key Building Blocks

### Nodes
Any device on the network is a **node**: laptops, phones, servers, routers, cameras, even smart thermostats.

### Links
The physical or logical connections between nodes. Links can be:
- **Wired** — Ethernet cables (copper or fiber)
- **Wireless** — Wi-Fi, Bluetooth, cellular (4G/5G)

### Protocols
Rules that define how data is formatted, addressed, sent, and received. Without agreed-upon protocols, nodes couldn't understand each other. Key protocols include:
- **IP** — Internet Protocol (addressing and routing)
- **TCP** — Transmission Control Protocol (reliable delivery)
- **HTTP** — HyperText Transfer Protocol (web pages)
- **DNS** — Domain Name System (names to addresses)

---

## Types of Networks by Size

| Name | Abbreviation | Scale | Example |
|------|-------------|-------|---------|
| Personal Area Network | PAN | < 10 m | Bluetooth headphones |
| Local Area Network | LAN | Building | Office floor |
| Metropolitan Area Network | MAN | City | University campus |
| Wide Area Network | WAN | Country / global | The Internet |

---

## How Data Moves: Packets

Networks don't send files whole. They break data into **packets** — small chunks, typically 64–1500 bytes each.

Each packet carries:
1. **Header** — source address, destination address, sequence number, protocol info
2. **Payload** — the actual chunk of data
3. **Trailer** — error-detection bits (on some protocols)

Why packets?
- Many senders can share the same link simultaneously (**multiplexing**)
- If one packet is lost, only that packet is resent — not the entire file
- Packets can take different routes and arrive out of order, then be reassembled

---

## Client and Server

Most network communication follows the **client-server** model:

- **Server** — waits, listens for requests, provides a service (web server, database, DNS server)
- **Client** — initiates a request and consumes the service (browser, phone app)

Example: when you type `google.com` in your browser, your browser (client) sends an HTTP request to Google's server. The server responds with the HTML of the page.

---

## Addressing: How Devices Find Each Other

Every device needs an address so packets reach the right destination.

**MAC Address** — a hardware-level address burned into the network card (e.g. `AA:BB:CC:DD:EE:FF`). Used for local delivery within a LAN.

**IP Address** — a logical address assigned by software (e.g. `192.168.1.10` for IPv4 or `2001:db8::1` for IPv6). Used for routing across networks.

**Port Number** — identifies a specific service on a device (e.g. port `80` = HTTP, port `443` = HTTPS, port `22` = SSH). A single device can run many services simultaneously, each on its own port.

---

## The Internet vs. a Network

A **network** is any group of connected devices. The **Internet** is the world's largest network — millions of smaller networks interconnected using the IP protocol suite (TCP/IP).

The Internet isn't owned by any one company or government. It's a collaborative infrastructure maintained by ISPs, backbone providers, and standards bodies like the IETF.

---

## Try It With pktana

pktana lets you see exactly how these concepts work in real life:

```bash
# See every active network connection on your machine
pktana connections

# List all network interfaces (your physical and virtual links)
pktana nic list

# Capture live packets and watch them flow
pktana capture --interface eth0 --count 20
```

When you run `pktana capture`, you'll see real packets with real source/destination addresses, protocol names, and payloads. Every packet is a live example of the concepts in this guide.

---

## Summary

- A network connects devices so they can exchange data
- Data travels in **packets** — small, addressed chunks
- Every device has a **MAC address** (local) and an **IP address** (global)
- **Protocols** are the shared rules that make communication possible
- The **Internet** is the world's largest collection of interconnected networks

**Next:** [The OSI Model](02-osi-model.md) — the 7-layer framework that organizes all of networking
