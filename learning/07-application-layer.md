# Layer 7 — The Application Layer

The Application Layer is the layer closest to the user. It defines the protocols that applications use to communicate — the specific language and rules for web browsing, email, file transfer, name resolution, and more.

Unlike lower layers, the Application Layer doesn't worry about how data gets there. It assumes the transport works and focuses entirely on **what** to say.

---

## HTTP — HyperText Transfer Protocol

HTTP is the foundation of the web. Every time you load a webpage, your browser sends HTTP requests and receives HTTP responses.

### Request Structure

```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html
Connection: keep-alive
```

- **Method** — what action to perform
- **Path** — which resource to access
- **Headers** — metadata (who's asking, what they accept, auth tokens)
- **Body** — optional data (for POST/PUT requests)

### HTTP Methods

| Method | Purpose |
|--------|---------|
| GET | Retrieve a resource |
| POST | Create / submit data |
| PUT | Replace a resource |
| PATCH | Partially update |
| DELETE | Remove a resource |
| HEAD | Like GET but no body |
| OPTIONS | Ask what methods are allowed |

### Response Structure

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1234
Cache-Control: max-age=3600

<html>...</html>
```

### Status Codes

| Range | Meaning | Examples |
|-------|---------|---------|
| 1xx | Informational | 100 Continue |
| 2xx | Success | 200 OK, 201 Created, 204 No Content |
| 3xx | Redirect | 301 Moved Permanently, 302 Found |
| 4xx | Client Error | 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found |
| 5xx | Server Error | 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable |

### HTTP Versions

| Version | Key Change |
|---------|-----------|
| HTTP/1.0 | One request per connection |
| HTTP/1.1 | Persistent connections, pipelining, Host header (1997) |
| HTTP/2 | Binary, multiplexed streams, header compression, server push (2015) |
| HTTP/3 | Built on QUIC (UDP), 0-RTT, no head-of-line blocking (2022) |

---

## HTTPS and TLS

**HTTPS** = HTTP over **TLS (Transport Layer Security)**. TLS sits between the Application and Transport layers and provides:

1. **Encryption** — data is unreadable to eavesdroppers
2. **Authentication** — you're talking to the real server (via certificates)
3. **Integrity** — data can't be tampered with in transit

### TLS Handshake (TLS 1.3, simplified)

```
Client                        Server
  |─── ClientHello ──────────►|  (supported ciphers, random, key share)
  |◄── ServerHello + Cert ────|  (chosen cipher, cert, key share)
  |─── Finished ─────────────►|  (verify cert, derive keys)
  |◄── Finished ──────────────|  (confirm keys)
  |═══════ Encrypted data ════|
```

TLS 1.3 completes in **1 RTT** (vs. 2 RTT for TLS 1.2). With session resumption: **0 RTT**.

### Certificates

A TLS certificate contains:
- The server's **public key**
- The **domain name** it's valid for
- A **digital signature** from a trusted Certificate Authority (CA)
- **Validity period** (not before / not after)

Your browser has a built-in list of trusted CAs. If a cert is signed by a trusted CA and matches the domain, the green padlock appears.

---

## DNS — Domain Name System

DNS translates human-readable names (`www.google.com`) into IP addresses (`142.250.80.36`). Without DNS, you'd have to memorize IPs for every website.

### DNS Hierarchy

```
.                          ← Root zone (13 root server clusters)
├── com.                   ← Top-Level Domain (TLD)
│   └── google.com.        ← Second-Level Domain (owned by Google)
│       └── www.google.com ← Hostname
```

### Resolution Process

1. Browser checks its own **cache** → found? Done.
2. OS checks **`/etc/hosts`** → found? Done.
3. OS asks the configured **recursive resolver** (usually your router or ISP)
4. Recursive resolver asks the **root nameserver** → get TLD nameserver
5. Ask the **TLD nameserver** (`.com`) → get the authoritative nameserver
6. Ask the **authoritative nameserver** → get the final answer (the A record)
7. Recursive resolver caches and returns the answer

This whole process typically takes 20–100 ms and is invisible to users.

### Record Types

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | `google.com → 142.250.80.36` |
| AAAA | IPv6 address | `google.com → 2607:f8b0:4004::200e` |
| CNAME | Alias (canonical name) | `www → example.com` |
| MX | Mail server | `example.com → mail.example.com` |
| TXT | Arbitrary text (SPF, DKIM, etc.) | |
| NS | Nameserver for zone | |
| PTR | Reverse DNS (IP → name) | |
| SRV | Service location | `_sip._tcp.example.com` |

### DNS over HTTPS (DoH) / DNS over TLS (DoT)

Traditional DNS uses port 53 over **UDP** (or TCP for large responses) in **plaintext** — anyone on the network can see what domains you're resolving. DoH (port 443) and DoT (port 853) encrypt DNS queries.

---

## SMTP, IMAP, POP3 — Email Protocols

| Protocol | Port | Role |
|---------|------|------|
| SMTP | 25, 587, 465 | Send mail (client→server, server→server) |
| IMAP | 143, 993 | Access mail on server (leave on server) |
| POP3 | 110, 995 | Download mail to client (remove from server) |

Email flow: you → SMTP → sender's mail server → SMTP → recipient's mail server → IMAP/POP3 → recipient.

---

## SSH — Secure Shell

SSH provides an **encrypted terminal session** to a remote machine. Also used for:
- Port forwarding (tunnel other protocols through SSH)
- SFTP (file transfer)
- Git remote operations (`git@github.com:...`)

Default port: **22**

```bash
ssh user@192.168.1.100
ssh -p 2222 user@server.com       # custom port
ssh -L 8080:localhost:80 user@server # local port forward
```

---

## Other Key Application Protocols

| Protocol | Port | Purpose |
|---------|------|---------|
| FTP | 20, 21 | File transfer (unencrypted, legacy) |
| SFTP | 22 | Encrypted file transfer over SSH |
| DHCP | 67/68 | Auto-assign IP addresses to hosts |
| NTP | 123 | Network time synchronization |
| SNMP | 161/162 | Network device monitoring and management |
| LDAP | 389, 636 | Directory services (user authentication) |
| RDP | 3389 | Windows remote desktop |
| Syslog | 514 | Log shipping to a central server |

---

## Try It With pktana

```bash
# Capture HTTP traffic
pktana capture --interface eth0 --filter "port 80" --count 20

# Capture DNS queries (port 53)
pktana capture --interface eth0 --filter "port 53" --count 10

# See all connections — note the application ports in use
pktana connections
```

In the pktana Web UI, expand a DNS packet to see:
- Query type (A, AAAA, CNAME)
- Question name
- Answer records with TTL

Expand an HTTP packet to see the full method, path, headers, and body.

---

## Summary

- The Application Layer defines **what** applications say to each other
- **HTTP/HTTPS** is the foundation of the web; HTTPS wraps HTTP in TLS for security
- **DNS** maps domain names to IP addresses using a hierarchical, cached system
- **TLS** provides encryption, authentication, and integrity for any protocol
- Dozens of application protocols exist — each tuned for a specific job

**Next:** [Network Topologies](08-topologies.md) — how networks are physically and logically arranged
