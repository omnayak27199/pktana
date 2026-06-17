# Layers 5, 6, 7 — Session, Presentation, and Application

In the TCP/IP model, OSI Layers 5, 6, and 7 are collapsed into a single **Application layer**. In practice, the functions of all three layers are performed by application software, protocol libraries, and the operating system's socket API — not by distinct protocol stacks.

This page covers all three layers together as the TCP/IP Application layer does, following the structure taught by Cisco NetAcademy.

---

## Layer 5 — Session Layer

The Session Layer manages the **lifecycle of a dialogue (session)** between two applications. A session is a higher-level concept than a TCP connection — it represents the context of an ongoing conversation, including authentication state, transaction boundaries, and recovery checkpoints.

### Session Establishment

Before two applications can exchange meaningful data, they must establish a shared context:
- **Authentication** — the session layer verifies identity before allowing access
- **Authorisation** — what the authenticated entity is permitted to do
- **Session token creation** — a token, cookie, or ID is issued to represent the established session, avoiding re-authentication on every request

### Dialog Control

The session layer controls the direction and flow of conversation:

**Simplex:** data flows in one direction only. Rare in modern applications.

**Half-duplex:** one side speaks at a time. Used by older protocols and some interactive command-line systems.

**Full-duplex:** both sides communicate simultaneously. All modern sessions (web browsing, database queries, API calls) are full-duplex — the client can send a new request while the server is still responding to the previous one.

### Synchronisation and Checkpointing

For long data transfers (large file uploads, database bulk exports), the session layer can insert **synchronisation points (checkpoints)**. If the transfer is interrupted, it can resume from the last checkpoint rather than starting over. FTP's restart mechanism and database transaction savepoints are examples.

### Session Layer in Practice

| Protocol | Session Layer Role |
|---------|-------------------|
| **SIP (Session Initiation Protocol)** | Establishes, modifies, and terminates VoIP and video call sessions |
| **RPC (Remote Procedure Call)** | Manages the context of remote function calls |
| **NetBIOS** | Session management for legacy Windows file sharing |
| **SOCKS** | Proxy protocol that establishes a tunnel session |
| **SQL sessions** | Database connection state: open connection, transaction context, cursor state |
| **TLS session resumption** | Re-uses a previously negotiated TLS session, skipping the full handshake |

In TCP/IP implementations, session layer functions are typically handled by TCP (for connection lifecycle) combined with application-layer tokens (HTTP cookies, JWT tokens, database session IDs).

---

## Layer 6 — Presentation Layer

The Presentation Layer ensures that data produced by one application can be **correctly interpreted by another**, regardless of internal data representations, platform differences, or security requirements.

### Data Translation and Encoding

Different systems use different internal representations for the same data:
- **ASCII vs EBCDIC:** ASCII (American Standard Code for Information Interchange) is used by Unix/Windows systems; EBCDIC is used by IBM mainframes. Sending a text file between the two requires character translation.
- **Unicode / UTF-8:** modern universal encoding. HTTP, JSON, XML, and HTML all use UTF-8 by default.
- **Big-endian vs Little-endian:** network byte order (big-endian) is specified by IP; the presentation layer ensures integers are transmitted in a consistent order.
- **Floating-point:** IEEE 754 is standard but must be agreed upon between communicating applications.

### Encryption and Decryption

The most important presentation layer function in modern networks is **TLS (Transport Layer Security)**. TLS encrypts application data before handing it to TCP, and decrypts it upon receipt — ensuring confidentiality, authentication, and integrity.

TLS sits between the application protocol (HTTP, SMTP, LDAP) and TCP. From TCP's perspective, it is just application data. From the application's perspective, TLS handles all security transparently.

### Compression

The presentation layer can compress data to reduce transmission size:
- **gzip / Brotli / zlib** — HTTP servers compress response bodies; browsers decompress them transparently
- **DEFLATE** — used in ZIP files and older HTTP compression
- **Video codecs (H.264, H.265, AV1)** — compress video streams for transmission

HTTP content negotiation: the browser sends `Accept-Encoding: gzip, br` in the request header; the server compresses the response and indicates `Content-Encoding: gzip` in the reply.

### Serialisation and Data Formats

Application objects (in-memory data structures) must be converted to a transmittable byte stream:

| Format | Type | Used By |
|--------|------|---------|
| **JSON** | Text, human-readable | REST APIs, web apps, configuration |
| **XML** | Text, verbose | SOAP APIs, RSS, older web services |
| **Protocol Buffers (Protobuf)** | Binary, compact, schema-required | gRPC, Google internal services |
| **MessagePack** | Binary JSON equivalent | High-performance APIs |
| **ASN.1 / DER** | Binary, strict | X.509 certificates, SNMP |
| **XDR** | Binary | NFS |
| **CBOR** | Binary | IoT, CoAP |

---

## Client-Server and Peer-to-Peer Models

Most networked applications follow one of two models for how they communicate.

### Client-Server Model

One party (the **client**) initiates requests; the other (the **server**) provides responses. The server is always listening and available; the client connects when it needs a service.

- The client initiates the TCP connection to the server's well-known port
- The server runs continuously, listening for connections
- Multiple clients can connect to the same server simultaneously
- The server holds the data or service; the client accesses it on demand

Examples: web browser (client) → web server; email client → IMAP server; DNS resolver → DNS authoritative server.

### Peer-to-Peer (P2P) Model

Every participant can act as both a client and a server simultaneously. There is no central server — peers connect directly to each other.

- Each node shares resources directly with other nodes
- Scales well — more participants = more resources, not more load on one server
- More complex: peer discovery, data consistency, no central control point

Examples: BitTorrent (file sharing), Bitcoin (distributed ledger), WebRTC (browser-to-browser voice/video), some VoIP systems.

---

## TLS — Transport Layer Security

TLS is the security protocol underlying HTTPS, SMTPS, IMAPS, FTPS, and any other "secure" application protocol. It provides:

- **Confidentiality** — data is encrypted; eavesdroppers read ciphertext
- **Integrity** — HMAC (Hash-based Message Authentication Code) detects any tampering
- **Authentication** — the server presents a digital certificate proving its identity

### TLS 1.3 Handshake (1 RTT)

```
Client                                      Server
  │──── ClientHello ─────────────────────►  │
  │     Supported cipher suites              │
  │     Client random nonce                  │
  │     Key share (ECDHE public key)         │
  │                                          │
  │◄─── ServerHello + Certificate ──────────│
  │     Chosen cipher suite                  │
  │     Server random nonce                  │
  │     Key share (server ECDHE public key)  │
  │     Server certificate                   │
  │     CertificateVerify + Finished         │
  │                                          │
  │──── Finished ─────────────────────────►  │
  │     Client verifies certificate          │
  │     Both sides derive session keys       │
  │                                          │
  │════════ Encrypted Application Data ══════│
```

Both sides derive the same symmetric session key from the ECDHE key exchange without transmitting the key — **forward secrecy** ensures that even if the server's private key is later compromised, past sessions cannot be decrypted.

**TLS 1.3 vs TLS 1.2:**

| Feature | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| Handshake RTT | 2 RTT | 1 RTT |
| 0-RTT reconnection | No | Yes (session tickets) |
| Key exchange | RSA or ECDHE | ECDHE only (forward secrecy mandatory) |
| Weak cipher suites | Many (RC4, 3DES, etc.) | Removed — only AEAD (AES-GCM, ChaCha20-Poly1305) |
| Forward secrecy | Optional | Mandatory |

### X.509 Certificates

A TLS certificate proves the server's identity. It contains:
- The server's **public key**
- The **domain name** it covers (Common Name or Subject Alternative Name)
- The **issuer** — the Certificate Authority (CA) that signed it
- **Validity period** (Not Before / Not After dates)
- The **CA's digital signature** over all the above

The browser verifies the certificate by:
1. Checking the domain name matches what was requested
2. Checking the certificate is not expired
3. Verifying the CA's signature using the CA's public key
4. Checking the CA is in the browser's trusted root store (~150 built-in CAs)

**Certificate chain:** Leaf → Intermediate CA → Root CA. Root CAs are self-signed and pre-installed in OS/browser trust stores.

**SNI (Server Name Indication):** a TLS extension where the client includes the target hostname in the ClientHello. This allows one server with one IP to host multiple domains with different certificates.

---

## HTTP — HyperText Transfer Protocol

HTTP is the foundation of the World Wide Web. Every web page, image, API call, and web form submission uses HTTP.

### HTTP Request Structure

```
GET /api/products?page=2 HTTP/1.1
Host: shop.example.com
Accept: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
User-Agent: Mozilla/5.0
Connection: keep-alive
```

- **Method:** what action to perform (GET, POST, PUT, DELETE...)
- **Path + Query string:** which resource and with what parameters
- **Version:** HTTP/1.1, HTTP/2, or HTTP/3
- **Headers:** metadata — who is asking, what format is acceptable, auth tokens, caching directives

### HTTP Methods

| Method | Purpose | Idempotent | Safe |
|--------|---------|-----------|------|
| **GET** | Retrieve a resource | Yes | Yes |
| **HEAD** | Like GET but no response body (check headers only) | Yes | Yes |
| **OPTIONS** | What methods does this server support? | Yes | Yes |
| **POST** | Submit data / create a new resource | No | No |
| **PUT** | Replace a resource entirely (idempotent — same result if repeated) | Yes | No |
| **PATCH** | Partially update a resource | No | No |
| **DELETE** | Remove a resource | Yes | No |
| **CONNECT** | Establish a TCP tunnel through an HTTP proxy (used for HTTPS) | No | No |

**Idempotent** means calling the same method multiple times produces the same result as calling it once. PUT and DELETE are idempotent; POST is not.

**Safe** means the method does not modify server state. GET, HEAD, OPTIONS are safe.

### HTTP Status Codes

Status codes tell the client whether the request succeeded, failed, or needs further action.

| Range | Meaning | Common Examples |
|-------|---------|----------------|
| **1xx** | Informational | 100 Continue, 101 Switching Protocols |
| **2xx** | Success | 200 OK, 201 Created, 204 No Content |
| **3xx** | Redirection | 301 Moved Permanently, 302 Found, 304 Not Modified |
| **4xx** | Client Error | 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 429 Too Many Requests |
| **5xx** | Server Error | 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout |

Key distinctions:
- **401 vs 403:** 401 = not authenticated (login required); 403 = authenticated but not authorised (forbidden)
- **301 vs 302:** 301 = permanent redirect (cache it); 302 = temporary redirect (don't cache)
- **502 vs 504:** 502 = upstream server returned an invalid response; 504 = upstream server did not respond in time

### HTTP Versions

**HTTP/1.0 (1996):** one request per TCP connection. After the response, the connection closes. Opening a new TCP connection for every request adds latency.

**HTTP/1.1 (1997):** persistent connections by default (`Connection: keep-alive`). Multiple requests can reuse one TCP connection. Also added: chunked transfer encoding, the mandatory `Host:` header (enabling virtual hosting), and pipelining (sending multiple requests without waiting for each response — limited support in practice).

**HTTP/2 (2015):** binary protocol (not human-readable text). Multiplexed streams over one TCP connection — multiple requests and responses interleaved simultaneously. Header compression (HPACK). Server push (server can proactively send resources the browser will need). Practically requires TLS (all major browsers require HTTPS for HTTP/2).

**HTTP/3 (2022):** same semantics as HTTP/2 but runs over **QUIC (UDP)** instead of TCP. Eliminates TCP-level head-of-line blocking, provides 0-RTT reconnections, and survives mobile network transitions.

### HTTP Caching

Caching reduces server load and improves client performance by storing responses locally.

| Header | Meaning |
|--------|---------|
| `Cache-Control: max-age=86400` | Cache this response for 86400 seconds (1 day) |
| `Cache-Control: no-cache` | Always revalidate with server before using cached copy |
| `Cache-Control: no-store` | Never cache this response (sensitive data) |
| `Cache-Control: public` | CDNs and shared caches may store this |
| `Cache-Control: private` | Only the user's browser may cache this |
| `ETag: "abc123def"` | A version fingerprint of the resource |
| `If-None-Match: "abc123def"` | Only return if ETag has changed (returns 304 if unchanged) |
| `Last-Modified: Wed, 21 Oct 2025 07:28:00 GMT` | When the resource was last changed |

---

## DNS — Domain Name System

DNS translates human-readable domain names (`www.google.com`) into IP addresses. It is the phone book of the Internet — without DNS, every user would need to memorise IP addresses.

### DNS Hierarchy

DNS is a distributed, hierarchical database. No single server knows all names:

```
.                         ← Root zone (13 root server clusters globally)
├── com.                  ← Generic Top-Level Domain (gTLD) managed by Verisign
├── org.
├── net.
├── uk.                   ← Country code TLD (ccTLD) managed by Nominet
│   └── co.uk.
└── google.com.           ← Second-level domain — Google manages this zone
    ├── www.google.com.   ← A record (IPv4 address)
    └── mail.google.com.  ← MX record target
```

### DNS Resolution Process

1. User types `www.example.com` in a browser
2. Browser checks its **internal DNS cache** (typically 1–5 min TTL) — hit? Done.
3. OS checks **`/etc/hosts`** (Linux/Mac) or `C:\Windows\System32\drivers\etc\hosts` (Windows) — match? Done.
4. OS sends query to the configured **recursive resolver** (your router, ISP DNS, or a public resolver like 8.8.8.8 or 1.1.1.1)
5. Recursive resolver checks its **cache** — hit? Return cached answer.
6. If not cached, recursive resolver queries a **root nameserver** (one of 13 clusters globally) → gets the address of the `.com` TLD nameserver
7. Queries the **`.com` TLD nameserver** → gets the address of `example.com`'s authoritative nameserver
8. Queries the **authoritative nameserver for `example.com`** → gets the A record: `93.184.216.34`
9. Recursive resolver **caches** the answer (per the TTL in the response) and returns it to the client
10. Browser connects to `93.184.216.34`

This full iterative lookup takes 20–100 ms. Cached lookups return in under 1 ms.

### DNS Record Types

| Type | Purpose | Example |
|------|---------|---------|
| **A** | Maps hostname to IPv4 address | `www.example.com → 93.184.216.34` |
| **AAAA** | Maps hostname to IPv6 address | `www.example.com → 2606:2800:220:1:248:1893:25c8:1946` |
| **CNAME** | Alias — hostname to hostname | `www.example.com → example.com` |
| **MX** | Mail server for a domain (with priority) | `example.com → 10 mail.example.com` |
| **TXT** | Arbitrary text — SPF, DKIM, domain verification | `"v=spf1 include:_spf.google.com ~all"` |
| **NS** | Authoritative nameservers for a zone | `example.com → ns1.example.com` |
| **PTR** | Reverse DNS: IP → hostname | `34.216.184.93.in-addr.arpa → www.example.com` |
| **SOA** | Zone metadata: serial number, refresh interval, contact | One per zone |
| **SRV** | Service location: server, port, priority, weight | `_sip._tcp.example.com → sip.example.com:5060` |
| **CAA** | Which CAs may issue TLS certs for this domain | `example.com CAA 0 issue "letsencrypt.org"` |

**CNAME restriction:** a CNAME cannot coexist with other record types at the same name. You cannot have both a CNAME and an MX record for `example.com`. CNAME at the zone apex (root domain) is not allowed in standard DNS — some providers offer an "ALIAS" or "ANAME" record as an extension.

### DNS TTL

Every DNS record has a **TTL (Time To Live)** in seconds, specifying how long resolvers may cache the answer.

- **Short TTL (60–300 seconds):** changes propagate quickly; useful before planned IP changes. More DNS queries.
- **Long TTL (3600–86400 seconds):** fewer queries; better performance. Changes take longer to propagate.

### Secure DNS

Standard DNS uses **UDP port 53** (or TCP for large responses/zone transfers) in **plaintext** — network observers can see every domain queried.

| Protocol | Port | Encryption | Standard |
|---------|------|-----------|---------|
| Plain DNS | 53 UDP/TCP | None | RFC 1035 |
| **DNS over TLS (DoT)** | 853 TCP | TLS | RFC 7858 |
| **DNS over HTTPS (DoH)** | 443 TCP | HTTPS | RFC 8484 |
| DNS over QUIC | 853 UDP | QUIC | RFC 9250 |

DoH is now default in Firefox and Chrome. It sends DNS queries as HTTPS requests to a DoH provider (Cloudflare, Google) — making DNS queries indistinguishable from normal HTTPS traffic.

**DNSSEC** adds digital signatures to DNS records, allowing resolvers to verify that answers have not been tampered with. Prevents **DNS cache poisoning** (Kaminsky attack).

---

## DHCP — Dynamic Host Configuration Protocol

DHCP automates IP address and network configuration assignment. Without DHCP, every device would need a manually configured IP address, subnet mask, default gateway, and DNS server.

DHCP uses **UDP** — server on port 67, client on port 68.

### DORA Process

| Step | Message | Direction | Purpose |
|------|---------|-----------|---------|
| **D**iscover | DHCPDISCOVER | Client → Broadcast (255.255.255.255) | "I need a network configuration" |
| **O**ffer | DHCPOFFER | Server → Client | "Here is 192.168.1.50 with these settings" |
| **R**equest | DHCPREQUEST | Client → Broadcast | "I accept 192.168.1.50 from this server" |
| **A**cknowledge | DHCPACK | Server → Client | "Confirmed — here is your full configuration" |

The client broadcasts the Request (instead of unicasting) so that other DHCP servers on the segment know their offers were declined.

**Configuration provided in DHCPACK:**
- IP address and lease duration
- Subnet mask
- Default gateway
- DNS server addresses
- Domain name
- NTP server (optional)

### DHCP Lease Renewal

When a lease reaches **50% of its lifetime (T1)**, the client unicasts a DHCPREQUEST to the server to renew. At **87.5% (T2)**, the client broadcasts a DHCPREQUEST to any available server. If the lease expires without renewal, the client loses its IP and must restart DORA.

### DHCP Relay Agent

DHCP uses broadcasts that routers do not forward. A DHCP relay agent (configured with `ip helper-address <server-IP>` in Cisco IOS) converts the client's broadcast to a unicast and forwards it to the DHCP server on another subnet. This allows one central DHCP server to serve multiple network segments.

### DHCP Security

**Rogue DHCP server:** an attacker connects an unauthorised DHCP server to the network. If it responds before the legitimate server, clients receive incorrect gateway and DNS settings — enabling man-in-the-middle attacks.

**DHCP snooping:** a switch security feature that marks only authorised ports (those connected to legitimate DHCP servers) as trusted. DHCP offers arriving on untrusted ports are dropped.

---

## Web and Email Protocols

### HTTP and HTTPS

HTTP was covered above. HTTPS is HTTP running inside a TLS tunnel — all request/response content is encrypted. The browser connects to TCP port 443 instead of 80, negotiates a TLS session, and then sends standard HTTP inside it.

HTTP Strict Transport Security (HSTS) is a response header (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) that tells browsers to only connect via HTTPS for the specified duration — even if the user types `http://`.

### SMTP — Simple Mail Transfer Protocol

SMTP is the protocol for **sending email**: from mail client to mail server, and between mail servers.

| Port | Usage |
|------|-------|
| 25 | Server-to-server mail relay (MTA to MTA); blocked by ISPs for residential users |
| 587 | Client mail submission with STARTTLS (upgrade to TLS within SMTP session) |
| 465 | Client mail submission with implicit TLS (TLS from the start) |

**SMTP session flow:**
```
Client: EHLO client.example.com
Server: 250 OK (lists supported extensions)
Client: MAIL FROM: <alice@example.com>
Server: 250 OK
Client: RCPT TO: <bob@example.com>
Server: 250 OK
Client: DATA
Server: 354 Start input
Client: Subject: Hello
Client: .  (single dot ends the message body)
Server: 250 OK Message queued
Client: QUIT
```

**Email authentication** prevents spoofing and phishing:
- **SPF (Sender Policy Framework):** a DNS TXT record listing IP addresses authorised to send mail for the domain. Receiving servers check whether the sending server's IP is in the SPF record.
- **DKIM (DomainKeys Identified Mail):** the sending mail server signs outgoing messages with a private key. The public key is published in DNS. Receiving servers verify the signature — proves the email came from the claimed domain and was not altered.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** ties SPF and DKIM together. The domain owner publishes a DMARC policy specifying what to do when SPF or DKIM fail: `p=none` (report only), `p=quarantine` (spam folder), or `p=reject` (block).

### IMAP and POP3 — Receiving Email

| Feature | IMAP (port 143 / 993 TLS) | POP3 (port 110 / 995 TLS) |
|---------|--------------------------|--------------------------|
| Email storage | Stays on server | Downloaded to client |
| Multi-device access | Yes — folders and read state synced | No — one device only |
| Folder management | Full server-side folders | No |
| Bandwidth | Higher (syncs state) | Lower (download once) |
| Offline access | Limited (cached locally) | Full (everything downloaded) |
| Modern use | Standard for all email clients | Legacy; used in simple scripts |

IMAP is the universal standard for modern multi-device email. POP3 is used in automated workflows that download and delete messages for processing.

---

## File Sharing Services

### FTP — File Transfer Protocol

FTP uses two TCP connections: **port 21** for control (commands and responses) and a separate data connection for file transfer.

**Active mode (PORT):** client opens port 21 to the server for control; server initiates a connection back to the client's port 20 for data. Problematic — the server initiating a connection is blocked by most client-side firewalls and NAT.

**Passive mode (PASV):** client opens both connections. Client opens port 21 for control; server tells client a high-numbered port to connect to for data. Firewall-friendly — the client initiates all connections. Passive mode is the standard today.

FTP transmits credentials and data in **plaintext**. Use SFTP or FTPS for secure file transfer.

**FTPS (FTP Secure):** FTP with TLS. Port 990 (implicit TLS) or port 21 with STARTTLS upgrade.

### SFTP — SSH File Transfer Protocol

SFTP is a completely separate protocol from FTP — it is a file transfer subsystem of SSH, not FTP over SSH. Uses **TCP port 22** (the SSH port). Provides encrypted file transfer, directory listing, and remote file management.

```bash
sftp user@hostname
sftp> ls
sftp> get remote-file.txt
sftp> put local-file.txt /remote/path/
```

### TFTP — Trivial File Transfer Protocol

TFTP uses **UDP port 69** — no authentication, no directory listing, very simple. Used for:
- Network device firmware and configuration file upload/download (Cisco `copy tftp flash:`)
- PXE boot — loading OS boot images over the network
- IP phones downloading configuration

TFTP is suitable only on trusted, controlled networks.

### SMB — Server Message Block

SMB (**TCP port 445**) is the Windows file and printer sharing protocol. It allows Windows clients to access shared folders, printers, and services on Windows servers. SMB3 (current version) supports encryption and signing. SAMBA implements SMB on Linux/Unix.

---

## Remote Access Protocols

### SSH — Secure Shell

SSH (**TCP port 22**) provides an encrypted interactive terminal session to a remote machine. It also supports:
- **Secure file transfer** via SCP and SFTP
- **Port forwarding** — tunnel other protocols through the SSH connection
- **Git remote operations** — `git@github.com` uses SSH

```bash
ssh user@192.168.1.100                   # Basic connection
ssh -p 2222 user@host                    # Custom port
ssh -L 8080:localhost:80 user@host       # Local port forward
ssh -R 9090:localhost:80 user@host       # Remote port forward
ssh -D 1080 user@host                    # SOCKS proxy
```

SSH authentication methods:
- **Password:** username + password over the encrypted tunnel
- **Public key:** client holds a private key; server stores the matching public key in `~/.ssh/authorized_keys`. No password is transmitted.
- **Certificate:** SSH certificate issued by an internal CA — scales to large fleets

### Telnet

Telnet (**TCP port 23**) was the predecessor to SSH — it provides a remote terminal session but with **no encryption**. Credentials and all session data are transmitted in plaintext. Telnet is **never acceptable on any production network**. SSH replaced it in the late 1990s. The only remaining use is quick network debugging (`telnet hostname port` to test if a TCP port is open).

### RDP — Remote Desktop Protocol

RDP (**TCP port 3389**) is Microsoft's protocol for graphical remote desktop access to Windows. The client sees and controls the full Windows desktop. RDP should be protected with TLS (enabled by default in modern Windows) and should never be exposed directly to the Internet without a VPN or gateway.

---

## Network Management and Monitoring Protocols

### SNMP — Simple Network Management Protocol

SNMP (**UDP port 161** for queries, **UDP port 162** for traps) allows network management systems (NMS) to monitor and configure network devices (routers, switches, servers, printers).

**MIB (Management Information Base):** a hierarchical database of variables on the managed device. Each variable has an **OID (Object Identifier)** — e.g., `1.3.6.1.2.1.1.1` is the system description.

| SNMP Version | Security | Notes |
|-------------|---------|-------|
| SNMPv1 | Community string (plaintext) | Legacy; avoid |
| SNMPv2c | Community string (plaintext) | Most common still deployed |
| **SNMPv3** | Username + auth + encryption | Only version for production use |

**SNMP operations:**
- **GET:** NMS requests the value of a specific OID from the agent
- **GETNEXT:** retrieve the next OID (used to walk the MIB)
- **GETBULK (v2+):** retrieve multiple OIDs efficiently
- **SET:** NMS writes a value to the agent (configure device)
- **TRAP:** agent proactively notifies NMS of an event (interface down, CPU threshold exceeded)
- **INFORM (v2+):** like TRAP but requires acknowledgement from the NMS

### NTP — Network Time Protocol

NTP (**UDP port 123**) synchronises clocks across all network devices. Accurate time is essential for:
- **Log correlation** — comparing events across multiple devices requires consistent timestamps
- **Security** — TLS certificates have validity periods; time skew invalidates them
- **Authentication** — Kerberos requires clocks within 5 minutes of each other
- **Routing protocols** — some require time synchronisation

**NTP stratum:** measures distance from the reference clock.
| Stratum | Description |
|---------|------------|
| 0 | Atomic clock, GPS receiver — reference clock (not on the network) |
| 1 | Server directly connected to a stratum 0 source |
| 2 | Server synced from stratum 1 |
| 3 | Server synced from stratum 2 |
| ... | Each level adds ~1 ms of accuracy degradation |

Devices should sync from stratum 2 or lower for reliable accuracy. Public NTP pools (pool.ntp.org) are stratum 2–3.

### Syslog

Syslog (**UDP port 514** or TCP 514/601 for reliable delivery) is the standard protocol for sending log messages from network devices and servers to a central log server.

**Syslog severity levels:**

| Level | Name | Meaning |
|-------|------|---------|
| 0 | Emergency | System is unusable |
| 1 | Alert | Immediate action needed |
| 2 | Critical | Critical conditions |
| 3 | Error | Error conditions |
| 4 | Warning | Warning conditions |
| 5 | Notice | Normal but significant |
| 6 | Informational | Informational messages |
| 7 | Debug | Debug-level messages |

Centralised logging enables security monitoring (SIEM), compliance auditing, and troubleshooting across an entire infrastructure.

---

## Authentication and Directory Protocols

### LDAP — Lightweight Directory Access Protocol

LDAP (**TCP port 389**, TLS on port 636) is a protocol for accessing and maintaining distributed directory services. Active Directory (Microsoft's enterprise identity system) is an LDAP-compatible directory.

LDAP stores information as a hierarchical tree of **entries** (users, groups, computers, printers). Each entry has a **DN (Distinguished Name)**: `CN=Alice Smith,OU=Engineering,DC=example,DC=com`.

Used for: user authentication, group membership lookup, email address book, certificate storage.

### Kerberos

Kerberos (**TCP/UDP port 88**) is the authentication protocol used by Active Directory (and Linux systems in enterprise environments). It uses **tickets** — cryptographic tokens that prove identity without transmitting passwords.

**Kerberos flow:**
1. User logs in → client requests a **TGT (Ticket Granting Ticket)** from the **KDC (Key Distribution Centre)**
2. KDC verifies credentials → issues an encrypted TGT
3. When user accesses a service, client presents the TGT to the KDC and requests a **service ticket**
4. Client presents the service ticket to the target server → server grants access

No password is ever sent over the network. Kerberos requires **time synchronisation** (clocks within 5 minutes) — a common failure mode.

### RADIUS — Remote Authentication Dial-In User Service

RADIUS (**UDP port 1812** for authentication, **1813** for accounting) is the standard protocol for network access authentication. Used by:
- Wi-Fi with 802.1X authentication (enterprise WPA2/WPA3-Enterprise)
- VPN authentication
- Switch port authentication (802.1X / NAC)

RADIUS uses a client-server model: the network device (switch, AP, VPN concentrator) is the RADIUS client; the RADIUS server authenticates users.

RADIUS encrypts only the **password** in the Access-Request packet; other attributes are cleartext.

### TACACS+ — Terminal Access Controller Access Control System Plus

TACACS+ (**TCP port 49**) is a Cisco-developed AAA (Authentication, Authorisation, Accounting) protocol used for **device administration** — controlling who can log into routers, switches, and firewalls and what commands they can run.

| Feature | RADIUS | TACACS+ |
|---------|--------|---------|
| Transport | UDP | TCP |
| Encryption | Password only | Full packet |
| AAA separation | Combined | Separate A, A, A |
| Vendor | Open standard | Cisco-proprietary |
| Primary use | Network access (Wi-Fi, VPN) | Device administration |

---

## Summary

- **Layer 5 (Session):** manages session lifecycle — SIP for VoIP, RPC for remote calls, DHCP session state, TLS session resumption
- **Layer 6 (Presentation):** TLS encryption, gzip compression, JSON/XML/Protobuf serialisation, character encoding
- **Client-Server** model: server listens, client initiates — used by web, email, DNS, SSH
- **HTTP:** GET/POST/PUT/DELETE methods; 2xx success, 4xx client error, 5xx server error; HTTP/3 runs over QUIC
- **DNS:** hierarchical, cached name resolution; A, AAAA, CNAME, MX, TXT, PTR records; DoH/DoT for encryption
- **DHCP:** DORA process auto-assigns IP + gateway + DNS; relay agent crosses subnets
- **TLS:** 1-RTT handshake (TLS 1.3); certificate proves server identity; forward secrecy mandatory
- **Email:** SMTP sends (port 587), IMAP syncs (port 143), POP3 downloads (port 110); SPF/DKIM/DMARC prevent spoofing
- **SSH** (port 22): encrypted shell, SFTP, port forwarding — replaces plaintext Telnet
- **SNMP** (port 161/162): device monitoring — use SNMPv3 only; **NTP** (port 123): time sync; **Syslog** (port 514): centralised logging

**Next:** [Network Topologies](08-topologies.md) — how networks are physically and logically arranged
