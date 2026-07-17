// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

pub mod inner {
    use std::sync::Arc;

    use rmcp::{handler::server::wrapper::Parameters, schemars, serde_json, tool, tool_router};
    use serde::Deserialize;

    use pktana_core::{
        evaluate_packet, geoip_lookup_str, get_ethtool_report, get_nic_dataplane, get_nic_info,
        get_security_config, inspect, list_connections, list_nics, list_routes, CaptureConfig,
        FlowAnalyzer, LinuxCaptureEngine,
    };

    // ── Parameter structs ────────────────────────────────────────────────────────

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct InspectParams {
        /// Raw packet bytes as a hex string (spaces allowed). Example: "ffffffffffff..."
        pub hex: String,
    }

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct CaptureParams {
        /// Network interface name (e.g. "eth0", "ens3")
        pub interface: String,
        /// Number of packets to capture (max 500)
        pub count: Option<u32>,
        /// Optional BPF filter string (e.g. "tcp port 443")
        pub filter: Option<String>,
    }

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct PcapFileParams {
        /// Absolute path to the .pcap file on the server
        pub path: String,
        /// Maximum packets to analyse (default 500, max 5000)
        pub max_packets: Option<u32>,
    }

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct NicStatsParams {
        /// Network interface name (e.g. "eth0")
        pub interface: String,
    }

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct GeoipParams {
        /// List of IP addresses to look up
        pub ips: Vec<String>,
    }

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct FlowAnalysisParams {
        /// Network interface name (e.g. "eth0")
        pub interface: String,
        /// Number of packets to capture (max 500)
        pub count: Option<u32>,
        /// Optional BPF filter string
        pub filter: Option<String>,
    }

    // ── Helper: build a concise text summary of a DeepPacket ────────────────────

    fn summarise_deep_packet(dp: &pktana_core::DeepPacket) -> serde_json::Value {
        summarise_deep_packet_with_iface(dp, "", 0)
    }

    fn summarise_deep_packet_with_iface(
        dp: &pktana_core::DeepPacket,
        iface: &str,
        ts: u64,
    ) -> serde_json::Value {
        let proto = if dp.quic_detected {
            "QUIC".to_string()
        } else if dp.http2_detected {
            "HTTP2".to_string()
        } else if let Some(p) = &dp.app_proto {
            p.to_uppercase()
        } else if dp.tcp_src_port.is_some() {
            "TCP".to_string()
        } else if dp.udp_src_port.is_some() {
            "UDP".to_string()
        } else if dp.icmp_type.is_some() {
            "ICMP".to_string()
        } else if dp.arp.is_some() {
            "ARP".to_string()
        } else {
            "?".to_string()
        };

        let src = if let Some(ip) = dp.ip_src {
            if let Some(p) = dp.tcp_src_port.or(dp.udp_src_port) {
                format!("{ip}:{p}")
            } else {
                ip.to_string()
            }
        } else if let Some(s6) = &dp.ipv6_src {
            s6.clone()
        } else {
            dp.eth_src.clone()
        };

        let dst = if let Some(ip) = dp.ip_dst {
            if let Some(p) = dp.tcp_dst_port.or(dp.udp_dst_port) {
                format!("{ip}:{p}")
            } else {
                ip.to_string()
            }
        } else if let Some(d6) = &dp.ipv6_dst {
            d6.clone()
        } else {
            dp.eth_dst.clone()
        };

        let risk_label = if dp.risk_score >= 70 {
            "HIGH"
        } else if dp.risk_score >= 35 {
            "MEDIUM"
        } else {
            "LOW"
        };

        let mut out = serde_json::json!({
            "summary": dp.one_liner(),
            "protocol": proto,
            "src": src,
            "dst": dst,
            "frame_bytes": dp.frame_len,
            "risk_score": dp.risk_score,
            "risk_level": risk_label,
            "risk_reasons": dp.risk_reasons,
            "anomalies": dp.anomalies,
            "diagnosis": dp.diagnose(),
            "app_proto": dp.app_proto,
            "app_detail": dp.app_detail,
            "dns_query": dp.dns_query_name,
            "tls_sni": dp.app_detail.iter()
                .find(|l| l.starts_with("SNI"))
                .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string())),
            "tcp_flags": dp.tcp_flags_str,
            "quic_detected": dp.quic_detected,
            "http2_detected": dp.http2_detected,
            "category": dp.app_category,
        });

        let sec_cfg = get_security_config();
        if sec_cfg.dlp_enabled || sec_cfg.idps_enabled {
            let sec = evaluate_packet(dp, ts, dp.frame_len as u64, iface, "");
            if let Some(obj) = out.as_object_mut() {
                obj.insert(
                    "security_verdict".into(),
                    serde_json::Value::String(sec.verdict),
                );
                obj.insert(
                    "security_dropped".into(),
                    serde_json::Value::Bool(sec.dropped),
                );
                obj.insert(
                    "security_alerts".into(),
                    serde_json::to_value(&sec.alerts).unwrap_or_else(|_| serde_json::json!([])),
                );
                obj.insert(
                    "security_engines".into(),
                    serde_json::to_value(&sec.engines).unwrap_or_else(|_| serde_json::json!([])),
                );
            }
        }
        out
    }

    // ── MCP Server struct ────────────────────────────────────────────────────────

    pub struct PktanaMcpServer;

    #[tool_router(server_handler)]
    impl PktanaMcpServer {
        /// Deep packet inspection from raw hex bytes. Returns protocol layers,
        /// risk assessment, anomalies and diagnosis for a single packet.
        #[tool(
            name = "inspect_packet",
            description = "Deep packet inspection: decode all protocol layers (Ethernet/IP/TCP/UDP/TLS/DNS/HTTP/...) from raw hex bytes and return risk score, anomalies, and diagnosis."
        )]
        async fn inspect_packet(
            &self,
            Parameters(InspectParams { hex }): Parameters<InspectParams>,
        ) -> String {
            let result = tokio::task::spawn_blocking(move || {
                let cleaned: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if !cleaned.len().is_multiple_of(2) {
                    return Err("Hex string has odd length".to_string());
                }
                let bytes: Result<Vec<u8>, _> = (0..cleaned.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| e.to_string()))
                    .collect();
                let bytes = bytes?;
                let dp = inspect(&bytes);
                Ok(serde_json::to_string_pretty(&summarise_deep_packet(&dp))
                    .unwrap_or_else(|e| e.to_string()))
            })
            .await;
            match result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => format!("{{\"error\":\"{e}\"}}"),
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// Capture live packets from a network interface.
        /// Requires root or CAP_NET_RAW.
        #[tool(
            name = "capture_live",
            description = "Capture live packets from a network interface and return DPI summaries. Requires root or CAP_NET_RAW. Count is capped at 500."
        )]
        async fn capture_live(
            &self,
            Parameters(CaptureParams {
                interface,
                count,
                filter,
            }): Parameters<CaptureParams>,
        ) -> String {
            let result = tokio::task::spawn_blocking(move || {
                let max = count.unwrap_or(50).min(500) as usize;
                let config = CaptureConfig {
                    interface,
                    max_packets: max,
                    promiscuous: true,
                    snapshot_len: 65_535,
                    filter,
                    pcap_export: None,
                };
                let mut packets = Vec::new();
                let stats = LinuxCaptureEngine::capture_streaming(&config, |pkt| {
                    let dp = inspect(&pkt.data);
                    packets.push(summarise_deep_packet_with_iface(
                        &dp,
                        &config.interface,
                        pkt.timestamp_sec as u64,
                    ));
                    true
                })
                .map_err(|e| e.to_string())?;
                let out = serde_json::json!({
                    "packets_captured": stats.packets_seen,
                    "bytes_captured": stats.bytes_seen,
                    "packets": packets,
                });
                Ok::<String, String>(
                    serde_json::to_string_pretty(&out).unwrap_or_else(|e| e.to_string()),
                )
            })
            .await;
            match result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => format!("{{\"error\":\"{e}\"}}"),
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// Analyse a PCAP file on disk.
        #[tool(
            name = "analyze_pcap_file",
            description = "Analyse a .pcap file on the server's filesystem and return per-packet DPI summaries plus protocol breakdown."
        )]
        async fn analyze_pcap_file(
            &self,
            Parameters(PcapFileParams { path, max_packets }): Parameters<PcapFileParams>,
        ) -> String {
            let result = tokio::task::spawn_blocking(move || {
                let max = max_packets.unwrap_or(500).min(5000) as usize;
                let mut packets = Vec::new();
                let mut count = 0usize;
                let stats = LinuxCaptureEngine::read_pcap_file(&path, |pkt| {
                    if count < max {
                        let dp = inspect(&pkt.data);
                        packets.push(summarise_deep_packet_with_iface(
                            &dp,
                            "pcap",
                            pkt.timestamp_sec as u64,
                        ));
                        count += 1;
                        true
                    } else {
                        false
                    }
                })
                .map_err(|e| e.to_string())?;

                // Protocol breakdown
                let mut proto_counts: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                for p in &packets {
                    let proto = p["protocol"].as_str().unwrap_or("?").to_string();
                    *proto_counts.entry(proto).or_insert(0) += 1;
                }
                let mut proto_vec: Vec<_> = proto_counts.into_iter().collect();
                proto_vec.sort_by_key(|b| std::cmp::Reverse(b.1));

                let out = serde_json::json!({
                    "file": path,
                    "packets_read": stats.packets_seen,
                    "packets_analysed": packets.len(),
                    "protocol_breakdown": proto_vec,
                    "packets": packets,
                });
                Ok::<String, String>(
                    serde_json::to_string_pretty(&out).unwrap_or_else(|e| e.to_string()),
                )
            })
            .await;
            match result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => format!("{{\"error\":\"{e}\"}}"),
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// List active TCP/UDP connections.
        #[tool(
            name = "list_connections",
            description = "List active TCP and UDP connections on the server, including local/remote addresses, state, PID, and process name."
        )]
        async fn list_connections(&self) -> String {
            let result = tokio::task::spawn_blocking(|| {
                let conns = list_connections();
                let rows: Vec<serde_json::Value> = conns
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "protocol": c.proto,
                            "local": format!("{}:{}", c.local_ip, c.local_port),
                            "remote": if c.remote_ip == "0.0.0.0" && c.remote_port == 0 {
                                "—".to_string()
                            } else {
                                format!("{}:{}", c.remote_ip, c.remote_port)
                            },
                            "state": c.state,
                            "pid": c.pid,
                            "process": c.process,
                        })
                    })
                    .collect();
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": rows.len(),
                    "connections": rows,
                }))
                .unwrap_or_else(|e| e.to_string())
            })
            .await;
            match result {
                Ok(s) => s,
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// List kernel routing table entries.
        #[tool(
            name = "list_routes",
            description = "List the kernel routing table (IPv4 + IPv6) including destinations, gateways, interfaces, and metrics."
        )]
        async fn list_routes(&self) -> String {
            let result = tokio::task::spawn_blocking(|| {
                let routes = list_routes();
                let rows: Vec<serde_json::Value> = routes
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "interface": r.interface,
                            "destination": r.destination,
                            "prefix_len": r.prefix_len,
                            "gateway": r.gateway,
                            "metric": r.metric,
                            "summary": r.summary,
                            "is_default": r.is_default,
                        })
                    })
                    .collect();
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": rows.len(),
                    "routes": rows,
                }))
                .unwrap_or_else(|e| e.to_string())
            })
            .await;
            match result {
                Ok(s) => s,
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// List available network interfaces.
        #[tool(
            name = "list_interfaces",
            description = "List all network interfaces on the server with their state, MAC address, IP addresses, speed, and MTU."
        )]
        async fn list_interfaces(&self) -> String {
            let result = tokio::task::spawn_blocking(|| {
                let nics = list_nics().map_err(|e| e.to_string())?;
                let rows: Vec<serde_json::Value> = nics
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "name": n.name,
                            "state": if n.is_up() { "UP" } else { "DOWN" },
                            "mac": n.mac,
                            "mtu": n.mtu,
                            "speed_mbps": n.speed_mbps,
                            "ip_addresses": n.ip_addresses,
                            "driver": n.driver,
                            "loopback": n.is_loopback(),
                            "rx_bytes": n.rx_bytes,
                            "tx_bytes": n.tx_bytes,
                        })
                    })
                    .collect();
                Ok::<String, String>(
                    serde_json::to_string_pretty(&serde_json::json!({
                        "count": rows.len(),
                        "interfaces": rows,
                    }))
                    .unwrap_or_else(|e| e.to_string()),
                )
            })
            .await;
            match result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => format!("{{\"error\":\"{e}\"}}"),
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// Get detailed NIC statistics for one interface.
        #[tool(
            name = "get_nic_stats",
            description = "Get detailed statistics for a specific network interface: driver info, link settings, offload features, IRQ affinity, extended counters."
        )]
        async fn get_nic_stats(
            &self,
            Parameters(NicStatsParams { interface }): Parameters<NicStatsParams>,
        ) -> String {
            let result = tokio::task::spawn_blocking(move || {
                let info = get_nic_info(&interface).map_err(|e| e.to_string())?;
                let dp = get_nic_dataplane(&interface).map_err(|e| e.to_string())?;
                let eth = get_ethtool_report(&interface).map_err(|e| e.to_string())?;

                let out = serde_json::json!({
                    "name": info.name,
                    "state": if info.is_up() { "UP" } else { "DOWN" },
                    "mac": info.mac,
                    "mtu": info.mtu,
                    "speed_mbps": info.speed_mbps,
                    "duplex": info.duplex,
                    "driver": info.driver,
                    "ip_addresses": info.ip_addresses,
                    "rx": {
                        "bytes": info.rx_bytes,
                        "packets": info.rx_packets,
                        "errors": info.rx_errors,
                        "dropped": info.rx_dropped,
                    },
                    "tx": {
                        "bytes": info.tx_bytes,
                        "packets": info.tx_packets,
                        "errors": info.tx_errors,
                        "dropped": info.tx_dropped,
                    },
                    "dataplane": {
                        "bypass_mode": format!("{}", dp.bypass_mode),
                        "xdp_prog_ids": dp.xdp_prog_ids,
                        "xdp_mode": dp.xdp_mode,
                        "afxdp_sockets": dp.afxdp_sockets,
                        "dpdk_bound": dp.dpdk_bound,
                        "userspace_driver": dp.userspace_driver,
                        "sriov_vfs_enabled": dp.sriov_vfs_enabled,
                        "sriov_vfs_total": dp.sriov_vfs_total,
                        "tc_clsact": dp.tc_clsact,
                        "tc_bpf_directions": dp.tc_bpf_directions,
                        "tc_bpf_prog_ids": dp.tc_bpf_prog_ids,
                        "pci_link_speed": dp.pci_link_speed,
                        "pci_link_width": dp.pci_link_width,
                        "hw_features_on": dp.hw_features_on,
                        "pci_address": dp.pci_address,
                    },
                    "ethtool": {
                        "pci_address": dp.pci_address,
                        "firmware_ver": eth.firmware_ver,
                        "bus_info": eth.bus_info,
                        "rx_queues": eth.rx_queues,
                        "tx_queues": eth.tx_queues,
                        "features": eth.features,
                    },
                });
                Ok::<String, String>(
                    serde_json::to_string_pretty(&out).unwrap_or_else(|e| e.to_string()),
                )
            })
            .await;
            match result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => format!("{{\"error\":\"{e}\"}}"),
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// Batch GeoIP lookup for a list of IP addresses.
        #[tool(
            name = "geoip_lookup",
            description = "Perform offline GeoIP lookup for one or more IP addresses. Returns country, region, city, ISP, and coordinates."
        )]
        async fn geoip_lookup(
            &self,
            Parameters(GeoipParams { ips }): Parameters<GeoipParams>,
        ) -> String {
            let result = tokio::task::spawn_blocking(move || {
                let rows: Vec<serde_json::Value> = ips
                    .iter()
                    .map(|ip| match geoip_lookup_str(ip) {
                        Some(info) => serde_json::json!({
                            "ip": ip,
                            "country_code": info.country_code,
                            "country_name": info.country_name,
                            "continent": info.continent,
                        }),
                        None => serde_json::json!({
                            "ip": ip,
                            "country_code": null,
                            "country_name": "Unknown / Private",
                            "continent": null,
                        }),
                    })
                    .collect();
                serde_json::to_string_pretty(&serde_json::json!({ "results": rows }))
                    .unwrap_or_else(|e| e.to_string())
            })
            .await;
            match result {
                Ok(s) => s,
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// Get server system info.
        #[tool(
            name = "get_server_info",
            description = "Get system information from the pktana server: hostname, uptime, memory usage."
        )]
        async fn get_server_info(&self) -> String {
            let result = tokio::task::spawn_blocking(|| {
                let hostname = {
                    let mut buf = [0i8; 256];
                    unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) };
                    let bytes: Vec<u8> = buf
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect();
                    String::from_utf8_lossy(&bytes).to_string()
                };

                let uptime_secs = std::fs::read_to_string("/proc/uptime")
                    .ok()
                    .and_then(|s| {
                        s.split_whitespace()
                            .next()
                            .and_then(|v| v.parse::<f64>().ok())
                    })
                    .unwrap_or(0.0);

                let (mem_total_kb, mem_available_kb) = std::fs::read_to_string("/proc/meminfo")
                    .ok()
                    .map(|s| {
                        let mut total = 0u64;
                        let mut avail = 0u64;
                        for line in s.lines() {
                            if line.starts_with("MemTotal:") {
                                total = line
                                    .split_whitespace()
                                    .nth(1)
                                    .and_then(|v| v.parse().ok())
                                    .unwrap_or(0);
                            } else if line.starts_with("MemAvailable:") {
                                avail = line
                                    .split_whitespace()
                                    .nth(1)
                                    .and_then(|v| v.parse().ok())
                                    .unwrap_or(0);
                            }
                        }
                        (total, avail)
                    })
                    .unwrap_or((0, 0));

                let uptime_h = (uptime_secs as u64) / 3600;
                let uptime_m = ((uptime_secs as u64) % 3600) / 60;

                serde_json::to_string_pretty(&serde_json::json!({
                    "hostname": hostname,
                    "uptime_seconds": uptime_secs as u64,
                    "uptime_human": format!("{uptime_h}h {uptime_m}m"),
                    "memory_total_mb": mem_total_kb / 1024,
                    "memory_available_mb": mem_available_kb / 1024,
                    "memory_used_mb": (mem_total_kb - mem_available_kb) / 1024,
                    "memory_used_pct": ((mem_total_kb - mem_available_kb) * 100).checked_div(mem_total_kb).unwrap_or(0)
                }))
                .unwrap_or_else(|e| e.to_string())
            })
            .await;
            match result {
                Ok(s) => s,
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }

        /// Run TCP/TLS/DHCP/DNS flow analysis on a live interface.
        #[tool(
            name = "run_flow_analysis",
            description = "Capture packets and run TCP/TLS handshake, DHCP DORA, and DNS transaction flow analysis. Requires root or CAP_NET_RAW."
        )]
        async fn run_flow_analysis(
            &self,
            Parameters(FlowAnalysisParams {
                interface,
                count,
                filter,
            }): Parameters<FlowAnalysisParams>,
        ) -> String {
            let result = tokio::task::spawn_blocking(move || {
                let max = count.unwrap_or(100).min(500) as usize;
                let config = CaptureConfig {
                    interface,
                    max_packets: max,
                    promiscuous: true,
                    snapshot_len: 65_535,
                    filter,
                    pcap_export: None,
                };
                let mut analyzer = FlowAnalyzer::new();
                let mut events: Vec<String> = Vec::new();
                let _stats = LinuxCaptureEngine::capture_streaming(&config, |pkt| {
                    let dp = inspect(&pkt.data);
                    let results = analyzer.analyze_packet(&dp);
                    for r in results {
                        events.push(r);
                    }
                    true
                })
                .map_err(|e| e.to_string())?;

                let summary = analyzer.get_summary();
                Ok::<String, String>(
                    serde_json::to_string_pretty(&serde_json::json!({
                        "events": events,
                        "summary": {
                            "total_tcp_flows": summary.total_tcp_flows,
                            "complete_tcp_handshakes": summary.complete_tcp_handshakes,
                            "total_tls_flows": summary.total_tls_flows,
                            "complete_tls_handshakes": summary.complete_tls_handshakes,
                            "total_dhcp_flows": summary.total_dhcp_flows,
                            "complete_dhcp_dora": summary.complete_dhcp_dora,
                        },
                    }))
                    .unwrap_or_else(|e| e.to_string()),
                )
            })
            .await;
            match result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => format!("{{\"error\":\"{e}\"}}"),
                Err(e) => format!("{{\"error\":\"task panic: {e}\"}}"),
            }
        }
    }

    // ── Helpers for startup banner ───────────────────────────────────────────────

    /// Return the primary outgoing IP by connecting a UDP socket (no data sent).
    fn detect_primary_ip() -> String {
        std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| {
                s.connect("8.8.8.8:53")?;
                s.local_addr()
            })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "YOUR_SERVER_IP".to_string())
    }

    /// Return the path of the `claude` CLI binary if installed, or None.
    fn find_claude_cli() -> Option<String> {
        let known = [
            "/usr/local/bin/claude",
            "/usr/bin/claude",
            "/root/.npm/bin/claude",
            "/root/.local/bin/claude",
        ];
        for p in &known {
            if std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
        std::process::Command::new("which")
            .arg("claude")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    // ── Server entry point ───────────────────────────────────────────────────────

    pub fn run_mcp_server(port: u16, host: &str, stdio: bool) -> Result<(), String> {
        // Warn if not root — capture tools will fail silently
        if unsafe { libc::geteuid() } != 0 {
            eprintln!(
                "Warning: pktana MCP server is running without root/CAP_NET_RAW.\n\
                 Tools: list_connections, list_routes, list_interfaces, inspect_packet,\n\
                 geoip_lookup, get_nic_stats, get_server_info — will work.\n\
                 Tools: capture_live, analyze_pcap_file (live), run_flow_analysis — need root."
            );
        }

        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

        rt.block_on(async {
            if stdio {
                eprintln!("pktana MCP server starting (stdio mode)…");
                let transport = rmcp::transport::io::stdio();
                rmcp::serve_server(PktanaMcpServer, transport)
                    .await
                    .map_err(|e| e.to_string())?
                    .waiting()
                    .await
                    .map_err(|e| e.to_string())?;
            } else {
                use rmcp::transport::streamable_http_server::{
                    session::local::LocalSessionManager, StreamableHttpServerConfig,
                    StreamableHttpService,
                };

                let addr = format!("{host}:{port}");

                // Resolve the real IP to show in connection instructions.
                // If bound to 0.0.0.0, detect the primary outgoing interface IP.
                let display_ip = if host == "0.0.0.0" {
                    detect_primary_ip()
                } else {
                    host.to_string()
                };
                let mcp_url = format!("http://{}:{}/mcp", display_ip, port);

                let bar = "━".repeat(62);
                eprintln!("{bar}");
                eprintln!("  pktana MCP server  listening on  http://{addr}/mcp");
                eprintln!("{bar}");
                eprintln!();
                eprintln!("  Server IP  : {display_ip}");
                eprintln!("  MCP URL    : {mcp_url}");
                eprintln!();

                // ── Claude CLI ──────────────────────────────────────────────────
                match find_claude_cli() {
                    Some(claude_bin) => {
                        eprintln!("  [1] Claude CLI  ({claude_bin})");
                        eprintln!("      Run on the machine where you use Claude:");
                        eprintln!();
                        eprintln!("        claude mcp add --transport http pktana {mcp_url}");
                        eprintln!();
                        eprintln!("      Then start Claude and ask:");
                        eprintln!("        \"list network interfaces on this server\"");
                        eprintln!("        \"show active TCP connections\"");
                        eprintln!("        \"capture 20 packets on m1\"");
                    }
                    None => {
                        eprintln!("  [1] Claude CLI — not found, install it first:");
                        eprintln!();
                        eprintln!("      # Ubuntu/Debian");
                        eprintln!("        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -");
                        eprintln!("        apt-get install -y nodejs");
                        eprintln!();
                        eprintln!("      # RHEL/CentOS/Rocky");
                        eprintln!("        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -");
                        eprintln!("        dnf install -y nodejs");
                        eprintln!();
                        eprintln!("      # Then install Claude Code CLI");
                        eprintln!("        npm install -g @anthropic-ai/claude-code");
                        eprintln!();
                        eprintln!("      After installing, register pktana:");
                        eprintln!("        claude mcp add --transport http pktana {mcp_url}");
                    }
                }

                // ── Claude Desktop ──────────────────────────────────────────────
                eprintln!();
                eprintln!("  [2] Claude Desktop — edit claude_desktop_config.json:");
                eprintln!("        Linux : ~/.config/claude/claude_desktop_config.json");
                eprintln!("        macOS : ~/Library/Application Support/Claude/claude_desktop_config.json");
                eprintln!("        Windows: %APPDATA%\\Claude\\claude_desktop_config.json");
                eprintln!();
                eprintln!("      {{\"mcpServers\":{{\"pktana\":{{\"url\":\"{mcp_url}\"}}}}}}");
                eprintln!();
                eprintln!("{bar}");

                let session_manager = Arc::new(LocalSessionManager::default());

                // disable_allowed_hosts() sets the list to [] which allows all hosts
                let config = StreamableHttpServerConfig::default().disable_allowed_hosts();

                let mcp_service =
                    StreamableHttpService::new(|| Ok(PktanaMcpServer), session_manager, config);

                let app = axum::Router::new().nest_service("/mcp", mcp_service);

                let listener = tokio::net::TcpListener::bind(&addr)
                    .await
                    .map_err(|e| format!("bind {addr}: {e}"))?;

                axum::serve(listener, app)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })
    }
}
