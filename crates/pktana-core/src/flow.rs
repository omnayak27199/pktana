// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::packet::{PacketSummary, TransportHeader};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: &'static str,
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub packets: usize,
    pub bytes: usize,
}

#[derive(Debug, Default)]
pub struct FlowTable {
    records: BTreeMap<FlowKey, FlowRecord>,
}

impl FlowTable {
    pub fn ingest(&mut self, summary: &PacketSummary) {
        let Some(ip) = &summary.ipv4 else {
            return;
        };

        let (source_port, destination_port, protocol) = match summary.transport.as_ref() {
            Some(TransportHeader::Tcp {
                source_port,
                destination_port,
                ..
            }) => (*source_port, *destination_port, "TCP"),
            Some(TransportHeader::Udp {
                source_port,
                destination_port,
                ..
            }) => (*source_port, *destination_port, "UDP"),
            _ => (0, 0, "OTHER"),
        };

        let key = FlowKey {
            source_ip: ip.source,
            destination_ip: ip.destination,
            source_port,
            destination_port,
            protocol,
        };

        // Use entry API to avoid double-lookup and unnecessary clone
        use std::collections::btree_map::Entry;
        match self.records.entry(key) {
            Entry::Occupied(mut entry) => {
                // Key already exists, just update stats
                entry.get_mut().packets += 1;
                entry.get_mut().bytes += summary.frame_len;
            }
            Entry::Vacant(entry) => {
                // New flow, insert with initial stats
                let record = FlowRecord {
                    key: entry.key().clone(),
                    packets: 1,
                    bytes: summary.frame_len,
                };
                entry.insert(record);
            }
        }
    }

    pub fn records(&self) -> Vec<&FlowRecord> {
        self.records.values().collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}
