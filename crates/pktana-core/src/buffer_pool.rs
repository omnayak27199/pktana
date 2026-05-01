// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, Mutex};

/// Pre-allocated packet buffer for zero-copy parsing.
/// Uses Arc for cheap cloning without re-allocation.
#[derive(Clone)]
pub struct PacketBuffer {
    data: Arc<Vec<u8>>,
}

impl fmt::Debug for PacketBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuffer")
            .field("len", &self.data.len())
            .field("strong_count", &Arc::strong_count(&self.data))
            .finish()
    }
}

impl PartialEq for PacketBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.data.as_ref() == other.data.as_ref()
    }
}

impl Eq for PacketBuffer {}

impl PacketBuffer {
    /// Create a new packet buffer from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            data: Arc::new(bytes),
        }
    }

    /// Create a packet buffer from a slice (allocates once).
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            data: Arc::new(bytes.to_vec()),
        }
    }

    /// Get a reference to the underlying data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the packet data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the reference count (number of clones still in use).
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.data)
    }
}

/// A thread-safe buffer pool for reusing packet buffers.
/// Reduces allocation overhead for high-throughput packet processing.
pub struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    max_size: usize,
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool.
    ///
    /// # Arguments
    /// * `max_size` - Maximum number of buffers to pool
    /// * `buffer_size` - Size of each pre-allocated buffer
    pub fn new(max_size: usize, buffer_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(max_size);
        for _ in 0..max_size {
            buffers.push(Vec::with_capacity(buffer_size));
        }

        Self {
            buffers: Mutex::new(buffers),
            max_size,
            buffer_size,
        }
    }

    /// Acquire a buffer from the pool or allocate a new one.
    pub fn acquire(&self) -> Vec<u8> {
        match self.buffers.lock() {
            Ok(mut pool) => pool
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(self.buffer_size)),
            Err(_) => Vec::with_capacity(self.buffer_size),
        }
    }

    /// Return a buffer to the pool for reuse.
    pub fn release(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        if let Ok(mut pool) = self.buffers.lock() {
            if pool.len() < self.max_size {
                pool.push(buffer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_buffer_cloning_is_cheap() {
        let buf = PacketBuffer::from_slice(b"hello");
        assert_eq!(buf.strong_count(), 1);

        let _buf2 = buf.clone();
        assert_eq!(buf.strong_count(), 2);

        let _buf3 = buf.clone();
        assert_eq!(buf.strong_count(), 3);
    }

    #[test]
    fn buffer_pool_reuses_buffers() {
        let pool = BufferPool::new(2, 1024);

        let buf1 = pool.acquire();
        let buf2 = pool.acquire();

        pool.release(buf1);
        pool.release(buf2);

        let reused1 = pool.acquire();
        assert_eq!(reused1.capacity(), 1024);
    }
}
