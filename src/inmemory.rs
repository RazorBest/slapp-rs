use std::collections::HashSet;

use crate::{NetworkSlappHandler, PayloadWrapper, SlappInterceptVerdict};

#[derive(Clone, Debug, Default)]
pub struct MemoryPacket {
    pub id: u64,
    pub data: Vec<u8>,
}

impl PayloadWrapper for MemoryPacket {
    fn get_payload_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[derive(Clone, Debug)]
pub enum SlappInmemoryVerdict {
    Accept(MemoryPacket),
    Drop(MemoryPacket),
}

pub struct SlappInmemoryNet<NetHandler>
where
    NetHandler: NetworkSlappHandler<MemoryPacket>,
{
    pub id_counter: u64,
    pub net_handler: NetHandler,
    pub packets: HashSet<u64>,
    pub verdicts: Vec<SlappInterceptVerdict<MemoryPacket>>,
}

impl<NetHandler> SlappInmemoryNet<NetHandler>
where
    NetHandler: NetworkSlappHandler<MemoryPacket>,
{
    /// Creates a new `Self` instance from `NetHandler`.
    ///
    /// # Arguments
    ///
    /// * `net_handler` - An instance that handles network packets.
    pub fn new_from_handler(net_handler: NetHandler) -> Self {
        Self {
            id_counter: 0,
            net_handler,
            packets: HashSet::new(),
            verdicts: vec![],
        }
    }

    pub fn push_packet(&mut self, data: Vec<u8>) -> u64 {
        self.id_counter += 1;
        let packet = MemoryPacket {
            id: self.id_counter,
            data,
        };
        self.packets.insert(self.id_counter);

        let verdicts = self.net_handler.on_payload(packet);

        self.verdicts.extend(verdicts);

        self.id_counter
    }

    pub fn consume(&mut self) -> impl Iterator<Item = SlappInmemoryVerdict> {
        use SlappInterceptVerdict::*;

        self.verdicts
            .drain(..)
            .inspect(|verdict| {
                let (Accept(packet) | Drop(packet)) = verdict else {
                    return;
                };
                self.packets.remove(&packet.id);
            })
            .filter_map(|verdict| match verdict {
                Accept(packet) => Some(SlappInmemoryVerdict::Accept(packet)),
                Drop(packet) => Some(SlappInmemoryVerdict::Drop(packet)),
                Keep => None,
            })
    }
}

impl<NetHandler> Default for SlappInmemoryNet<NetHandler>
where
    NetHandler: NetworkSlappHandler<MemoryPacket> + Default,
{
    fn default() -> Self {
        Self::new_from_handler(NetHandler::default())
    }
}
