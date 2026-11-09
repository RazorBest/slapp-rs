#![cfg(test)]

use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::Path;

use pcap_file::pcap::PcapReader;

use slapp::inmemory::{MemoryPacket, SlappInmemoryNet, SlappInmemoryVerdict};
use slapp::tcp::SlappTcpError;
use slapp::{
    ApplicationDataSlappHandler, InterceptVerdict, Ipv4Type, NetworkSlappHandler, NoSpy, SlappIpv4,
    SlappTcp, TransportSlappSpy,
};

#[derive(Debug, Default)]
struct TransportErrTracker {
    errors: Vec<SlappTcpError>,
}

impl TransportSlappSpy for TransportErrTracker {
    fn before(
        &mut self,
        _net_header: &[u8],
        _transport_header: &[u8],
        _data: &[u8],
        _session_id: u64,
    ) {
    }
    fn after(
        &mut self,
        _net_header: &[u8],
        _transport_header: &[u8],
        _is_client: bool,
        _data: &[u8],
        _session_id: u64,
        _verdict: &InterceptVerdict,
    ) {
    }
    fn close(&mut self, _is_client: bool, _session_id: u64) {}
    fn error(
        &mut self,
        _net_header: &[u8],
        _transport_header: &[u8],
        _data: &[u8],
        _session_id: u64,
        err: SlappTcpError,
    ) -> InterceptVerdict {
        self.errors.push(err);

        InterceptVerdict::Accept
    }
}

struct SlappPcapReplay<NetHandler>
where
    NetHandler: NetworkSlappHandler<MemoryPacket>,
{
    pub handler: SlappInmemoryNet<NetHandler>,
    pub pcap_reader: PcapReader<File>,
}

impl<NetHandler> SlappPcapReplay<NetHandler>
where
    NetHandler: NetworkSlappHandler<MemoryPacket>,
{
    fn new_from_handler(
        path: &Path,
        handler: SlappInmemoryNet<NetHandler>,
    ) -> Result<Self, Box<dyn Error>> {
        let file = File::open(path)?;
        let pcap_reader = PcapReader::new(file)?;

        Ok(Self {
            handler,
            pcap_reader,
        })
    }

    fn new(path: &Path) -> Result<Self, Box<dyn Error>>
    where
        NetHandler: Default,
    {
        Self::new_from_handler(path, SlappInmemoryNet::default())
    }

    fn replay(
        &mut self,
    ) -> (
        HashMap<u64, Vec<u8>>,
        impl Iterator<Item = SlappInmemoryVerdict>,
    ) {
        let mut packets: HashMap<u64, Vec<u8>> = HashMap::new();

        while let Some(packet) = self.pcap_reader.next_packet() {
            let packet = packet.expect("Error reading pcap packet");
            let packet_id = self.handler.push_packet(packet.data.to_vec());
            packets.insert(packet_id, packet.data.to_vec());
        }

        (packets, self.handler.consume())
    }
}

#[derive(Default)]
struct TransparentApp {}

impl ApplicationDataSlappHandler for TransparentApp {
    fn on_data(
        &mut self,
        _session_id: u64,
        _is_client: bool,
        _counter: i64,
        _data: &mut [u8],
    ) -> InterceptVerdict {
        InterceptVerdict::Accept
    }
    fn close(&mut self, _session_id: u64, _is_client: bool) {}
}

type Replayer = SlappPcapReplay<
    SlappIpv4<SlappTcp<TransparentApp, NoSpy, Ipv4Type, MemoryPacket>, NoSpy, MemoryPacket>,
>;
type ReplayerTrackErr = SlappPcapReplay<
    SlappIpv4<
        SlappTcp<TransparentApp, TransportErrTracker, Ipv4Type, MemoryPacket>,
        NoSpy,
        MemoryPacket,
    >,
>;

fn ensure_packets_not_modified(
    packets: HashMap<u64, Vec<u8>>,
    verdicts: impl Iterator<Item = SlappInmemoryVerdict>,
) {
    for verdict in verdicts {
        match verdict {
            SlappInmemoryVerdict::Accept(mp) => {
                assert_eq!(mp.data, packets[&mp.id]);
            }
            _ => {
                panic!("Unexpected verdict: {verdict:?}");
            }
        }
    }
}

#[test]
fn test_pcap_scenario1() {
    let mut replayer = Replayer::new(Path::new("./tests/scenarios/scenario1.pcap"))
        .expect("Failed initializing replayer");
    let (packets, verdicts) = replayer.replay();
    ensure_packets_not_modified(packets, verdicts);
}

#[test]
fn test_pcap_scenario2() {
    let mut replayer = Replayer::new(Path::new("./tests/scenarios/scenario2.pcap"))
        .expect("Failed initializing replayer");
    let (packets, verdicts) = replayer.replay();
    ensure_packets_not_modified(packets, verdicts);
}

#[test]
fn test_pcap_scenario3() {
    let mut replayer = Replayer::new(Path::new("./tests/scenarios/scenario3.pcap"))
        .expect("Failed initializing replayer");
    let (packets, verdicts) = replayer.replay();
    ensure_packets_not_modified(packets, verdicts);
}

#[test]
fn test_pcap_scenario4() {
    let mut replayer = Replayer::new(Path::new("./tests/scenarios/scenario4.pcap"))
        .expect("Failed initializing replayer");
    let (packets, verdicts) = replayer.replay();
    ensure_packets_not_modified(packets, verdicts);
}

#[test]
fn test_pcap_scenario5() {
    let mut replayer = Replayer::new(Path::new("./tests/scenarios/scenario5.pcap"))
        .expect("Failed initializing replayer");
    let (packets, verdicts) = replayer.replay();
    ensure_packets_not_modified(packets, verdicts);
}

#[test]
fn test_pcap_scenario6() {
    let mut replayer = ReplayerTrackErr::new(Path::new("./tests/scenarios/scenario6.pcap"))
        .expect("Failed initializing replayer");
    let (_, verdicts) = replayer.replay();
    let verdicts: Vec<SlappInmemoryVerdict> = verdicts.collect();

    assert_eq!(verdicts.len(), 2);
    let tspy = replayer.handler.net_handler.transport_handler.transport_spy;
    assert_eq!(tspy.errors.len(), 1);
    assert!(matches!(
        tspy.errors[0],
        SlappTcpError::NonZeroDataLengthInSyn
    ));
}

#[test]
fn test_pcap_scenario7() {
    let mut replayer = Replayer::new(Path::new("./tests/scenarios/scenario7.pcap"))
        .expect("Failed initializing replayer");
    let (packets, verdicts) = replayer.replay();
    ensure_packets_not_modified(packets, verdicts);
}
