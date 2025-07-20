pub trait ProcessorState: Clone + Send {}

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use stacked_errors::StackableErr;

use xdp::{
    Packet, Umem,
    error::PacketError,
    packet::{
        self, csum,
        net_types::{
            EthHdr, EtherType, IpAddresses, IpHdr, Ipv4Hdr, Ipv6Hdr, NetworkU16, UdpHdr, UdpHeaders,
        },
    },
    slab::{Slab, StackSlab},
};
use zerocopy::IntoBytes;

use crate::utils::default_ephimeral_ports;

pub trait PacketProcessor<const TXN: usize, S: ProcessorState, ProcessorError>:
    Fn(Packet, &mut S, &mut Umem, &mut StackSlab<TXN>) -> Result<(), ProcessorError>
{
    type ProcessorError;
}

#[inline]
pub fn process_packets<const RXN: usize, const TXN: usize, S, F, E>(
    rx_slab: &mut StackSlab<RXN>,
    umem: &mut Umem,
    tx_slab: &mut StackSlab<TXN>,
    worker_state: &mut S,
) where
    S: ProcessorState,
    F: PacketProcessor<TXN, S, E>,
{
    while let Some(mut buffer) = rx_slab.pop_back() {
        //<PrFn as Fn>/// How to respond after packet Processing
        todo!();
    }
}

fn create_ip_hdr(headers: &UdpHeaders, destination_addr: &SocketAddr) -> packet::net_types::IpHdr {
    match (&headers.ip, destination_addr) {
        (xdp::packet::net_types::IpHdr::V4(ipv4_hdr), SocketAddr::V4(socket_addr_v4)) => {
            IpAddresses::V4 {
                source: Ipv4Addr::try_from(ipv4_hdr.source.0).unwrap(),
                destination: *socket_addr_v4.ip(),
            }
        }
        //todo verify whether these branches are unreachable
        (xdp::packet::net_types::IpHdr::V4(_ipv4_hdr), SocketAddr::V6(_socket_addr_v6)) => {
            todo!("What to do here?")
        }
        (xdp::packet::net_types::IpHdr::V6(_ipv6_hdr), SocketAddr::V4(_socket_addr_v4)) => {
            todo!("What to do here?")
        }
        (xdp::packet::net_types::IpHdr::V6(ipv6_hdr), SocketAddr::V6(socket_addr_v6)) => {
            IpAddresses::V6 {
                source: Ipv6Addr::try_from(ipv6_hdr.source).unwrap(),
                destination: *socket_addr_v6.ip(),
            }
        }
    }
    .with_header(&headers.ip)
}


/// Modifies the headers of an existing well formed packet to a new source and
/// destination, resizing the header portion as needed if changing between ipv4
/// and ipv6
#[inline]
fn modify_packet_headers(
    original_header: &UdpHeaders,
    new: &mut UdpHeaders,
    packet: &mut Packet,
) -> stacked_errors::Result<()> {
    match (original_header.is_ipv4(), new.is_ipv4()) {
        (true, false) => packet.adjust_head(-20).stack()?,
        (false, true) => packet.adjust_head(20).stack()?,
        (..) => {}
    }
    tracing::info!(
        "setting packet headers, new len {}",
        (new.data.end - new.data.start + UdpHdr::LEN) as u16
    );
    tracing::info!("header len {}", new.udp.length);

    debug_set_packet_headers(new, packet).stack()?;
    tracing::info!("packet headers set");
    Ok(())
}

/// Writes the headers to the front of the packet buffer.
///
/// # Errors
///
/// The packet buffer must have enough space for all of the headers
pub fn debug_set_packet_headers(
    header: &mut UdpHeaders,
    packet: &mut Packet,
) -> Result<(), PacketError> {
    let mut offset = packet::net_types::EthHdr::LEN;

    let length = (header.data.end - header.data.start + UdpHdr::LEN) as u16;
    tracing::info!("inside xdp, length{length}");
    header.eth.ether_type = match &mut header.ip {
        IpHdr::V4(v4) => {
            v4.total_length = (length + Ipv4Hdr::LEN as u16).into();
            v4.calc_checksum();
            tracing::info!("about to write v4"); //, head-tail {}", Ipv4Hdr::len(*v4));
            packet.write(offset, *v4)?;
            offset += Ipv4Hdr::LEN;
            EtherType::Ipv4
        }
        IpHdr::V6(v6) => {
            v6.payload_length = length.into();
            packet.write(offset, *v6)?;
            offset += Ipv6Hdr::LEN;
            EtherType::Ipv6
        }
    };
    tracing::info!("pre eth xdp, length{length}");
    packet.write(0, header.eth)?;
    tracing::info!("pre udp xdp, length{length}");
    header.udp.length = length.into();
    packet.write(offset, header.udp)?;

    Ok(())
}

#[inline]
fn fill_packet(
    headers: &mut UdpHeaders,
    data: &[u8],
    data_checksum: csum::DataChecksum,
    frame: &mut Packet,
) -> stacked_errors::Result<()> {
    let hdr_len = headers.header_length();
    tracing::info!(hdr_len);
    frame.adjust_tail(hdr_len as i32).stack()?;
    headers.calc_checksum(data_checksum);
    headers.set_packet_headers(frame).stack()?;
    frame.insert(hdr_len, data).stack()?;
    Ok(())
}
//From quilken, we probably want to add something similar for the process of
// actually sending packets to collect metrics. also just copying here to figure
// out how to structure packet transmission
#[inline]
fn push_packet<const TXN: usize>(
    // direction: metrics::Direction,
    packet: Packet,
    // asn: AsnInfo<'_>,
    //data_length: usize,
    res: stacked_errors::Result<()>,
    tx_slab: &mut StackSlab<TXN>,
    umem: &mut Umem,
) {
    tracing::info!("made it to push packet");
    match res {
        Ok(()) => {
            if let Some(packet) = tx_slab.push_front(packet) {
                // metrics::packets_dropped_total(direction, "tx slab full",
                // &metrics::EMPTY).inc();
                umem.free_packet(packet);
                //         } else {
                //             metrics::packets_total(direction, &asn).inc();
                //             metrics::bytes_total(direction,
                // &asn).inc_by(data_length as u64);         }
            }
        }
        Err(err) => {
            tracing::error!("couldn't push packet. Error: {err}");
            //let discriminant = err.discriminant();
            // metrics::errors_total(direction, discriminant,
            // &metrics::EMPTY).inc();
            // metrics::packets_dropped_total(direction, discriminant,
            // &metrics::EMPTY).inc();
            umem.free_packet(packet);
        }
    }
}

#[derive(Debug)]
pub(crate) struct LocalPacket {
    /// The entire packet buffer, including headroom, initialized packet
    /// contents, and uninitialized/empty remainder
    pub(crate) data: *mut u8,
    pub(crate) capacity: usize,
    /// The offset in data where the packet starts
    pub(crate) head: usize,
    /// The offset in data where the packet ends
    pub(crate) tail: usize,
    pub(crate) base: *const u8,
    pub(crate) options: u32,
}

impl From<Packet> for LocalPacket {
    fn from(value: Packet) -> Self {
        unsafe { std::mem::transmute::<Packet, LocalPacket>(value) }
    }
}

impl Into<Packet> for LocalPacket {
    fn into(self) -> Packet {
        unsafe { std::mem::transmute::<LocalPacket, Packet>(self) }
    }
}
