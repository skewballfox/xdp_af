#![allow(unused)]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use stacked_errors::StackableErr;
use xdp::{
    Packet,
    error::PacketError,
    packet::{
        self, csum,
        net_types::{EtherType, IpAddresses, IpHdr, Ipv4Hdr, UdpHdr, UdpHeaders},
    },
};

fn create_ip_hdr(headers: &UdpHeaders, destination_addr: &SocketAddr) -> packet::net_types::IpHdr {
    match (&headers.ip, destination_addr) {
        (xdp::packet::net_types::IpHdr::V4(ipv4_hdr), SocketAddr::V4(socket_addr_v4)) => {
            IpAddresses::V4 {
                source: Ipv4Addr::from(ipv4_hdr.source.0),
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
                source: Ipv6Addr::from(ipv6_hdr.source),
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
            offset += Ipv4Hdr::LEN;
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
