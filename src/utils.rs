use std::ffi::CString;

use stacked_errors::{StackableErr, bail};
use xdp::nic::NicIndex;

const LOCAL_PORT_RANGE: &str = "/proc/sys/net/ipv4/ip_local_port_range";
/// quilkin relied on the default ephimeral port range being the default
/// (32768-60999), so that it could use 61000-65535 for its program.
/// This function checks that the system ephimeral port range is still
/// ends at 60999 and returns the range above it to u16::MAX
pub fn default_ephimeral_ports() -> stacked_errors::Result<Vec<(u16, u16)>> {
    let (start, end) = get_ephemeral_port_range().stack()?;

    if end != 60999 {
        bail!(format!(
            "Default ephimeral port range modified: {start} {end}"
        ));
    }

    Ok(vec![(end + 1, u16::MAX)])
}

/// Pass in a port range you would like to reserve for your program.
/// mutates the system ephimeral port range to exclude the provided range
/// returns an error if any part of the range is not available.
/// Assumes the passed ports are little endian u16
pub fn confirm_available_port_range(
    start: u16,
    end: u16,
) -> std::result::Result<(), std::io::Error> {
    let (sys_start, sys_end) = get_ephemeral_port_range()?;
    if sys_start > start {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "ephimeral range start not available: system start {} provided start {}",
                sys_start, start
            ),
        ));
    }
    // range starts at system range and stops prior to system end
    if sys_start == start && sys_end > end {
        //set system start to be
        mut_ephemeral_port_range(end + 1, sys_end)?;
        //the range ends at the end of the range available by the system
        //and starts after the system start
    } else if sys_end == end && start > sys_start {
        // set the available range to keep the system start and
        //stop right before our range start
        mut_ephemeral_port_range(sys_start, start - 1)?;
    }
    //todo: handle other cases (range in middle)

    // if start is after sys end, do nothing

    Ok(())
}

/// reads the system ephimeral port range from
/// /proc/sys/net/ipv4/ip_local_port_range
pub fn get_ephemeral_port_range() -> std::result::Result<(u16, u16), std::io::Error> {
    let port_range = std::fs::read_to_string(LOCAL_PORT_RANGE)?;
    let (start, end) =
        port_range
            .trim()
            .split_once(char::is_whitespace)
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected 2 u16 integers",
            ))?;
    let start: u16 = start.parse().map_err(|_e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse range start '{start}'"),
        )
    })?;
    let end: u16 = end.parse().map_err(|_e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse range end '{end}'"),
        )
    })?;
    Ok((start, end))
}

#[allow(unused)]
fn mut_ephemeral_port_range(start: u16, stop: u16) -> std::result::Result<(), std::io::Error> {
    std::fs::write(LOCAL_PORT_RANGE, format!(" {}   {}", start, stop));
    Ok(())
}

pub fn nic_index_from_name(iface: CString) -> stacked_errors::Result<NicIndex> {
    match NicIndex::lookup_by_name(&iface).stack() {
        Ok(Some(res)) => Ok(res),
        Ok(None) => bail!(format!("iface {:?} does not exists", &iface)),
        Err(e) => Err(e),
    }
}

///For functions that take bytes, offsets or lengths, this provides a
/// way to indicate where exactly in the packet the inner value starts
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum Lvl<T> {
    Eth(T),
    Ip(T),
    Transport(T),
    Data(T),
}

pub struct InvalidLvl;

impl<T> Lvl<T> {
    /// Helper function to be used in functions that
    /// expect to start at the eth header level
    pub fn into_eth(self) -> Result<T, InvalidLvl> {
        match self {
            Lvl::Eth(x) => Ok(x),
            _ => Err(InvalidLvl),
        }
    }

    /// Helper function to be used in functions that
    /// expect to start at the ip header level
    pub fn into_ip(self) -> Result<T, InvalidLvl> {
        match self {
            Lvl::Ip(x) => Ok(x),
            _ => Err(InvalidLvl),
        }
    }

    /// Helper function to be used in functions that
    /// expect to start at the transport header level
    pub fn into_transport(self) -> Result<T, InvalidLvl> {
        match self {
            Lvl::Transport(x) => Ok(x),
            _ => Err(InvalidLvl),
        }
    }

    /// Helper function to be used in functions that
    /// expect to start at the data inside the packet
    pub fn into_data(self) -> Result<T, InvalidLvl> {
        match self {
            Lvl::Data(x) => Ok(x),
            _ => Err(InvalidLvl),
        }
    }
}
