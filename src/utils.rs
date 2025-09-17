use std::ffi::CString;

use stacked_errors::{Result, StackableErr, bail};
use xdp::nic::NicIndex;

pub fn reserved_port_calculator() -> Vec<(u16, u16)> {
    todo!()
}

const LOCAL_PORT_RANGE: &str = "/proc/sys/net/ipv4/ip_local_port_range";
/// quilkin relied on the default ephimeral port range being
/// 32768-60999, so that it could use 61000-65535 for its program.
/// This function checks that the system ephimeral port range is still
/// ends at 60999 and returns the range above it to u16::MAX
pub fn default_ephimeral_ports() -> Result<Vec<(u16, u16)>> {
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
    if sys_start == start && sys_end > end {
        //set start..end aside for program
        mut_ephemeral_port_range(end, sys_end)?;
    } else if sys_end == end && start > sys_start {
        mut_ephemeral_port_range(start + 1, sys_end)?;
    }

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
    Ok((start.to_be(), end.to_be()))
}

#[allow(unused)]
fn mut_ephemeral_port_range(start: u16, stop: u16) -> std::result::Result<(), std::io::Error> {
    std::fs::write(LOCAL_PORT_RANGE, format!(" {}   {}", start, stop));
    Ok(())
}

pub fn nic_index_from_name(iface: CString) -> Result<NicIndex> {
    match NicIndex::lookup_by_name(&iface).stack() {
        Ok(Some(res)) => Ok(res),
        Ok(None) => bail!(format!("iface {:?} does not exists", &iface)),
        Err(e) => Err(e),
    }
}
