use std::ffi::CString;

use procfs::ProcError;
use stacked_errors::{StackableErr, bail};
use thiserror::Error;
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
#[derive(Error, Debug)]
pub enum XdpCheckError {
    #[error("error while getting kernel info {0}")]
    ProcFsError(ProcError),
    #[error("error while getting driver info {0}")]
    IoError(std::io::Error),
    #[error("error while getting driver name")]
    DriverNameUnreadable,
    #[error("ethtool invocation failed: {0}")]
    EthtoolError(String),
}

/// Returns the best flag to use given the systems capability
pub fn get_xdp_capability(iface: &str) -> Result<Option<aya::programs::XdpFlags>, XdpCheckError> {
    let version = procfs::sys::kernel::Version::current().map_err(XdpCheckError::ProcFsError)?;
    // while support for XDP existed in some form since 4.18, gt 5.10 seems to be recommended for most features
    // I'll tweak this to be lower if someone request it (hint, hint)
    if version.major < 5 || (version.major == 5 && version.minor < 10) {
        return Ok(None);
    }
    if check_driver_hw_capable(iface)? {
        return Ok(Some(aya::programs::XdpFlags::HW_MODE));
    }

    //check if native and zero copy is supported
    if check_native_xdp_support(iface)? == Some(NativeSupport::ZeroCopy) {
        return Ok(Some(aya::programs::XdpFlags::DRV_MODE));
    }

    Ok(Some(aya::programs::XdpFlags::SKB_MODE))
}

#[derive(Debug, PartialEq)]
enum NativeSupport {
    ZeroCopy, // xdp-zc: on  (implies native too)
    Native,   // xdp-native: on, xdp-zc: off
}

fn check_driver_hw_capable(iface: &str) -> Result<bool, XdpCheckError> {
    // HW_MODE offload is realistically only nfp today
    const HW_OFFLOAD_DRIVERS: &[&str] = &["nfp"];
    let driver = get_driver_name(iface)?;
    Ok(HW_OFFLOAD_DRIVERS.contains(&driver.as_str()))
}

fn get_driver_name(iface: &str) -> Result<String, XdpCheckError> {
    let path = format!("/sys/class/net/{}/device/driver", iface);
    let link = std::fs::read_link(&path).map_err(XdpCheckError::IoError)?;
    link.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or(XdpCheckError::DriverNameUnreadable)
}

/// Runs `ethtool -k <iface>` and parses xdp-native / xdp-zc feature flags.
/// ethtool is part of the standard Linux net-tools suite and can be assumed
/// present on any system where XDP is relevant.
fn check_native_xdp_support(iface: &str) -> Result<Option<NativeSupport>, XdpCheckError> {
    let out = std::process::Command::new("ethtool")
        .args(["-k", iface])
        .output()
        .map_err(XdpCheckError::IoError)?;

    if !out.status.success() {
        return Err(XdpCheckError::EthtoolError(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_ethtool_xdp_features(&stdout)
}

fn parse_ethtool_xdp_features(output: &str) -> Result<Option<NativeSupport>, XdpCheckError> {
    let mut native = false;
    let mut zero_copy = false;

    for line in output.lines() {
        // Lines look like:  "xdp-native: on" or "xdp-zc: off [fixed]"
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("xdp-zc:") {
            zero_copy = rest.trim_start().starts_with("on");
        } else if let Some(rest) = line.strip_prefix("xdp-native:") {
            native = rest.trim_start().starts_with("on");
        }
    }

    Ok(match (native || zero_copy, zero_copy) {
        (_, true) => Some(NativeSupport::ZeroCopy),
        (true, false) => Some(NativeSupport::Native),
        (false, false) => None,
    })
}

#[allow(unused)]
fn mut_ephemeral_port_range(start: u16, stop: u16) -> std::result::Result<(), std::io::Error> {
    std::fs::write(LOCAL_PORT_RANGE, format!(" {}   {}", start, stop));
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum NicLookupError {
    #[error("interface name {0:?} is invalid (contains nul byte)")]
    InvalidName(String),
    #[error("interface {0:?} does not exist")]
    NotFound(CString),
    #[error("failed to look up interface {1:?}: {0}")]
    LookupFailed(#[source] std::io::Error, CString),
}

pub fn nic_index_from_name(iface: &str) -> Result<NicIndex, NicLookupError> {
    let cname = CString::new(iface).map_err(|_| NicLookupError::InvalidName(iface.to_string()))?;
    match NicIndex::lookup_by_name(&cname) {
        Ok(Some(res)) => Ok(res),
        Ok(None) => Err(NicLookupError::NotFound(cname)),
        Err(e) => Err(NicLookupError::LookupFailed(e, cname)),
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
