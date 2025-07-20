use core::num::NonZeroU16;
use std::ffi::CString;

use stacked_errors::{Error, Result, StackableErr, bail};
use xdp::nic::NicIndex;

pub fn reserved_port_calculator() -> Vec<(u16, u16)> {
    todo!()
}
// We exploit the fact that Linux by default does not assign ephemeral
// ports in the full range allowed by IANA, but we want to sanity check
// it here, as otherwise something else could have been assigned an
// ephemeral port that we think we can use, which would lead to both
// quilkin and whatever program was assigned that port misbehaving
pub fn default_ephimeral_ports() -> Result<Vec<(u16, u16)>> {
    // We exploit the fact that Linux by default does not assign ephemeral
    // ports in the full range allowed by IANA, but we want to sanity check
    // it here, as otherwise something else could have been assigned an
    // ephemeral port that we think we can use, which would lead to both
    // quilkin and whatever program was assigned that port misbehaving
    let port_range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").stack()?;

    let (start, end) = port_range
        .trim()
        .split_once(char::is_whitespace)
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected 2 u16 integers",
        ))
        .stack()?;

    let start: u16 = start
        .parse()
        .map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse range start '{start}'"),
            )
        })
        .stack()?;
    let end: u16 = end
        .parse()
        .map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse range end '{end}'"),
            )
        })
        .stack()?;

    if end != 60999 {
        bail!(format!(
            "Default ephimeral port range modified: {start} {end}"
        ));
    }

    Ok(vec![(end + 1, u16::MAX)])
}
// this is a very delicate function, if you need to patch it, better implement
// new one...
//
// Trying to solve this problem:
//
// given reserved ranges `ranges` and a number of other ranges `n_cpus`, what is
// the maximum size of the smallest range if you need to allocate all `n_cpus`
// ranges with no intersection with `ranges`. Then it also tries to expand to
// give a few more ports to the calculated ranges
/// Returns a vector of `n_cpus` ranges like [l, r] trying to keep the ranges
/// fair. The ranges are inclusive.
pub fn port_range_best_effort_calculator(
    mut ranges: Vec<(u16, u16)>,
    n_cpus: NonZeroU16,
) -> Vec<(u16, u16)> {
    const U16_MAX: i32 = u16::MAX as _;
    let n_cpus = n_cpus.get() as i32;

    // reserved ports = [0, 1023]
    ranges.push((0, 1023));

    // guarantee ranges are disjoint and ordered
    // cast to i32 to ease add and subtract
    ranges.sort_unstable();
    let mut ranges_good = Vec::with_capacity(ranges.len());
    ranges_good.push((ranges[0].0 as i32, ranges[0].1 as i32));
    for (l, r) in ranges
        .into_iter()
        .map(|(l, r)| (l as i32, r as i32))
        // first entry already inserted
        .skip(1)
    {
        let cur_max = ranges_good.last().map(|x| x.1).unwrap();

        if cur_max >= l - 1 {
            ranges_good.last_mut().unwrap().1 = cur_max.max(r);
        } else {
            ranges_good.push((l, r));
        }
    }
    // make operations homogeneous
    ranges_good.push((U16_MAX + 1, U16_MAX + 1));
    let ranges = ranges_good;

    // check if this size solves the problem
    let try_range_size = |m: i32| {
        let mut target = n_cpus;

        for ((_, cur_r), (next_l, _)) in ranges.iter().zip(ranges.iter().skip(1)) {
            let usable_range = next_l - cur_r - 1;
            let slices = usable_range / m;
            if target <= slices {
                return true;
            }
            target -= slices;
        }

        false
    };

    // try to find the maximum size of the smallest range by binary search.
    // Only works because of the setup above!
    let mut r = (U16_MAX / n_cpus) + 1;
    let mut l = 0;
    while l < r {
        let m = (l + r + 1) / 2;

        if try_range_size(m) {
            // possible with this number
            l = m;
        } else {
            // not possible with this number
            r = m - 1;
        }
    }
    let initial_size = l;

    if initial_size == 0 {
        panic!(); // TODO: create error codes (this number should also be bigger)
    }

    // create the resulting ranges and try to add some length to them
    let mut res = Vec::with_capacity(n_cpus as _);
    let range_iter = ranges.iter().zip(ranges.iter().skip(1));
    'res: for ((_, cur_r), (next_l, _)) in range_iter {
        // SAFETY: ranges_good guarantee > 0
        let available_range = next_l - cur_r - 1;

        let allocations = available_range / initial_size;
        if allocations > 0 {
            // for something stupid like initial_size = 1 this is bad, but if initial_size
            // is 1 there's something VERY wrong with configuration
            let rest = (available_range % initial_size) / allocations;
            let step = initial_size + rest;

            for i in 0..allocations {
                res.push((
                    (cur_r + step * i + 1) as u16,
                    (cur_r + step * (i + 1)) as u16,
                ));

                if res.len() == n_cpus as usize {
                    break 'res;
                }
            }
        }
    }

    res
}

pub fn nic_index_from_name(iface: CString) -> Result<NicIndex> {
    match NicIndex::lookup_by_name(&iface).stack() {
        Ok(Some(res)) => Ok(res),
        Ok(None) => bail!(format!("iface {:?} does not exists", &iface)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;

    #[test]
    fn test_port_allocator() {
        let assert = |ports: &mut [(u16, u16)], min_range_len: u16, cores: u16| {
            // right now the implementation returns them sorted but not necessary...
            ports.sort();

            assert_eq!(ports.len(), cores as usize);
            assert!(ports.iter().all(|port_range| {
                port_range
                    .1
                    .checked_sub(port_range.0)
                    .unwrap()
                    .checked_add(1)
                    .unwrap()
                    >= min_range_len
            }));
            assert!(
                ports
                    .iter()
                    .zip(ports.iter().skip(1))
                    .all(|(range_l, range_r)| range_l.0 <= range_l.1
                        && range_l.1 <= range_r.0
                        && range_r.0 <= range_r.1)
            );
        };

        let cores = 16;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (65000, u16::MAX)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert(ports, 2000, cores);

        let cores = 1;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (65000, u16::MAX)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert_eq!(ports[0], (1024, 51819));
        assert(ports, 51819 - 1024, cores);

        let cores = 2;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (65000, u16::MAX)],
            NonZeroU16::new(2).unwrap(),
        );
        assert(ports, 20_000, cores);

        let cores = 192;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (65000, u16::MAX)],
            NonZeroU16::new(192).unwrap(),
        );
        assert(ports, 100, cores);

        let cores = 30_000;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (65000, u16::MAX)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert(ports, 2, cores);

        let cores = 60_000;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (65000, u16::MAX)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert(ports, 1, cores);

        let cores = 20_000;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820), (60000, u16::MAX)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert(ports, 2, cores);

        let cores = 20_000;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert(ports, 3, cores);

        let cores = 16;
        let ports = &mut port_range_best_effort_calculator(
            vec![(51820, 51820)],
            NonZeroU16::new(cores).unwrap(),
        );
        assert(ports, 2000, cores);
    }
}
