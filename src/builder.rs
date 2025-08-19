#![allow(unused)]
use std::marker::PhantomData;

use stacked_errors::StackableErr;
use xdp::{
    RingConfigBuilder,
    affinity::CoreId,
    nic::{NetdevCapabilities, NicIndex},
    umem::UmemCfgBuilder,
};

use crate::{
    io_loop::{IOLoopHandler, XdpWorkers, spawn},
    program::EbpfProgram,
    traits::{UserSpaceConfig, XdpLoaderConfig},
};

pub struct XdpBuilder<const TXN: usize, const RXN: usize, C>
where
    C: UserSpaceConfig<TXN, RXN>,
{
    nic_index: NicIndex,
    dev_capabilities: NetdevCapabilities,
    pub cores: Option<Vec<CoreId>>,
    pub config: C,
    pub umem_config: UmemCfgBuilder,
    pub ring_cfg: RingConfigBuilder,
}

impl<const TXN: usize, const RXN: usize, C> XdpBuilder<TXN, RXN, C>
where
    C: UserSpaceConfig<TXN, RXN> + 'static,
{
    pub fn new(nic: NicIndex, config: C) -> stacked_errors::Result<XdpBuilder<TXN, RXN, C>> {
        let dev_capabilities = nic.query_capabilities().stack()?;
        let mut umem_config = UmemCfgBuilder::new(dev_capabilities.tx_metadata);
        // Provide enough headroom so that we can convert an ipv4 header to ipv6
        // header without needing to copy any bytes. note this doesn't take into
        // account if a filter adds or removes bytes from the beginning of the
        // data payload
        umem_config.head_room =
            (xdp::packet::net_types::Ipv6Hdr::LEN - xdp::packet::net_types::Ipv4Hdr::LEN) as u32;

        Ok(Self {
            nic_index: nic,
            dev_capabilities,
            config,
            cores: None,
            umem_config,
            ring_cfg: RingConfigBuilder::default(),
        })
    }

    pub fn build_io_loop(self) -> stacked_errors::Result<IOLoopHandler<C::Loader>> {
        let Self {
            nic_index,
            dev_capabilities,
            config,
            umem_config,
            ring_cfg,
            cores,
        } = self;
        let umem_config = umem_config.build().stack()?;
        let ring_cfg = ring_cfg.build().stack()?;
        let mut program = EbpfProgram::load(config.init_loader_config()).stack()?;

        if let Some(core_ids) = cores {
            program.use_core_ids(core_ids);
        }
        let workers =
            program.create_and_bind_sockets(nic_index, umem_config, &dev_capabilities, ring_cfg)?;
        spawn(XdpWorkers {
            program,
            workers,
            nic: nic_index,
            user_space: config,
        })
    }
}
