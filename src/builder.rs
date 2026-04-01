#![allow(unused)]
use std::marker::PhantomData;

use aya::programs::{XdpFlags, xdp::XdpLinkId};
use thiserror::Error;
use xdp::{
    RingConfigBuilder,
    affinity::CoreId,
    nic::{NetdevCapabilities, NicIndex},
    umem::UmemCfgBuilder,
};

use crate::{
    io_loop::{IOLoopHandler, SpawnError, XdpWorkers, spawn},
    program::{EbpfProgram, ProgramError},
    traits::{UserSpaceConfig, XdpLoaderConfig},
};

#[derive(Error, Debug)]
pub enum XdpBuilderError<E: UserSpaceConfig> {
    #[error("error while querying nic capablities {0}")]
    NicQueryError(std::io::Error),
    #[error("error while setting cores for program {0}")]
    CoreSetError(std::io::Error),
    #[error("error while building umemcfg {0}")]
    UmemCfgError(xdp::error::Error),
    #[error("error while building RingCfg {0}")]
    RingConfigError(xdp::error::Error),
    #[error("error while initializing program {0}")]
    LoadError(ProgramError<E::Loader>),
    #[error("error encountered during program execution {0}")]
    SpawnError(SpawnError<E::Loader>),
}

pub struct XdpBuilder<C>
where
    C: UserSpaceConfig,
{
    nic_index: NicIndex,
    dev_capabilities: NetdevCapabilities,
    /// The cores to be used for the userspace workers
    pub cores: Option<Vec<CoreId>>,
    /// The configuration for your specific program
    pub config: C,
    pub flags: Vec<XdpFlags>,
    pub umem_config: UmemCfgBuilder,
    pub ring_cfg: RingConfigBuilder,
}

type LError<C> = <<C as UserSpaceConfig>::Loader as XdpLoaderConfig>::Error;
impl<C> XdpBuilder<C>
where
    C: UserSpaceConfig + 'static,
{
    pub fn new(nic: NicIndex, config: C) -> Result<XdpBuilder<C>, XdpBuilderError<C>> {
        let dev_capabilities = nic
            .query_capabilities()
            .map_err(XdpBuilderError::NicQueryError)?;
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
            /// we will default to the defualt flag, which should
            /// attach in driver mode if the NIC + driver is capable of it,
            /// otherwise it will fallback to SKB mode.
            flags: vec![XdpFlags::default()],
        })
    }

    /// Set the cores to be used by the io loop
    pub fn with_cores(mut self, cores: Vec<CoreId>) -> Self {
        self.cores = Some(cores);
        self
    }

    /// Set one core per queue on the device
    pub fn core_per_queue(mut self) -> Result<Self, XdpBuilderError<C>> {
        let cores = xdp::affinity::CoreIds::new().map_err(XdpBuilderError::CoreSetError)?;
        let workers = cores
            .into_iter()
            .take(self.dev_capabilities.queue_count as usize)
            .collect::<Vec<CoreId>>();
        self.cores = Some(workers);
        Ok(self)
    }

    /// Sets one core per queue on the device and returns both the builder with cores assigned as well as the leftover coreids
    pub fn core_per_queue_and_available(
        mut self,
    ) -> Result<(Self, Vec<CoreId>), XdpBuilderError<C>> {
        let cores = xdp::affinity::CoreIds::new()
            .map_err(XdpBuilderError::CoreSetError)?
            .collect::<Vec<CoreId>>();
        let (workers, cores) = cores.split_at(self.dev_capabilities.queue_count as usize);
        let workers = workers.to_vec();

        self.cores = Some(workers);
        Ok((self, cores.to_vec()))
    }

    /// Set the flags passed when attaching the program
    pub fn set_flag(mut self, flags: XdpFlags) -> Self {
        self.flags = vec![flags];
        self
    }

    /// Set the flags to be used or attempted when attaching the eBPF program
    pub fn set_flags(mut self, flags: Vec<XdpFlags>) -> Self {
        self.flags = flags;
        self
    }

    /// Try HW mode, then try Driver mode, then try SKB mode
    pub fn try_all_flags(mut self) -> Self {
        self.flags = vec![XdpFlags::HW_MODE, XdpFlags::DRV_MODE, XdpFlags::SKB_MODE];
        self
    }

    pub fn build_io_loop<const TXN: usize, const RXN: usize>(
        mut self,
    ) -> Result<IOLoopHandler<C::Loader>, XdpBuilderError<C>> {
        if self.cores.is_none() {
            self = self.core_per_queue()?;
        }

        let Self {
            nic_index,
            dev_capabilities,
            config,
            umem_config,
            ring_cfg,
            cores,
            flags,
        } = self;

        // Need to expose umem and ring config builders to allow customization
        let umem_config = umem_config.build().map_err(XdpBuilderError::UmemCfgError)?;
        let ring_cfg = ring_cfg.build().map_err(XdpBuilderError::RingConfigError)?;
        let mut program =
            EbpfProgram::load(config.init_loader_config()).map_err(XdpBuilderError::LoadError)?;

        if let Some(core_ids) = cores {
            program.use_core_ids(core_ids);
        }
        let workers = program
            .create_and_bind_sockets(nic_index, umem_config, &dev_capabilities, ring_cfg)
            .map_err(XdpBuilderError::LoadError)?;
        spawn::<TXN, RXN, _>(
            XdpWorkers {
                program,
                workers,
                nic: nic_index,
                user_space: config,
            },
            &flags,
        )
        .map_err(XdpBuilderError::SpawnError)
    }
}
