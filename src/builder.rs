use stacked_errors::StackableErr;
use xdp::{
    RingConfigBuilder,
    affinity::CoreId,
    nic::{NetdevCapabilities, NicIndex},
    umem::UmemCfgBuilder,
};

use crate::{
    io_loop::{IOLoopHandler, io_loop, spawn},
    packet_processing::ProcessorState,
    program::{EbpfConfig, EbpfProgram, XdpWorkers},
};

/// Since there is a lot of configuration that goes into setting up the bridge,
/// and we want some sort of tweakable default, a builder for everything
/// required to load the ebpf module and set up the main loop. If you need
/// something to be tweakable, feel free to add a method, or just mutate
/// it directly
pub struct XdpBuilder<'a, S: ProcessorState + Clone> {
    nic_index: NicIndex,
    dev_capabilities: NetdevCapabilities,
    pub cores: Option<Vec<CoreId>>,
    pub config: EbpfConfig<'a, S>,
    pub umem_config: UmemCfgBuilder,
    pub ring_cfg: RingConfigBuilder,
}

impl<'a, S: ProcessorState + Clone> XdpBuilder<'a, S> {
    // The bare minimum in terms of required configuration is a nic interface and a
    // wg private key, everything else can have a settable default
    pub fn new(
        nic: NicIndex,
        config: EbpfConfig<'a, S>,
    ) -> stacked_errors::Result<XdpBuilder<'a, S>> {
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

    pub fn set_ebpf_program(mut self, prog: &'a str) -> Self {
        self.config.prog_name = prog;
        self
    }

    pub fn set_entry_point(mut self, entry: &'a str) -> Self {
        self.config.entry_point = entry;
        self
    }

    pub fn build_io_loop(self) -> stacked_errors::Result<IOLoopHandler<'a, S>> {
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
        let mut program = EbpfProgram::load(config).stack()?;

        if let Some(core_ids) = cores {
            program.use_core_ids(core_ids);
        }
        let workers =
            program.create_and_bind_sockets(nic_index, umem_config, &dev_capabilities, ring_cfg)?;
        spawn(XdpWorkers {
            program,
            workers,
            nic_index,
        })
    }
}
