use aya::Ebpf;
use stacked_errors::{Error, Result};
use xdp::{affinity::CoreId, nic::NicIndex};

use crate::traits::XdpLoaderConfig;

#[derive(thiserror::Error, Debug)]
pub enum BindError {
    #[error("'XSK' map not found in eBPF program")]
    MissingXskMap,
    #[error("failed to insert socket: {0}")]
    Map(#[from] aya::maps::MapError),
    #[error("failed to bind socket: {0}")]
    Socket(#[from] xdp::socket::SocketError),
    #[error("XDP error: {0}")]
    Xdp(#[from] xdp::error::Error),
    #[error("mmap error: {0}")]
    Mmap(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError<E: core::error::Error + Send + Sync + 'static> {
    /// This wraps the errors that directly occur when loading the eBPF program
    #[error("eBPF load error: {0}")]
    Ebpf(#[from] aya::EbpfError),
    /// This wraps the errors that can occur when configuring the loader for our
    /// specific program, such as setting globals or checking constraints
    /// required for its operation
    #[error("error configuring loader: {0}")]
    Config(E),
}

/// An individual XDP worker.
///
/// For now there is always one worker per NIC queue, and doesn't use shared
/// memory allowing them to work on the queue in complete isolation
pub struct XdpWorker {
    /// The actual socket bound to the queue, used for polling operations
    pub socket: xdp::socket::XdpSocket,
    /// The memory map shared with the kernel where buffers used to receive
    /// and send packets are stored
    pub umem: xdp::Umem,
    /// The ring used to indicate to the kernel we wish to receive packets
    pub fill: xdp::WakableFillRing,
    /// The ring the kernel pushes received packets to
    pub rx: xdp::RxRing,
    /// The ring we push packets we wish to send
    pub tx: xdp::WakableTxRing,
    /// The ring the kernel pushes packets that have finished sending
    pub completion: xdp::CompletionRing,
}

pub struct EbpfProgram<C: XdpLoaderConfig> {
    pub bpf: Ebpf,
    pub core_ids: Option<Vec<CoreId>>,
    pub config: C,
}

impl<C: XdpLoaderConfig> EbpfProgram<C> {
    pub fn load(config: C) -> core::result::Result<Self, LoadError<C::Error>> {
        let mut loader = aya::EbpfLoader::new();
        loader = config.configure_loader(loader).map_err(LoadError::Config)?;

        Ok(Self {
            bpf: config.load(loader)?,
            core_ids: None,
            config,
        })
    }

    pub fn use_core_ids(&mut self, core_ids: Vec<CoreId>) {
        self.core_ids = Some(core_ids);
    }

    /// Creates and binds sockets
    pub fn create_and_bind_sockets(
        &mut self,
        nic: NicIndex,
        umem_cfg: xdp::umem::UmemCfg,
        device_caps: &xdp::nic::NetdevCapabilities,
        ring_cfg: xdp::RingConfig,
    ) -> Result<Vec<XdpWorker>> {
        use std::os::fd::AsRawFd as _;

        let mut xsk_map = aya::maps::XskMap::try_from(
            self.bpf
                .map_mut("XSK_MAP")
                .expect("failed to retrieve XSK map"),
        )
        .map_err(Error::from_err)?;

        let num_workers = if self.core_ids.is_some() {
            u32::try_from(self.core_ids.as_ref().unwrap().len())
                .unwrap()
                .min(device_caps.queue_count)
        } else {
            device_caps.queue_count
        };
        let mut entries = Vec::with_capacity(num_workers.try_into().unwrap());
        for i in 0..num_workers {
            let umem = xdp::Umem::map(umem_cfg).map_err(Error::from_err)?;
            let mut sb = xdp::socket::XdpSocketBuilder::new().map_err(Error::from_err)?;
            let (rings, mut bind_flags) = sb
                .build_wakable_rings(&umem, ring_cfg)
                .map_err(Error::from_err)?;

            println!("zc is available {}", device_caps.zero_copy.is_available());
            if device_caps.zero_copy.is_available() {
                bind_flags.force_zerocopy();
            }
            println!("socket index {i}");

            let socket = sb.bind(nic, i, bind_flags).map_err(Error::from_err)?;
            xsk_map
                .set(i, socket.as_raw_fd(), 0)
                .map_err(Error::from_err)?;

            entries.push(XdpWorker {
                socket,
                umem,
                fill: rings.fill_ring,
                rx: rings.rx_ring.unwrap(),
                tx: rings.tx_ring.unwrap(),
                completion: rings.completion_ring,
            });
        }

        Ok(entries)
    }

    pub fn attach(
        &mut self,
        nic: NicIndex,
        flags: aya::programs::XdpFlags,
    ) -> Result<aya::programs::xdp::XdpLinkId> {
        if let Err(_error) = aya_log::EbpfLogger::init(&mut self.bpf) {
            // Would be good to enable this if we do end up adding log messages
            // to the eBPF program, right now we don't so this will
            // error as the ring buffer used to transfer log
            // messages is not created if there are none
            // tracing::warn!(%error, "failed to initialize eBPF logging");
        }

        // We use this entrypoint for now, but in the future we could also use
        // a round robin mode when the xdp lib supports shared Umem
        let program: &mut aya::programs::Xdp = self
            .bpf
            .program_mut(self.config.entry_point())
            .unwrap_or_else(|| panic!("failed to locate {} program", self.config.entry_point()))
            .try_into()
            .unwrap_or_else(|_| panic!("{} is not an xdp program", self.config.entry_point()));
        program
            .load()
            .map_err(Error::from_err)
            .map_err(Error::from_err)?;

        program
            .attach_to_if_index(nic.into(), flags)
            .map_err(Error::from_err)
    }

    pub fn detach(&mut self, link_id: aya::programs::xdp::XdpLinkId) -> Result<()> {
        let program: &mut aya::programs::Xdp = self
            .bpf
            .program_mut(self.config.entry_point())
            .unwrap_or_else(|| panic!("failed to locate {} program", self.config.entry_point()))
            .try_into()
            .unwrap_or_else(|_| panic!("{} is not an xdp program", self.config.entry_point()));
        program.detach(link_id).map_err(Error::from_err)?;
        Ok(())
    }
}
