use aya::{Ebpf, maps::MapError};
use xdp::{affinity::CoreId, error::SocketError, nic::NicIndex};

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
pub enum ProgramError<E: XdpLoaderConfig> {
    /// This wraps the errors that directly occur when loading the eBPF program
    #[error("eBPF load error: {0}")]
    Ebpf(#[from] aya::EbpfError),
    /// This wraps the errors that can occur when configuring the loader for our
    /// specific program, such as setting globals or checking constraints
    /// required for its operation
    #[error("error configuring loader: {0}")]
    Config(E::Error),
    #[error("failed to retrieve xsk map")]
    XskRetrievalError,
    #[error("failed to convert xsk map {0}")]
    XskConversionError(MapError),
    #[error("failed to convert initialize umem {0}")]
    UmemCreationError(std::io::Error),
    #[error("failed to convert initialize socket {0}")]
    SocketCreationError(SocketError),
    #[error("failed to bind socket {0}")]
    SocketBindError(SocketError),
    #[error("failed to build wakable rings {0}")]
    BuildWakableRingsError(SocketError),
    #[error("failed to set xsk map {0}")]
    XskSetError(MapError),
    #[error("failed to load program {0}")]
    ProgramLoadError(aya::programs::ProgramError),
    #[error("failed to attach program {0}")]
    ProgramAttachError(aya::programs::ProgramError),
    #[error("failed to detach program {0}")]
    ProgramDetachError(aya::programs::ProgramError),
    #[error("program not found: {0}")]
    ProgramNotFound(String),
    #[error("program not an XDP program: {0}")]
    ProgramNotXdp(String),
    #[error("failed to enqueue buffer to fill ring {0}")]
    WakableFillRingError(std::io::Error),
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
    pub fn load(config: C) -> core::result::Result<Self, ProgramError<C>> {
        let mut loader = aya::EbpfLoader::new();
        loader = config
            .configure_loader(loader)
            .map_err(ProgramError::Config)?;

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
    ) -> Result<Vec<XdpWorker>, ProgramError<C>> {
        use std::os::fd::AsRawFd as _;

        let mut xsk_map = aya::maps::XskMap::try_from(
            self.bpf
                .map_mut("XSK_MAP")
                .ok_or(ProgramError::XskRetrievalError)?,
        )
        .map_err(ProgramError::XskConversionError)?;

        let num_workers = if let Some(core_ids) = &self.core_ids {
            u32::try_from(core_ids.len())
                .unwrap()
                .min(device_caps.queue_count)
        } else {
            device_caps.queue_count
        };
        let mut entries = Vec::with_capacity(num_workers.try_into().unwrap());
        for i in 0..num_workers {
            let umem = xdp::Umem::map(umem_cfg).map_err(ProgramError::UmemCreationError)?;
            let mut sb =
                xdp::socket::XdpSocketBuilder::new().map_err(ProgramError::SocketCreationError)?;
            let (rings, mut bind_flags) = sb
                .build_wakable_rings(&umem, ring_cfg)
                .map_err(ProgramError::BuildWakableRingsError)?;

            println!("zc is available {}", device_caps.zero_copy.is_available());
            if device_caps.zero_copy.is_available() {
                bind_flags.force_zerocopy();
            }
            println!("socket index {i}");

            let socket = sb
                .bind(nic, i, bind_flags)
                .map_err(ProgramError::SocketBindError)?;
            xsk_map
                .set(i, socket.as_raw_fd(), 0)
                .map_err(ProgramError::XskSetError)?;

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
    ) -> Result<aya::programs::xdp::XdpLinkId, ProgramError<C>> {
        if self.config.enable_logging()
            && let Err(error) = aya_log::EbpfLogger::init(&mut self.bpf)
        {
            tracing::warn!("failed to initialize eBPF logging {}", error);
        }

        let program: &mut aya::programs::Xdp = self
            .bpf
            .program_mut(self.config.entry_point())
            .unwrap_or_else(|| panic!("failed to locate {} program", self.config.entry_point()))
            .try_into()
            .unwrap_or_else(|_| panic!("{} is not an xdp program", self.config.entry_point()));
        program.load().map_err(ProgramError::ProgramLoadError)?;

        program
            .attach_to_if_index(nic.into(), flags)
            .map_err(ProgramError::ProgramAttachError)
    }

    pub fn detach(
        &mut self,
        link_id: aya::programs::xdp::XdpLinkId,
    ) -> Result<(), ProgramError<C>> {
        let program: &mut aya::programs::Xdp = self
            .bpf
            .program_mut(self.config.entry_point())
            .ok_or(ProgramError::ProgramNotFound(
                self.config.entry_point().to_string(),
            ))?
            .try_into()
            .map_err(|_| ProgramError::ProgramNotXdp(self.config.entry_point().to_string()))?;

        program
            .detach(link_id)
            .map_err(ProgramError::ProgramDetachError)?;
        Ok(())
    }
}
