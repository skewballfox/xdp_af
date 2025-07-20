use aya::{Ebpf, VerifierLogLevel, programs::XdpFlags};

use stacked_errors::{Error, Result};
use xdp::{affinity::CoreId, nic::NicIndex};

use crate::packet_processing::ProcessorState;

pub struct EbpfConfig<'a, S: ProcessorState>
where
    S: Clone,
{
    pub prog_name: &'a str,
    pub entry_point: &'a str,
    ///flags to use on attaching xdp to a network interface
    pub flags: XdpFlags,

    data: S,
}

impl<'a, P: ProcessorState> EbpfConfig<'a, P>
where
    P: Clone,
{
    pub fn new(prog_name: &'a str, entry_point: &'a str, flags: XdpFlags, data: P) -> Self {
        Self {
            prog_name,
            entry_point,
            flags,
            data,
        }
    }
}

pub struct EbpfProgram<'a, S: ProcessorState + std::clone::Clone> {
    pub bpf: Ebpf,
    pub core_ids: Option<Vec<CoreId>>,
    pub config: EbpfConfig<'a, S>,
}

impl<'a, S: ProcessorState + std::clone::Clone> EbpfProgram<'a, S> {
    pub fn load(config: EbpfConfig<'a, S>) -> Result<Self> {
        let mut loader = aya::EbpfLoader::new();
        loader.verifier_log_level(VerifierLogLevel::VERBOSE);
        //loader.set_global("INITIAL_CLIENT_PORT", &config.port, true);

        //let ports = default_ephimeral_ports()?;

        Ok(Self {
            // This will include your eBPF object file as raw bytes at compile-time and load it at
            // runtime. This approach is recommended for most real-world use cases. If you would
            // like to specify the eBPF program at runtime rather than at compile-time, you can
            // reach for `Bpf::load_file` instead.
            bpf: Ebpf::load_file(config.prog_name).map_err(Error::from_err)?,
            core_ids: None,
            config,
            // external_port: xdp::packet::net_types::NetworkU16(external_port_no),
            // qcmp_port: xdp::packet::net_types::NetworkU16(qcmp_port_no),
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
    ) -> Result<Vec<XdpWorker<S>>> {
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
        let mut entries = Vec::with_capacity((num_workers as u32).try_into().unwrap());
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
            println!("socket index {}", i);

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
                data: self.config.data.clone(),
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
            .program_mut(self.config.entry_point)
            .expect(&format!(
                "failed to locate {} program",
                self.config.entry_point
            ))
            .try_into()
            .expect(&format!(
                "{} is not an xdp program",
                self.config.entry_point
            ));
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
            .program_mut(self.config.entry_point)
            .expect(&format!(
                "failed to locate {} program",
                self.config.entry_point
            ))
            .try_into()
            .expect(&format!(
                "{} is not an xdp program",
                self.config.entry_point
            ));
        program.detach(link_id).map_err(Error::from_err)?;
        Ok(())
    }
}

/// An individual XDP worker.
///
/// For now there is always one worker per NIC queue, and doesn't use shared
/// memory allowing them to work on the queue in complete isolation
pub struct XdpWorker<S: ProcessorState + Clone> {
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
    /// State for the worker threads processing packets
    pub data: S,
}

pub struct XdpWorkers<'a, S: ProcessorState>
where
    S: Clone,
{
    pub program: EbpfProgram<'a, S>,
    pub workers: Vec<XdpWorker<S>>,
    pub nic_index: NicIndex,
}
