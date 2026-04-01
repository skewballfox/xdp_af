#![allow(unused)]
use std::sync::{Arc, atomic::AtomicBool};

use aya::programs::{XdpFlags, xdp::XdpLinkId};
use tracing::span;
use xdp::{
    Umem, libc,
    nic::NicIndex,
    slab::{Slab, StackSlab},
};

use crate::{
    program::{EbpfProgram, ProgramError, XdpWorker},
    traits::{PacketProcessor, UserSpaceConfig, XdpLoaderConfig},
};
#[derive(thiserror::Error, Debug)]
pub enum SpawnError<L: XdpLoaderConfig> {
    #[error("failed to query local addresses: {0}")]
    AddressQueryError(std::io::Error),
    #[error("no local address found")]
    NoLocalAddressError,
    #[error("error during program configuration: {0}")]
    ProgramError(ProgramError<L>),
    #[error("failed to set thread affinity {0}")]
    ThreadAffinityError(std::io::Error),
    #[error("failed to spawn thread {0}")]
    ThreadSpawnError(std::io::Error),
    #[error("XDP I/O thread encountered error during shutdown: {0}")]
    ShutdownError(String),
}

const BATCH_SIZE: usize = 64;

pub fn spawn<const TXN: usize, const RXN: usize, C>(
    workers: XdpWorkers<TXN, RXN, C>,
    flags: &[XdpFlags],
) -> Result<IOLoopHandler<C::Loader>, SpawnError<C::Loader>>
where
    C: UserSpaceConfig + 'static,
{
    let (ipv4, ipv6) = workers
        .nic
        .addresses()
        .map_err(SpawnError::AddressQueryError)?;
    if ipv4.is_none() && ipv6.is_none() {
        return Err(SpawnError::NoLocalAddressError);
    }

    let barrier = Arc::new(std::sync::Barrier::new(workers.workers.len()));
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let _span = span!(tracing::Level::TRACE, "io loop").entered();
    let mut handles = Vec::with_capacity(workers.workers.len());

    for (i, mut worker) in workers.workers.into_iter().enumerate() {
        let core_id = workers
            .program
            .core_ids
            .as_ref()
            .map(|core_ids| core_ids[i]);

        let barrier = barrier.clone();
        let shutdown = shutdown.clone();
        let config = workers.user_space.clone();
        let jh = std::thread::Builder::new()
            .name(format!("xdp-io-{i}"))
            .spawn(move || {
                tracing::trace!("spawning worker {}", i);
                if let Some(core_id) = core_id {
                    core_id
                        .set_affinity()
                        .map_err(SpawnError::ThreadAffinityError)?;
                }
                unsafe {
                    if let Err(error) = worker.fill.enqueue(&mut worker.umem, BATCH_SIZE, true) {
                        return Err(SpawnError::ProgramError(
                            ProgramError::WakableFillRingError(error),
                        ));
                    }
                };
                barrier.wait();
                tracing::trace!("passing to inner loop");
                io_loop::<TXN, RXN, _>(worker, config, shutdown);
                Ok(())
            })
            .map_err(SpawnError::ThreadSpawnError)?;
        handles.push(jh);
    }

    let mut ebpf_program = workers.program;

    let xdp_link = 'attach: {
        let mut last_err = None;
        for &flag in flags {
            match ebpf_program.attach(workers.nic, flag) {
                Ok(l) => break 'attach l,
                Err(e) => last_err = Some(e),
            }
        }
        return Err(SpawnError::ProgramError(last_err.unwrap()));
    };

    Ok(IOLoopHandler {
        threads: handles,
        ebpf_program,
        xdp_link,
        shutdown,
    })
}

pub fn io_loop<const TXN: usize, const RXN: usize, C>(
    worker: XdpWorker,
    config: C,
    shutdown: Arc<AtomicBool>,
) where
    C: UserSpaceConfig,
{
    let XdpWorker {
        mut umem,
        socket,
        mut fill,
        mut rx,
        mut tx,
        mut completion,
    } = worker;

    const POLL_TIMEOUT: xdp::socket::PollTimeout =
        xdp::socket::PollTimeout::new(Some(std::time::Duration::from_millis(500)));

    let mut rx_slab = xdp::slab::StackSlab::<RXN>::new();
    let mut tx_slab = xdp::slab::StackSlab::<TXN>::new();
    let mut pending_sends = 0;

    let packet_processor =
        &mut C::PacketProcessor::new_processor::<TXN, RXN>(config.init_processor_shared_state());

    tracing::info!("starting io loop");
    unsafe {
        while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            match socket.poll_read(POLL_TIMEOUT) {
                Ok(true) => {
                    tracing::info!("io_loop poll read")
                }
                Ok(false) => {
                    //tracing::debug!("io_loop poll timeout");
                    continue;
                }
                Err(e) => {
                    tracing::error!("io_loop poll error message {e}");
                    continue;
                }
            }
            tracing::info!("in the io_loop");
            let received = rx.recv(&umem, &mut rx_slab);
            // Ensure the fill ring doesn't get starved, which could drop packets
            if let Err(error) = fill.enqueue(&mut umem, BATCH_SIZE * 2 - received, true) {
                //metrics can go here
                tracing::info!("todo handle received error check -- got error {}", error)
            }
            tracing::info!("received {}", received);

            packet_processor.process_batch::<TXN, RXN>(&mut rx_slab, &mut umem, &mut tx_slab);
            let prev_len = tx_slab.len();
            let enqueued_sends = match tx.send(&mut tx_slab, true) {
                Ok(es) => es,
                Err(error) => {
                    // TODO: add trait for doing per-packet metrics to make errors optionally trackable

                    prev_len - tx_slab.len()
                }
            };

            pending_sends += enqueued_sends;
            pending_sends -= completion.dequeue(&mut umem, pending_sends);
        }
    }
}

pub struct IOLoopHandler<L: XdpLoaderConfig> {
    /// threads running the io loop. Length is either num_queues for an
    /// interface or min(num_cores, num_queues)
    threads: Vec<std::thread::JoinHandle<Result<(), SpawnError<L>>>>,
    /// The loaded ebpf program
    ebpf_program: EbpfProgram<L>,
    /// id for link between xdp program and the network interface. Used to
    /// handle detachment during shutdown.
    xdp_link: XdpLinkId,
    ///shutdown signal
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

pub struct XdpWorkers<const TXN: usize, const RXN: usize, C: UserSpaceConfig> {
    pub program: EbpfProgram<C::Loader>,
    pub workers: Vec<XdpWorker>,
    pub nic: NicIndex,
    pub user_space: C,
}

impl<L: XdpLoaderConfig> IOLoopHandler<L> {
    /// Detaches the eBPF program from the attacked NIC and cancels all I/O
    /// threads, waiting for them to exit
    pub fn shutdown(mut self, wait: bool) -> Result<(), SpawnError<L>> {
        self.ebpf_program
            .detach(self.xdp_link)
            .map_err(SpawnError::ProgramError)?;
        tracing::trace!("starting io loop shutdown");
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);

        if !wait {
            return Ok(());
        }

        for jh in self.threads {
            if let Err(error) = jh.join() {
                Err(SpawnError::ShutdownError(format!("{:#?}", error)))?;
            }
        }
        Ok(())
    }
}
