use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicBool},
};

use aya::programs::xdp::XdpLinkId;
use stacked_errors::{Error, Result, bail};
use tracing::span;
use xdp::slab::Slab;

use crate::{
    packet_processing::{ProcessorState, process_packets},
    program::{EbpfProgram, XdpWorker, XdpWorkers},
};

const BATCH_SIZE: usize = 64;
pub fn spawn<S: ProcessorState + Clone + Send + 'static>(
    workers: XdpWorkers<S>,
    inner_loop: impl Fn(XdpWorker<S>, Option<Ipv4Addr>, Option<Ipv6Addr>, Arc<AtomicBool>) -> Result<()>
    + Clone
    + Send
    + 'static,
) -> Result<IOLoopHandler<S>> {
    let (ipv4, ipv6) = workers.nic_index.addresses().map_err(Error::from_err)?;
    if ipv4.is_none() && ipv6.is_none() {
        bail!(format!(
            "Needs at least one of defined local address for network interface"
        ));
    };

    let barrier = Arc::new(std::sync::Barrier::new(workers.workers.len()));
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let _span = span!(tracing::Level::INFO, "io loop").entered();
    let mut handles = Vec::with_capacity(workers.workers.len());
    for (i, mut worker) in workers.workers.into_iter().enumerate() {
        let core_id = if let Some(ref core_ids) = workers.program.core_ids {
            Some(core_ids[i].clone())
        } else {
            None
        };

        let barrier = barrier.clone();
        let shutdown = shutdown.clone();
        let inner_loop = inner_loop.clone();

        let jh = std::thread::Builder::new()
            .name(format!("xdp-io-{i}"))
            .spawn(move || {
                tracing::info!("spawning worker {}", i);
                if let Some(core_id) = core_id {
                    core_id.set_affinity().unwrap();
                }
                unsafe {
                    if let Err(error) = worker.fill.enqueue(&mut worker.umem, BATCH_SIZE, true) {
                        bail!(format!(
                            "failed to kick fill ring during initial spinup. Error: {error}"
                        ));
                    }
                };
                barrier.wait();
                tracing::info!("passing to inner loop");
                io_loop(worker, ipv4, ipv6, shutdown)
            })
            .map_err(Error::from_err)?;
        handles.push(jh);
    }

    // Now that all the io loops are running, attach the eBPF program to route
    // packets to the bound sockets
    let mut ebpf_program = workers.program;

    // We use the default flags here, which means that the program will be attached
    // in driver mode if the NIC + driver is capable of it, otherwise it will
    // fallback to SKB mode. This allows maximum compatibility, and we already
    // provide flags to force zerocopy, which relies on driver mode, so the user
    // can use that if they don't want the fallback behavior
    let xdp_link = ebpf_program.attach(workers.nic_index, ebpf_program.config.flags)?;

    Ok(IOLoopHandler {
        threads: handles,
        ebpf_program,
        xdp_link,
        shutdown,
    })
}

pub fn io_loop<PacketProcessor, S: ProcessorState + Clone, F>(
    worker: XdpWorker<S>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let XdpWorker {
        mut umem,
        socket,
        mut fill,
        mut rx,
        mut tx,
        mut completion,
        mut data,
    } = worker;

    const POLL_TIMEOUT: xdp::socket::PollTimeout =
        xdp::socket::PollTimeout::new(Some(std::time::Duration::from_millis(500)));

    let mut rx_slab = xdp::slab::StackSlab::<BATCH_SIZE>::new();
    let mut tx_slab = xdp::slab::StackSlab::<{ BATCH_SIZE << 2 }>::new();
    let mut pending_sends = 0;

    //let mut state = WorkerState::new(ipv4, ipv6, data);
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
            tracing::info!("recieved {}", received);
            process_packets::<BATCH_SIZE, { BATCH_SIZE << 2 }, PacketProcessor>(
                &mut rx_slab,
                &mut umem,
                &mut tx_slab,
                &mut data,
            );
            let prev_len = tx_slab.len();
            let enqueued_sends = match tx.send(&mut tx_slab, true) {
                Ok(es) => es,
                Err(error) => {
                    // These are all temporary errors that can occur during normal
                    // operation
                    // if !matches!(
                    //     error.raw_os_error(),
                    //     Some(libc::EBUSY | libc::ENOBUFS | libc::EAGAIN | libc::ENETDOWN)
                    // ) {
                    // This is shoehorning an error that isn't attributable to a particular packet
                    tracing::info!("TODO: handle enqueued sends err: {error}");
                    //}

                    prev_len - tx_slab.len()
                }
            };

            pending_sends += enqueued_sends;
            pending_sends -= completion.dequeue(&mut umem, pending_sends);
        }
    }
    Ok(())
}

pub struct IOLoopHandler<'a, S: ProcessorState + Clone> {
    /// threads running the io loop. Length is either num_queues for an
    /// interface or min(num_cores, num_queues)
    threads: Vec<std::thread::JoinHandle<Result<()>>>,
    /// The loaded ebpf program
    ebpf_program: EbpfProgram<'a, S>,
    /// id for link between xdp program and the network interface. Used to
    /// handle detachment during shutdown.
    xdp_link: XdpLinkId,
    ///shutdown signal
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl<'a, S: ProcessorState + Clone> IOLoopHandler<'a, S> {
    /// Detaches the eBPF program from the attacked NIC and cancels all I/O
    /// threads, waiting for them to exit
    pub fn shutdown(mut self, wait: bool) -> Result<()> {
        if let Err(error) = self.ebpf_program.detach(self.xdp_link) {
            bail!(format!("failed to detach eBPF program. Error: {error}"))
            //tracing::error!(%error, "failed to detach eBPF program");
        }
        tracing::info!("starting io loop shutdown");
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);

        if !wait {
            return Ok(());
        }

        for jh in self.threads {
            if let Err(error) = jh.join() {
                if let Some(error) = error.downcast_ref::<&'static str>() {
                    bail!(format!("XDP I/O thread enountered error {error}"))
                } else if let Some(error) = error.downcast_ref::<String>() {
                    bail!(format!("XDP I/O thread enountered error {error}"))
                } else {
                    bail!(format!("XDP I/O thread enountered error {:#?}", error))
                };
            }
        }
        Ok(())
    }
}
