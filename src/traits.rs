use aya::EbpfLoader;
use xdp::{Umem, slab::StackSlab};

/// Configures the loader for the XDP program, such as setting globals or
/// checking constraints required for its operation.
pub trait XdpLoaderConfig: Send {
    type Error: core::error::Error + Send + Sync + 'static;
    fn load<'a>(&'a self, loader: aya::EbpfLoader<'a>) -> Result<aya::Ebpf, aya::EbpfError>;
    fn entry_point(&self) -> &str;
    fn configure_loader<'a>(
        &'a self,
        loader: aya::EbpfLoader<'a>,
    ) -> Result<EbpfLoader<'a>, Self::Error>;
}

/// Responsible for propogating the configuration and state unique to the
/// Implemented program. The parameters take self just in case you need to pass
/// some state when instatiating them. If not, just return unit structs which implement
/// the required traits.
pub trait UserSpaceConfig<const TXN: usize, const RXN: usize>: Send + Clone {
    type Loader: XdpLoaderConfig;

    type PacketProcessor: PacketProcessor<TXN, RXN, Self::ProcessorState>;

    /// State shared between workers threads. I'm still working on this part
    type SharedState: Send + Sync + 'static;

    /// The mutable data used during packet processing
    type ProcessorState: Send + Sync + 'static;
    fn init_loader_config(&self) -> Self::Loader;
    fn init_processor_shared_state(&self) -> Self::SharedState;
    fn init_packet_processing_state(&self) -> Self::ProcessorState;
    fn packet_processor(&self) -> Self::PacketProcessor;
}

/// This defines the part of the user space program which grabs, processes and queues packets for transmission.
/// You'll probably want to implement this separately from the rest, it will be substantially larger.
pub trait PacketProcessor<const TXN: usize, const RXN: usize, S: Send + Sync + 'static> {
    //debating whether to have the packet processor return a result, for recording
    // certain types of errors by the parent
    //type ProcessorError;

    fn process_batch(
        rx_slab: &mut StackSlab<RXN>,
        umem: &mut Umem,
        tx_slab: &mut StackSlab<TXN>,
        worker_state: &mut S,
    );
}
