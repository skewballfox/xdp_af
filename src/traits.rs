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

    fn enable_logging(&self) -> bool {
        false
    }
}

/// Responsible for propogating the configuration and state unique to the
/// Implemented program. The parameters take self just in case you need to pass
/// some state when instatiating them. If not, just return unit structs which implement
/// the required traits.
pub trait UserSpaceConfig: Send + Clone {
    type Loader: XdpLoaderConfig;
    type PacketProcessor: PacketProcessor;

    /// The mutable data used during packet processing
    fn init_processor_shared_state(
        &self,
    ) -> <Self::PacketProcessor as PacketProcessor>::SharedState;
    fn init_loader_config(&self) -> Self::Loader;
}

/// This defines the part of the user space program which grabs, processes and queues packets for transmission.
/// You'll probably want to implement this separately from the rest, it will be substantially larger.
pub trait PacketProcessor {
    type SharedState: Send + Sync + 'static;

    /// Create a new processor. This has the TXN and RXN generics if implementor needs it, the same
    /// values for TXN and RXN will be used when call process_batch.
    /// The shared state comes from the UserSpaceConfig implementation
    fn new_processor<const TXN: usize, const RXN: usize>(shared_state: Self::SharedState) -> Self;
    fn process_batch<const TXN: usize, const RXN: usize>(
        &mut self,
        rx_slab: &mut StackSlab<RXN>,
        umem: &mut Umem,
        tx_slab: &mut StackSlab<TXN>,
    );
}
