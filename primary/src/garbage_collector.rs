// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Certificate;
use crate::primary::PrimaryWorkerMessage;
use bytes::Bytes;
use config::Committee;
use crypto::PublicKey;
use network::SimpleSender;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;

/// Receives the highest round reached by consensus and update it for all tasks.
pub struct GarbageCollector {
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The public key of this primary.
    name: PublicKey,
    /// The depth of the garbage collector.
    gc_depth: u64,
    /// Receives the ordered certificates from consensus.
    rx_consensus: Receiver<Certificate>,
    /// The network addresses of our workers.
    addresses: Vec<SocketAddr>,
    /// A network sender to notify our workers of cleanup events.
    network: SimpleSender,
}

impl GarbageCollector {
    pub fn spawn(
        name: &PublicKey,
        committee: &Committee,
        consensus_round: Arc<AtomicU64>,
        gc_depth: u64,
        rx_consensus: Receiver<Certificate>,
    ) {
        let name = *name;
        let addresses = committee
            .our_workers(&name)
            .expect("Our public key or worker id is not in the committee")
            .iter()
            .map(|x| x.primary_to_worker)
            .collect();

        tokio::spawn(async move {
            Self {
                consensus_round,
                name,
                gc_depth,
                rx_consensus,
                addresses,
                network: SimpleSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        let mut last_committed_round = 0;
        while let Some(certificate) = self.rx_consensus.recv().await {
            // TODO [issue #9]: Re-include batch digests that have not been sequenced into our next block.

            let round = certificate.round();
            if round > last_committed_round {
                last_committed_round = round;

                // Trigger cleanup on the primary.
                self.consensus_round.store(round, Ordering::Relaxed);
                if lifecycle_trace::enabled() {
                    lifecycle_trace::write(
                        lifecycle_trace::Event::new("primary", "CleanupAdvanced")
                            .str("source", "primary_gc")
                            .str("node", format!("{:?}", self.name))
                            .u64("committed_round", round)
                            .u64("cleanup_round", round.saturating_sub(self.gc_depth))
                            .u64("gc_depth", self.gc_depth),
                    );
                }

                // Trigger cleanup on the workers..
                let bytes = bincode::serialize(&PrimaryWorkerMessage::Cleanup(round))
                    .expect("Failed to serialize our own message");
                self.network
                    .broadcast(self.addresses.clone(), Bytes::from(bytes))
                    .await;
            }
        }
    }
}
