// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::{committee_with_base_port, keys, listener};
use crypto::SignatureService;
use std::fs;
use tokio::sync::mpsc::channel;
use tokio::time::timeout;

#[tokio::test]
async fn missing_batch_sync_goes_to_local_worker() {
    let mut keys = keys();
    let (author, secret) = keys.pop().unwrap();
    let (name, _) = keys.pop().unwrap();
    assert_ne!(name, author);

    let committee = committee_with_base_port(31_000);
    let digest = Digest::default();
    let header = Header::new(
        author,
        1,
        [(digest.clone(), 0)].iter().cloned().collect(),
        Default::default(),
        &mut SignatureService::new(secret),
    )
    .await;

    let path = ".db_test_header_waiter_sync_route";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();
    let (tx_sync, rx_sync) = channel(1);
    let (tx_core, _rx_core) = channel(1);
    HeaderWaiter::spawn(
        name,
        committee.clone(),
        store,
        Arc::new(AtomicU64::new(0)),
        50,
        10_000,
        3,
        rx_sync,
        tx_core,
    );

    let local_address = committee.worker(&name, &0).unwrap().primary_to_worker;
    let author_address = committee.worker(&author, &0).unwrap().primary_to_worker;
    let local_listener = listener(local_address);
    let mut author_listener = listener(author_address);
    tx_sync
        .send(WaiterMessage::SyncBatches(
            [(digest.clone(), 0)].iter().cloned().collect(),
            header,
        ))
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(5), local_listener)
        .await
        .expect("local worker did not receive the sync command")
        .unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryWorkerMessage::Synchronize(digests, target) => {
            assert_eq!(digests, vec![digest]);
            assert_eq!(target, author);
        }
        other => panic!("Unexpected message: {:?}", other),
    }
    assert!(timeout(Duration::from_millis(200), &mut author_listener)
        .await
        .is_err());
    author_listener.abort();
}
