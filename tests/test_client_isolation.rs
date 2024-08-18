use crate::common::dummy_packet;
use anyhow::Result;
use common::{
    client_config, make_queue_pair, server_config, TestInterface, TestReceiver, TestSender,
};
use ipnet::IpNet;
use quincy::network::interface::Interface;
use quincy::{
    client::QuincyClient,
    config::{ClientConfig, ServerConfig},
    server::QuincyServer,
};
use rstest::rstest;
use std::sync::LazyLock;
use std::{net::Ipv4Addr, time::Duration};
use tokio::time::timeout;

mod common;

struct ClientA;
type ClientAInterface = TestInterface<ClientA>;
struct ClientB;
type ClientBInterface = TestInterface<ClientB>;
struct Server;
type ServerInterface = TestInterface<Server>;

pub static TEST_QUEUE_CLIENT_A_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_A_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_B_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_B_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();

interface_impl!(
    ClientAInterface,
    TEST_QUEUE_CLIENT_A_SEND,
    TEST_QUEUE_CLIENT_A_RECV
);
interface_impl!(
    ClientBInterface,
    TEST_QUEUE_CLIENT_B_SEND,
    TEST_QUEUE_CLIENT_B_RECV
);
interface_impl!(
    ServerInterface,
    TEST_QUEUE_SERVER_SEND,
    TEST_QUEUE_SERVER_RECV
);

#[rstest]
#[tokio::test]
async fn test_client_isolation(client_config: ClientConfig, server_config: ServerConfig) {
    let client_a = QuincyClient::new(client_config.clone());
    let client_b = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_client_a = Ipv4Addr::new(10, 0, 0, 2);
    let ip_client_b = Ipv4Addr::new(10, 0, 0, 3);

    tokio::spawn(async move { server.run::<ServerInterface>().await.unwrap() });
    tokio::spawn(async move { client_a.run::<ClientAInterface>().await.unwrap() });
    tokio::spawn(async move { client_b.run::<ClientBInterface>().await.unwrap() });

    // Test client A -> client B
    let test_packet = dummy_packet(ip_client_a, ip_client_b);

    TEST_QUEUE_CLIENT_A_RECV
        .0
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let mut recv_queue = TEST_QUEUE_CLIENT_B_SEND.1.lock().await;

    let recv_result = timeout(Duration::from_secs(1), recv_queue.recv()).await;
    assert!(recv_result.is_err());
}
