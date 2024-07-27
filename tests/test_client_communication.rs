use std::net::Ipv4Addr;

use crate::common::dummy_packet;
use anyhow::Result;
use common::{
    client_config, make_queue_pair, server_config, TestInterface, TestReceiver, TestSender,
};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use quincy::network::interface::Interface;
use quincy::{
    client::QuincyClient,
    config::{ClientConfig, ServerConfig},
    server::QuincyServer,
};
use rstest::rstest;

mod common;

struct ClientA;
type ClientAInterface = TestInterface<ClientA>;
struct ClientB;
type ClientBInterface = TestInterface<ClientB>;
struct Server;
type ServerInterface = TestInterface<Server>;

pub static TEST_QUEUE_CLIENT_A_SEND: Lazy<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_A_RECV: Lazy<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_B_SEND: Lazy<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_B_RECV: Lazy<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_SEND: Lazy<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_RECV: Lazy<(TestSender, TestReceiver)> = make_queue_pair();

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
async fn test_client_communication(client_config: ClientConfig, mut server_config: ServerConfig) {
    server_config.isolate_clients = false;

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

    let recv_packet = TEST_QUEUE_CLIENT_B_SEND
        .1
        .lock()
        .await
        .recv()
        .await
        .unwrap();

    assert_eq!(recv_packet, test_packet);
}
