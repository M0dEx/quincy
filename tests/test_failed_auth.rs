use crate::common::{
    client_config, dummy_packet, make_queue_pair, server_config, TestInterface, TestReceiver,
    TestSender,
};
use anyhow::Result;
use ipnet::IpNet;
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, ServerConfig};
use quincy::network::interface::Interface;
use quincy::server::QuincyServer;
use rstest::rstest;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::time::sleep;
use tracing_test::traced_test;

mod common;

struct Client;
type ClientInterface = TestInterface<Client>;
struct Server;
type ServerInterface = TestInterface<Server>;

pub static TEST_QUEUE_CLIENT_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();

interface_impl!(
    ClientInterface,
    TEST_QUEUE_CLIENT_SEND,
    TEST_QUEUE_CLIENT_RECV
);
interface_impl!(
    ServerInterface,
    TEST_QUEUE_SERVER_SEND,
    TEST_QUEUE_SERVER_RECV
);

#[rstest]
#[tokio::test]
#[traced_test]
async fn test_failed_auth(mut client_config: ClientConfig, server_config: ServerConfig) {
    client_config.authentication.password = "wrong_password".to_string();
    let client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);
    let test_packet_client = dummy_packet(ip_client, ip_server);
    let test_packet_server = dummy_packet(ip_server, ip_client);

    tokio::spawn(async move { server.run::<ServerInterface>().await });
    let client_task = tokio::spawn(async move { client.run::<ClientInterface>().await });

    TEST_QUEUE_CLIENT_RECV
        .0
        .lock()
        .await
        .send(test_packet_client)
        .unwrap();

    TEST_QUEUE_SERVER_RECV
        .0
        .lock()
        .await
        .send(test_packet_server)
        .unwrap();

    assert!(client_task.await.unwrap().is_err());

    // Wait for everything to propagate and be logged
    sleep(Duration::from_secs(1)).await;

    let recv_packet_server = TEST_QUEUE_SERVER_SEND.1.lock().await.try_recv();
    assert!(recv_packet_server.is_err());

    let recv_packet_client = TEST_QUEUE_CLIENT_SEND.1.lock().await.try_recv();
    assert!(recv_packet_client.is_err());

    assert!(logs_contain("Failed to authenticate client"));
}
