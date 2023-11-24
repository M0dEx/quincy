use crate::common::{
    client_config, dummy_packet, server_config, TestInterface, TestReceiver, TestSender,
};
use anyhow::Result;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, ServerConfig};
use quincy::interface::Interface;
use quincy::server::QuincyServer;
use rstest::rstest;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

mod common;

pub static TEST_QUEUE_CLIENT_SEND: Lazy<(TestSender, TestReceiver)> = Lazy::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
});

pub static TEST_QUEUE_CLIENT_RECV: Lazy<(TestSender, TestReceiver)> = Lazy::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
});

pub static TEST_QUEUE_SERVER_SEND: Lazy<(TestSender, TestReceiver)> = Lazy::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
});

pub static TEST_QUEUE_SERVER_RECV: Lazy<(TestSender, TestReceiver)> = Lazy::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
});

struct Client;
struct Server;
impl Interface for TestInterface<Client> {
    fn create(_interface_address: IpNet, _mtu: i32) -> Result<Self> {
        Ok(Self::new(
            TEST_QUEUE_CLIENT_SEND.0.clone(),
            TEST_QUEUE_CLIENT_RECV.1.clone(),
        ))
    }
}

impl Interface for TestInterface<Server> {
    fn create(_interface_address: IpNet, _mtu: i32) -> Result<Self> {
        Ok(Self::new(
            TEST_QUEUE_SERVER_SEND.0.clone(),
            TEST_QUEUE_SERVER_RECV.1.clone(),
        ))
    }
}

#[rstest]
#[tokio::test]
async fn test_end_to_end_communication(client_config: ClientConfig, server_config: ServerConfig) {
    #[cfg(target_os = "macos")]
    use quincy::interface::prepend_packet_info_header;

    let client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });
    tokio::spawn(async move { client.run::<TestInterface<Client>>().await.unwrap() });

    // Test client -> server
    let test_packet = dummy_packet(ip_client, ip_server);
    #[cfg(target_os = "macos")]
    let test_packet = prepend_packet_info_header(test_packet).unwrap();

    TEST_QUEUE_CLIENT_RECV
        .0
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let recv_packet = TEST_QUEUE_SERVER_SEND.1.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);

    // Test server -> client
    let test_packet = dummy_packet(ip_server, ip_client);
    #[cfg(target_os = "macos")]
    let test_packet = prepend_packet_info_header(test_packet).unwrap();

    TEST_QUEUE_SERVER_RECV
        .0
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let recv_packet = TEST_QUEUE_CLIENT_SEND.1.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);
}
