use crate::common::{
    dummy_packet, TestInterfaceClient, TestInterfaceServer, TEST_QUEUE_CLIENT_RECV,
    TEST_QUEUE_CLIENT_SEND, TEST_QUEUE_SERVER_RECV, TEST_QUEUE_SERVER_SEND,
};
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy::server::QuincyServer;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::task::spawn_blocking;

mod common;

#[test]
fn test_end_to_end_communication() {
    #[cfg(target_os = "macos")]
    use quincy::interface::prepend_packet_info_header;

    let client_config =
        ClientConfig::from_path(Path::new("tests/static/client.toml"), "QUINCY").unwrap();
    let client = QuincyClient::new(client_config);

    let server_config =
        ServerConfig::from_path(Path::new("tests/static/server.toml"), "QUINCY").unwrap();
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);

    tokio_test::block_on(async move {
        tokio::spawn(async move { server.run::<TestInterfaceServer>().await.unwrap() });
        tokio::spawn(async move { client.run::<TestInterfaceClient>().await.unwrap() });

        // Test client -> server
        let test_packet = dummy_packet(ip_client, ip_server);
        #[cfg(target_os = "macos")]
        let test_packet = prepend_packet_info_header(test_packet).unwrap();

        TEST_QUEUE_CLIENT_RECV
            .0
            .lock()
            .unwrap()
            .send(test_packet.clone())
            .unwrap();

        let recv_packet = spawn_blocking(|| {
            TEST_QUEUE_SERVER_SEND
                .1
                .lock()
                .unwrap()
                .blocking_recv()
                .unwrap()
        })
        .await
        .unwrap();

        assert_eq!(test_packet, recv_packet);

        // Test server -> client
        let test_packet = dummy_packet(ip_server, ip_client);
        #[cfg(target_os = "macos")]
        let test_packet = prepend_packet_info_header(test_packet).unwrap();

        TEST_QUEUE_SERVER_RECV
            .0
            .lock()
            .unwrap()
            .send(test_packet.clone())
            .unwrap();

        let recv_packet = spawn_blocking(|| {
            TEST_QUEUE_CLIENT_SEND
                .1
                .lock()
                .unwrap()
                .blocking_recv()
                .unwrap()
        })
        .await
        .unwrap();

        assert_eq!(test_packet, recv_packet);
    });
}
