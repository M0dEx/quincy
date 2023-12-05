use bytes::{BufMut, Bytes, BytesMut};
use etherparse::PacketBuilder;
use once_cell::sync::Lazy;
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy::interface::{InterfaceRead, InterfaceWrite};
use rstest::fixture;
use std::io::Error;
use std::net::Ipv4Addr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex};

pub type TestSender = Arc<Mutex<UnboundedSender<Bytes>>>;
pub type TestReceiver = Arc<Mutex<UnboundedReceiver<Bytes>>>;

pub struct TestInterface<T> {
    _p: std::marker::PhantomData<T>,
    tx: TestSender,
    rx: TestReceiver,
}

impl<T> TestInterface<T> {
    pub fn new(tx: TestSender, rx: TestReceiver) -> Self {
        Self {
            _p: std::marker::PhantomData,
            tx,
            rx,
        }
    }
}

impl<T: Unpin> AsyncRead for TestInterface<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let data = self.get_mut().rx.try_lock().unwrap().poll_recv(cx);
        match data {
            Poll::Ready(Some(data)) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: Unpin> AsyncWrite for TestInterface<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let data = Bytes::copy_from_slice(buf);
        self.get_mut().tx.try_lock().unwrap().send(data).unwrap();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<T: 'static + Send + Sync + Unpin> InterfaceRead for TestInterface<T> {}
impl<T: 'static + Send + Sync + Unpin> InterfaceWrite for TestInterface<T> {}

pub fn dummy_packet(src: Ipv4Addr, dest: Ipv4Addr) -> Bytes {
    let mut writer = BytesMut::new().writer();
    PacketBuilder::ipv4(src.octets(), dest.octets(), 20)
        .icmpv4_echo_request(0, 0)
        .write(&mut writer, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();

    #[cfg(target_os = "macos")]
    {
        use quincy::interface::prepend_packet_info_header;
        prepend_packet_info_header(&writer.into_inner().into()).unwrap()
    }

    #[cfg(not(target_os = "macos"))]
    writer.into_inner().into()
}

#[fixture]
pub fn client_config() -> ClientConfig {
    ClientConfig::from_path(Path::new("tests/static/client.toml"), "QUINCY").unwrap()
}

#[fixture]
pub fn server_config() -> ServerConfig {
    ServerConfig::from_path(Path::new("tests/static/server.toml"), "QUINCY").unwrap()
}

pub const fn make_queue_pair() -> Lazy<(TestSender, TestReceiver)> {
    Lazy::new(|| {
        let (tx, rx) = mpsc::unbounded_channel();
        (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
    })
}

#[macro_export]
macro_rules! interface_impl {
    ($name:ident, $test_queue_send:ident, $test_queue_recv:ident) => {
        impl Interface for $name {
            fn create(_interface_address: IpNet, _mtu: i32) -> Result<Self> {
                Ok(Self::new(
                    $test_queue_send.0.clone(),
                    $test_queue_recv.1.clone(),
                ))
            }
        }
    };
}
