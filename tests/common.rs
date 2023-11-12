use bytes::{BufMut, Bytes, BytesMut};
use etherparse::PacketBuilder;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use quincy::interface::{Interface, InterfaceRead, InterfaceWrite};
use std::io::Error;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

type TestSender = Arc<Mutex<UnboundedSender<Bytes>>>;
type TestReceiver = Arc<Mutex<UnboundedReceiver<Bytes>>>;
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

pub struct Client;
pub struct Server;

pub struct TestInterface<T> {
    _p: std::marker::PhantomData<T>,
    tx: TestSender,
    rx: TestReceiver,
}

pub type TestInterfaceClient = TestInterface<Client>;
pub type TestInterfaceServer = TestInterface<Server>;

impl<T: Unpin> AsyncRead for TestInterface<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let data = self.get_mut().rx.lock().unwrap().poll_recv(cx);
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
        self.get_mut().tx.lock().unwrap().send(data).unwrap();
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
impl Interface for TestInterface<Client> {
    fn create(_interface_address: IpNet, _mtu: i32) -> anyhow::Result<Self> {
        Ok(Self {
            _p: std::marker::PhantomData,
            tx: TEST_QUEUE_CLIENT_SEND.0.clone(),
            rx: TEST_QUEUE_CLIENT_RECV.1.clone(),
        })
    }
}

impl Interface for TestInterface<Server> {
    fn create(_interface_address: IpNet, _mtu: i32) -> anyhow::Result<Self> {
        Ok(Self {
            _p: std::marker::PhantomData,
            tx: TEST_QUEUE_SERVER_SEND.0.clone(),
            rx: TEST_QUEUE_SERVER_RECV.1.clone(),
        })
    }
}

pub fn dummy_packet(src: Ipv4Addr, dest: Ipv4Addr) -> Bytes {
    let mut writer = BytesMut::new().writer();
    PacketBuilder::ipv4(src.octets(), dest.octets(), 20)
        .icmpv4_echo_request(0, 0)
        .write(&mut writer, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();

    writer.into_inner().into()
}
