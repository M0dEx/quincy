use anyhow::Result;
use async_trait::async_trait;
use bincode::{Decode, Encode};
use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncReadExt;

use crate::constants::BINCODE_BUFFER_SIZE;

use super::serde::{decode_message, encode_message};

#[async_trait]
pub trait AsyncSendBincode: Send {
    /// Sends a bincode-encoded message using this stream.
    ///
    /// ### Arguments
    /// - `message` - the message to be sent
    async fn send_message<M: Encode + Send>(&mut self, message: M) -> Result<()>;
}

#[async_trait]
pub trait AsyncReceiveBincode {
    /// Receives a bincode-encoded message using this stream.
    ///
    /// ### Arguments
    /// - `stream` - the RecvStream to receive the message from
    ///
    /// ### Returns
    /// - Type `M` - the received message
    async fn receive_message<M: Decode>(&mut self) -> Result<M>;
}

#[async_trait]
impl AsyncSendBincode for SendStream {
    async fn send_message<M: Encode + Send>(&mut self, message: M) -> Result<()> {
        let bytes = encode_message(message)?;

        self.write_all(&bytes).await?;

        Ok(())
    }
}

#[async_trait]
impl AsyncReceiveBincode for RecvStream {
    async fn receive_message<M: Decode>(&mut self) -> Result<M> {
        let mut buf = BytesMut::with_capacity(BINCODE_BUFFER_SIZE);
        self.read_buf(&mut buf).await?;

        let message = decode_message(buf.into())?;

        Ok(message)
    }
}
