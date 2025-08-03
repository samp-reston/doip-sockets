use std::{
    io::{self},
    pin::Pin,
};

use doip_codec::{DoipCodec, Error as CodecError};
use doip_definitions::{
    builder::DoipMessageBuilder, header::ProtocolVersion, message::DoipMessage,
    payload::DoipPayload,
};
use futures::{SinkExt, StreamExt};
use openssl::ssl::{Ssl, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use tokio::net::{TcpStream as TokioTcpStream, ToSocketAddrs};

use tokio_openssl::SslStream;
use tokio_util::codec::{Framed, FramedRead, FramedWrite};

use crate::error::SocketSendError;

use super::{
    tcp_split::{TcpStreamReadHalf, TcpStreamWriteHalf},
    SocketConfig,
};
/// Simple implementation of a TCP Stream
///
/// Applying only the most simple methods on this struct it is able to act as
/// a simple TCP stream. If extended functionality is required you can access the
/// inner Tokio TCP Stream, or raise a Issue on GitHub.
#[derive(Debug)]
pub struct DoIpSslStream {
    io: Framed<SslStream<TokioTcpStream>, DoipCodec>,
    config: SocketConfig,
}

impl DoIpSslStream {
    /// Creates a new TCP Stream from a Tokio TCP Stream
    pub fn new(io: SslStream<TokioTcpStream>) -> Self {
        DoIpSslStream {
            io: Framed::new(io, DoipCodec {}),
            config: SocketConfig {
                protocol_version: ProtocolVersion::Iso13400_2012,
            },
        }
    }

    /// Creates a new TCP Stream given a remote address with the default ciphers
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<DoIpSslStream> {
        let default_ciphers = vec![
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
        ];

        Self::connect_with_ciphers(addr, &default_ciphers, None).await
    }

    /// Creates a new TCP Stream given a remote address and a list of ciphers
    /// tls_ciphers is a list of ciphers in openssl format
    pub async fn connect_with_ciphers<A: ToSocketAddrs>(
        addr: A,
        tls_ciphers: &[&str],
        eliptic_curve_groups: Option<&[&str]>,
    ) -> io::Result<DoIpSslStream> {
        match TokioTcpStream::connect(addr).await {
            Ok(stream) => {
                // allow unsafe ciphers in order to get better debugging
                let mut builder = SslContextBuilder::new(SslMethod::tls_client())?;

                builder.set_cipher_list(&tls_ciphers.join(":"))?;
                builder.set_verify(SslVerifyMode::NONE);
                // necessary for NULL encryption
                builder.set_security_level(0);
                builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
                builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

                if let Some(groups) = eliptic_curve_groups {
                    builder.set_groups_list(&groups.join(":"))?;
                }

                let preset_options = builder.options();
                // this is the flag legacy_renegotiation in openssl client
                builder.set_options(
                    preset_options.union(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION),
                );

                let ctx = builder.build();
                let ssl = Ssl::new(&ctx)?;

                let mut stream = SslStream::new(ssl, stream)?;

                // wait for the actual connection .
                Pin::new(&mut stream)
                    .connect()
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                Ok(Self::apply_codec(stream))
            }
            Err(err) => Err(err),
        }
    }

    fn apply_codec(stream: SslStream<TokioTcpStream>) -> DoIpSslStream {
        DoIpSslStream {
            io: Framed::new(stream, DoipCodec {}),
            config: SocketConfig {
                protocol_version: ProtocolVersion::Iso13400_2012,
            },
        }
    }

    /// Send a DoIP frame to the sink
    pub async fn send(&mut self, payload: DoipPayload) -> Result<(), SocketSendError> {
        let msg = DoipMessageBuilder::new()
            .protocol_version(self.config.protocol_version)
            .payload(payload)
            .build();

        match self.io.send(msg).await {
            Ok(_) => Ok(()),
            Err(err) => Err(SocketSendError::EncodeError(err)),
        }
    }

    /// Read a DoIP frame off the stream
    pub async fn read(&mut self) -> Option<Result<DoipMessage, CodecError>> {
        self.io.next().await
    }

    /// Splits the TCP Stream into a Read Half and Write Half
    pub fn into_split(
        self,
    ) -> (
        TcpStreamReadHalf<SslStream<TokioTcpStream>>,
        TcpStreamWriteHalf<SslStream<TokioTcpStream>>,
    ) {
        let stream: SslStream<TokioTcpStream> = self.io.into_inner();

        let (r_half, w_half) = tokio::io::split(stream);

        let read = FramedRead::new(r_half, DoipCodec {});
        let write = FramedWrite::new(w_half, DoipCodec {});

        (
            TcpStreamReadHalf::new(read, Some(self.config)),
            TcpStreamWriteHalf::new(write, Some(self.config)),
        )
    }

    /// Get a reference to the inner Tokio TCP Stream
    pub fn get_stream_ref(&self) -> &SslStream<TokioTcpStream> {
        self.io.get_ref()
    }

    /// Access the inner Tokio TCP Stream, consumes the DoIP TCP Stream
    pub fn into_socket(self) -> SslStream<TokioTcpStream> {
        self.io.into_inner()
    }
}

#[cfg(test)]
mod test_tcp_stream {
    use doip_definitions::payload::{
        ActivationCode, ActivationType, DoipPayload, RoutingActivationRequest,
        RoutingActivationResponse,
    };

    use crate::tcp::{ssl_stream::DoIpSslStream, tcp_stream::TcpStream};

    #[ignore]
    #[tokio::test]
    async fn test_connect() {
        const TESTER_ADDR: &str = "10.2.1.101:3496";

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stream = TcpStream::connect(addr).await;
        dbg!(&stream);

        assert!(stream.is_ok());

        // Cleanup
        drop(listener);
    }

    #[ignore]
    #[tokio::test()]
    async fn test_send() {
        // try to connect to an actual ECU... actual ip address redacted
        let stream = DoIpSslStream::connect("127.0.0.1:3496").await;

        let mut stream = stream.unwrap();
        let routing_activation = DoipPayload::RoutingActivationRequest(RoutingActivationRequest {
            source_address: [15, 13],
            activation_type: ActivationType::Default,
            buffer: [0, 0, 0, 0],
        });

        let send_result = stream.send(routing_activation).await;
        println!("send_result: {:?}", send_result);

        let read_result = stream.read().await;
        println!("read_result: {:?}", read_result);
    }

    #[tokio::test]
    async fn test_read() {
        const TESTER_ADDR: &str = "127.0.0.1:0";
        let routing_activation = DoipPayload::RoutingActivationRequest(RoutingActivationRequest {
            source_address: [0x0e, 0x80],
            activation_type: ActivationType::Default,
            buffer: [0, 0, 0, 0],
        });

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await;
        let listener = listener.unwrap();

        let client = TcpStream::connect(listener.local_addr().unwrap()).await;
        let mut client = client.unwrap();

        let (socket, _) = listener.accept().await.unwrap();
        let mut server = TcpStream::new(socket);

        let _ = &client.send(routing_activation).await;
        let _ = server.read().await.unwrap().unwrap();

        let routing_activation_res =
            DoipPayload::RoutingActivationResponse(RoutingActivationResponse {
                logical_address: [0x0e, 0x80],
                source_address: [0x14, 0x11],
                activation_code: ActivationCode::SuccessfullyActivated,
                buffer: [0, 0, 0, 0],
            });
        let _ = server.send(routing_activation_res.clone()).await;
        let echo = client.read().await.unwrap().unwrap();

        assert_eq!(echo.payload, routing_activation_res);
    }

    #[tokio::test]
    async fn test_into_split() {
        const TESTER_ADDR: &str = "127.0.0.1:0";
        let routing_activation = DoipPayload::RoutingActivationRequest(RoutingActivationRequest {
            source_address: [0x0e, 0x80],
            activation_type: ActivationType::Default,
            buffer: [0, 0, 0, 0],
        });

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await;
        let listener = listener.unwrap();

        let client = TcpStream::connect(listener.local_addr().unwrap()).await;
        let client = client.unwrap();
        let (mut read, mut write) = client.into_split();

        let (socket, _) = listener.accept().await.unwrap();
        let mut server = TcpStream::new(socket);

        let _ = write.send(routing_activation).await;
        let _ = server.read().await.unwrap().unwrap();

        let routing_activation_res =
            DoipPayload::RoutingActivationResponse(RoutingActivationResponse {
                logical_address: [0x0e, 0x80],
                source_address: [0x14, 0x11],
                activation_code: ActivationCode::SuccessfullyActivated,
                buffer: [0, 0, 0, 0],
            });

        let _ = server.send(routing_activation_res.clone()).await;
        let echo = read.read().await.unwrap().unwrap();

        assert_eq!(echo.payload, routing_activation_res)
    }
}
