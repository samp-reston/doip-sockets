use std::io;

use doip_codec::{DecodeError, DoipCodec};
use doip_definitions::{header::PayloadType, message::DoipMessage};
use futures::{SinkExt, StreamExt};
use tokio::net::ToSocketAddrs;
use tokio_util::codec::Framed;

use crate::error::SocketSendError;

#[derive(Debug)]
pub struct TcpStream {
    io: Framed<tokio::net::TcpStream, DoipCodec>,
}

impl TcpStream {
    pub fn new(io: Framed<tokio::net::TcpStream, DoipCodec>) -> Self {
        TcpStream { io }
    }

    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => Ok(Self::apply_codec(stream)),
            Err(err) => Err(err),
        }
    }

    fn apply_codec(stream: tokio::net::TcpStream) -> TcpStream {
        TcpStream {
            io: Framed::new(stream, DoipCodec),
        }
    }

    pub async fn send(&mut self, msg: DoipMessage) -> Result<(), SocketSendError> {
        match self.is_valid_payload(msg.header.payload_type) {
            true => (),
            false => return Err(SocketSendError::InvalidTcpPayload),
        }

        match self.io.send(msg).await {
            Ok(_) => Ok(()),
            Err(err) => Err(SocketSendError::EncodeError(err)),
        }
    }

    pub async fn read(&mut self) -> Option<Result<DoipMessage, DecodeError>> {
        self.io.next().await
    }

    fn is_valid_payload(&self, payload_type: PayloadType) -> bool {
        // Allow for full type safety and implementation consistency.
        #[allow(clippy::match_like_matches_macro)]
        match payload_type {
            doip_definitions::header::PayloadType::GenericNack => true,
            doip_definitions::header::PayloadType::VehicleAnnouncementMessage => true,
            doip_definitions::header::PayloadType::RoutingActivationRequest => true,
            doip_definitions::header::PayloadType::RoutingActivationResponse => true,
            doip_definitions::header::PayloadType::AliveCheckRequest => true,
            doip_definitions::header::PayloadType::AliveCheckResponse => true,
            doip_definitions::header::PayloadType::DiagnosticMessage => true,
            doip_definitions::header::PayloadType::DiagnosticMessageAck => true,
            doip_definitions::header::PayloadType::DiagnosticMessageNack => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod test_tcp_stream {
    use doip_codec::DoipCodec;
    use doip_definitions::{
        header::DoipVersion,
        message::{
            ActivationType, DoipMessage, RoutingActivationRequest, VehicleIdentificationRequest,
        },
    };
    use tokio::io::AsyncReadExt;
    use tokio_util::codec::Framed;

    use crate::TcpStream;

    #[tokio::test]
    async fn test_connect() {
        const TESTER_ADDR: &str = "127.0.0.1:8080";

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await;

        let stream = TcpStream::connect(TESTER_ADDR).await;

        assert!(stream.is_ok());

        // Cleanup
        drop(listener);
    }

    #[tokio::test]
    async fn test_send() {
        const TESTER_ADDR: &str = "127.0.0.1:0";

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await;
        let listener = listener.unwrap();

        let stream = TcpStream::connect(listener.local_addr().unwrap()).await;

        let mut stream = stream.unwrap();

        let (mut socket, _) = listener.accept().await.unwrap();

        let routing_activation = DoipMessage::new(
            DoipVersion::Iso13400_2012,
            Box::new(RoutingActivationRequest {
                source_address: [0x0e, 0x80],
                activation_type: ActivationType::Default,
                buffer: [0, 0, 0, 0],
            }),
        );

        let bytes = routing_activation.to_bytes();

        let _ = &stream.send(routing_activation).await;

        let mut buffer = [0; 64];
        let read = socket.read(&mut buffer).await.unwrap();

        assert_eq!(&buffer[..read], &bytes);

        // Cleanup
        drop(socket);
    }

    #[tokio::test]
    async fn test_send_error() {
        const TESTER_ADDR: &str = "127.0.0.1:0";

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await;
        let listener = listener.unwrap();

        let stream = TcpStream::connect(listener.local_addr().unwrap()).await;

        let mut stream = stream.unwrap();

        let (socket, _) = listener.accept().await.unwrap();

        let vehicle_id_req = DoipMessage::new(
            DoipVersion::Iso13400_2012,
            Box::new(VehicleIdentificationRequest {}),
        );

        let req = stream.send(vehicle_id_req).await;

        assert!(
            req.is_err(),
            "Expected req to be an error, but it was {:?}",
            req
        );

        // Cleanup
        drop(socket);
    }

    #[tokio::test]
    async fn test_read() {
        const TESTER_ADDR: &str = "127.0.0.1:0";
        let routing_activation = DoipMessage::new(
            DoipVersion::Iso13400_2012,
            Box::new(RoutingActivationRequest {
                source_address: [0x0e, 0x80],
                activation_type: ActivationType::Default,
                buffer: [0, 0, 0, 0],
            }),
        );
        let bytes = routing_activation.to_bytes();

        let listener = tokio::net::TcpListener::bind(TESTER_ADDR).await;
        let listener = listener.unwrap();

        let client = TcpStream::connect(listener.local_addr().unwrap()).await;
        let mut client = client.unwrap();

        let (socket, _) = listener.accept().await.unwrap();
        let mut server = TcpStream::new(Framed::new(socket, DoipCodec));

        let _ = &client.send(routing_activation).await;
        let res = server.read().await.unwrap().unwrap();

        let _ = server.send(res).await;
        let echo = client.read().await.unwrap().unwrap();

        assert_eq!(echo.to_bytes(), bytes)
    }
}

// use std::io;

// use doip_codec::DoipCodec;
// use tokio::net::ToSocketAddrs;
// use tokio_util::codec::Framed;

// struct TCPTEST {}

// impl TCPTEST {
//     pub async fn connect<A: ToSocketAddrs>(
//         addr: A,
//     ) -> io::Result<Framed<tokio::net::TcpStream, DoipCodec>> {
//         let stream = tokio::net::TcpStream::connect(addr).await?;
//         Ok(Framed::new(stream, DoipCodec))
//     }
// }
