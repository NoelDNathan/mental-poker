use async_std::task;
use futures::prelude::*;
use libp2p::{
    identity, mdns, noise,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
    request_response::{RequestResponse, RequestResponseCodec, ProtocolSupport, RequestResponseEvent},
    Multiaddr,
};
use std::{collections::HashSet, error::Error, iter};

// Define a simple codec for communication
#[derive(Clone)]
struct PokerCodec;

impl RequestResponseCodec for PokerCodec {
    type Protocol = String;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    fn read_request(&mut self, _: &Self::Protocol, io: &mut impl AsyncRead) -> futures::io::Result<Self::Request> {
        async_std::io::read_to_end(io, &mut Vec::new())
    }

    fn read_response(&mut self, _: &Self::Protocol, io: &mut impl AsyncRead) -> futures::io::Result<Self::Response> {
        async_std::io::read_to_end(io, &mut Vec::new())
    }

    fn write_request(&mut self, _: &Self::Protocol, io: &mut impl AsyncWrite, req: Self::Request) -> futures::io::Result<()> {
        async_std::io::write_all(io, &req).await
    }

    fn write_response(&mut self, _: &Self::Protocol, io: &mut impl AsyncWrite, res: Self::Response) -> futures::io::Result<()> {
        async_std::io::write_all(io, &res).await
    }
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    let transport = tcp::TcpTransport::new()
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::NoiseAuthenticated::xx(&local_key)?)
        .multiplex(yamux::YamuxConfig::default())
        .boxed();

    let behaviour = RequestResponse::new(
        PokerCodec,
        iter::once(("poker/1.0.0".to_string(), ProtocolSupport::Full)),
        Default::default(),
    );

    let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id)
        .executor(Box::new(|fut| {
            async_std::task::spawn(fut);
        }))
        .build();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(RequestResponseEvent::Message { peer, message, .. }) => {
                println!("Received from {:?}: {:?}", peer, message);
            }
            _ => {}
        }
    }
}
