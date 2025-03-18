// Copyright 2018 Parity Technologies (UK) Ltd.
// ... existing copyright notice ...

use futures::StreamExt;
use libp2p::{core::multiaddr::Multiaddr, identify, noise, swarm::SwarmEvent, tcp, yamux};
use std::error::Error;
use tracing_subscriber::EnvFilter;

pub struct Swarm {
    swarm: libp2p::Swarm<identify::Behaviour>,
}

impl Swarm {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        let swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                identify::Behaviour::new(identify::Config::new(
                    "/ipfs/id/1.0.0".to_string(),
                    key.public(),
                ))
            })?
            .build();

        Ok(Self { swarm })
    }

    pub fn listen_on(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        self.swarm.listen_on(addr.parse()?)?;
        Ok(())
    }

    pub async fn dial(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let remote: Multiaddr = addr.parse()?;
        self.swarm.dial(remote)?;
        Ok(())
    }

    pub async fn run(&mut self) {
        loop {
            println!("Waiting for event");
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
                SwarmEvent::Behaviour(identify::Event::Sent { peer_id, .. }) => {
                    println!("Sent identify info to {peer_id:?}")
                }
                SwarmEvent::Behaviour(identify::Event::Received { info, .. }) => {
                    println!("Received {info:?}")
                }
                _ => {}
            }
        }
    }
}
