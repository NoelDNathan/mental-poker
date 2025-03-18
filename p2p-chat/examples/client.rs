use async_std::task;
use futures::prelude::*;
use libp2p::{
    identity, mdns, noise, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
    NetworkBehaviour,
};
use libp2p::floodsub::{Floodsub, FloodsubEvent, Topic};
use std::error::Error;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct PlayerInfo {
    peer_id: String,
    address: String,
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    floodsub: Floodsub,
    mdns: mdns::tokio::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Crear identidad
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Tu Peer ID es: {}", peer_id);

    // 2. Configurar transporte (TCP + Seguridad)
    let transport = libp2p::tokio_development_transport(id_keys.clone()).await?;

    // 3. Crear protocolo de mensajería (Floodsub)
    let floodsub = Floodsub::new(peer_id);
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

    let topic = Topic::new("chat");

    let mut swarm = Swarm::new(
        transport,
        MyBehaviour { floodsub, mdns },
        peer_id,
    );

    swarm.behaviour_mut().floodsub.subscribe(topic.clone());

    // 4. Obtener dirección local
    let local_addr = format!("/ip4/127.0.0.1/tcp/{}", 4001); // Puerto local arbitrario

    // 5. Registrar en el servidor HTTP
    let client = Client::new();
    let server_url = "http://localhost:3000/register";

    let _ = client.post(server_url)
        .json(&PlayerInfo {
            peer_id: peer_id.to_string(),
            address: local_addr.clone(),
        })
        .send()
        .await?;

    println!("📡 Registrado en el servidor como {}", local_addr);

    // 6. Pedir la lista de jugadores permitidos
    let peers_url = format!("http://localhost:3000/get_peers/{}", peer_id);
    let response = client.get(&peers_url).send().await?;

    if response.status().is_success() {
        let peers: Vec<PlayerInfo> = response.json().await?;
        for peer in peers {
            println!("🎯 Conectando con {}", peer.address);
            if let Ok(addr) = peer.address.parse::<Multiaddr>() {
                swarm.dial(addr)?;
            }
        }
    }

    println!("Escribe mensajes en la consola:");

    // 7. Escuchar eventos y enviar mensajes
    loop {
        tokio::select! {
            Some(line) = async_std::io::stdin().lines().next().fuse() => {
                let msg = line?;
                swarm.behaviour_mut().floodsub.publish(topic.clone(), msg.as_bytes());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviour { floodsub: FloodsubEvent::Message(message), .. }) => {
                    println!(
                        "📨 Mensaje recibido de {}: {:?}",
                        message.source, String::from_utf8_lossy(&message.data)
                    );
                }
                _ => {}
            }
        }
    }
}
