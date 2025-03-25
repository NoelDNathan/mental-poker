use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::{rand::thread_rng, UniformRand};
use p2p_connection2::{GameAction, P2PConnection, ProtocolMessage};
use std::{collections::HashMap, env, error::Error, time::Duration};
use texas_holdem::{encode_cards, generator, Card, CardProtocol, ClassicPlayingCard};
use tokio::time::sleep;
use ark_ec::{
    models::{ModelParameters, MontgomeryModelParameters, TEModelParameters},
    twisted_edwards_extended::{GroupAffine, GroupProjective},
};
// Macro para serializar bytes, ya que el código original lo usa
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = Vec::new();
        buf.extend_from_slice($x);
        buf
    }};
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Inicializamos la conexión P2P
    let mut p2p = P2PConnection::init().await?;

    println!(
        "Conexión P2P inicializada con PeerID: {}",
        p2p.local_peer_id()
    );

    // Esperamos un momento para descubrir otros peers
    println!("Esperando para descubrir otros jugadores...");
    sleep(Duration::from_secs(5)).await;

    p2p.start_game().await?;
    // // Leer argumentos de la línea de comandos para determinar si somos dealer
    // let args: Vec<String> = env::args().collect();
    // let is_dealer = args.iter().any(|arg| arg == "--dealer");

    // // Setup del protocolo de cartas
    // let m = 2; // Cartas por jugador
    // let n = 26; // Número de tipos de cartas (para una baraja estándar de póker)
    // let num_of_cards = m * n;
    // let rng = &mut thread_rng();

    // let generator = generator();
    // let parameters = CardProtocol::setup(rng, generator, m, n)?;
    // let player = Player::new(rng, &parameters, &to_bytes!(b"Player1").unwrap())?;

    // // Enviamos nuestra clave pública
    // let pk_bytes = serialize_canonical(&player.pk)?;
    // p2p.send_public_key(&pk_bytes).await?;
    // println!("Clave pública enviada: {} bytes", pk_bytes.len());

    // // Si somos el dealer, preparamos las cartas codificadas
    // if is_dealer {
    //     println!("Actuando como dealer. Preparando el mazo...");

    //     // Generamos las cartas codificadas
    //     let encoded_cards: HashMap<Card, ClassicPlayingCard> = encode_cards(rng, num_of_cards);

    //     // Las serializamos para enviar
    //     let encoded_cards_bytes = serialize_canonical(&encoded_cards)?;

    //     // Enviamos las cartas codificadas a los otros jugadores
    //     // Nota: esta función no existe en el original, habría que añadirla
    //     // p2p.send_encoded_cards(&encoded_cards_bytes).await?;

    //     // Como alternativa, podríamos enviar un mensaje personalizado
    //     p2p.send_message(ProtocolMessage::Card(encoded_cards_bytes))
    //         .await?;

    //     println!(
    //         "Cartas codificadas enviadas: {} bytes",
    //         encoded_cards_bytes.len()
    //     );

    //     // Simulamos la distribución de cartas
    //     // En un juego real, aquí habría lógica para asignar cartas a cada jugador



    // } else {


    // }

    // Mantenemos el programa en ejecución para seguir recibiendo mensajes
    println!("Manteniendo conexión activa. Presiona Ctrl+C para salir.");
    loop {
        sleep(Duration::from_secs(1)).await;
    }
}

// Funciones de utilidad para serialización canónica
fn serialize_canonical<T: CanonicalSerialize>(data: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut buffer = Vec::new();
    data.serialize(&mut buffer)?;
    Ok(buffer)
}

fn deserialize_canonical<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let mut reader = &bytes[..];
    let value = T::deserialize(&mut reader)?;
    Ok(value)
}
