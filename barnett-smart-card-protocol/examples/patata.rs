// use tokio::time::sleep;
// use std::time::Duration;
// use p2p_connection::{P2PConnection, ProtocolMessage, GameAction};

// #[tokio::main]
// async fn main() {
//     // 1. Inicializar la conexión P2P
//     let p2p = match P2PConnection::init().await {
//         Ok(conn) => conn,
//         Err(e) => {
//             eprintln!("Error inicializando P2P: {}", e);
//             return;
//         }
//     };

//     // 2. Registrar un evento cuando se descubre un nuevo peer
//     p2p.on("peer_discovered", |peer_id| {
//         println!("🎉 Nuevo peer descubierto: {}", peer_id);
//     });

//     // 3. Registrar un evento para recibir mensajes del protocolo
//     p2p.on("received_message", |msg| {
//         println!("📩 Mensaje recibido: {}", msg);
//     });

//     // 4. Iniciar el sistema para escuchar eventos en la red P2P
//     p2p.start();

//     // 5. Enviar un mensaje de prueba después de unos segundos
//     sleep(Duration::from_secs(15)).await;
//     let test_message = ProtocolMessage::Action(GameAction::Bet(100));
    
//     if let Err(e) = p2p.send_message(test_message.clone()).await {
//         eprintln!("Error enviando mensaje: {}", e);
//     } else {
//         println!("✅ Mensaje enviado correctamente");
//     }

//     // 6. Escuchar mensajes en un loop
//     let mut i = 0;
//     while true {
//         match p2p.receive_message().await {
            
//             Ok(Some((peer, message))) => {
//                 let msg_str = format!("De {}: {:?}", peer, message);
//                 p2p.emit("received_message", &msg_str).await;
//             }
//             Ok(None) => {
//                 // No hay mensajes, esperar un poco antes de intentar de nuevo
//                 sleep(Duration::from_secs(5)).await;
//             }
//             Err(e) => {
//                 eprintln!("Error recibiendo mensaje: {}", e);
//             }
//         }
//         i = i + 1;
//         if i > 10 {
//             break;
//         }
//     }
// }
