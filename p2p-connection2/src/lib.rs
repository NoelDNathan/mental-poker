use ark_ff::to_bytes;
use ark_std::rand::thread_rng;
use ark_std::{rand::Rng, One};
use babyjubjub::{EdwardsAffine, EdwardsProjective};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use rand;
use std::collections::HashMap;
use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, generator, Card, CardProtocol, ClassicPlayingCard,
    InternalPlayer, ProofKeyOwnership, PublicKey, MaskedCard, RemaskingProof, Scalar
};

use std::{
    collections::hash_map::DefaultHasher,
    env,
    error::Error,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::Duration,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use futures::{channel::mpsc, StreamExt};
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId},
    mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{io, select};
use tracing_subscriber::EnvFilter;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyInfo {
    name: Vec<u8>,
    public_key: Vec<u8>,
    proof_key: Vec<u8>,
}

// Definimos una estructura para los mensajes del protocolo
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMessage {
    PublicKey(Vec<u8>),
    Proof(Vec<u8>),
    RevealToken(Vec<u8>),
    Card(Vec<u8>),
    Action(GameAction),
    EncodedCards(Vec<u8>),
    PublicKeyInfo(PublicKeyInfo),
    DeckAndProofs(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum GameAction {
    Bet(u64),
    Check,
    Fold,
    Call,
    Raise(u64),
}

// Estructura para la conexión P2P
pub struct P2PConnection {
    sender: Option<mpsc::Sender<ProtocolMessage>>,
    receiver: Option<Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>>,
    peer_id: Option<PeerId>,
    is_dealer: bool,
    num_players: u8,
    player_keys_proof_info: Option<Arc<Mutex<Vec<(PublicKey, ProofKeyOwnership, Vec<u8>)>>>>,
    joint_pk: Option<PublicKey>,
}

// El comportamiento de red combina Gossipsub y mDNS
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

impl P2PConnection {
    // Inicializa la conexión P2P
    pub fn new() -> Self {
        Self {
            sender: None,
            receiver: None,
            peer_id: None,
            is_dealer: false,
            num_players: 0,
            player_keys_proof_info: None,
            joint_pk: None,
        }
    }

    pub async fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        // Canales para comunicación con la aplicación principal
        let (to_swarm_tx, mut to_swarm_rx) = mpsc::channel(32);
        let (mut from_swarm_tx, from_swarm_rx) = mpsc::channel(32);

        let from_swarm_rx = Arc::new(Mutex::new(from_swarm_rx));

        // Crear y configurar el swarm
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    MessageId::from(s.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

                let gossipsub = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;
                Ok(MyBehaviour { gossipsub, mdns })
            })?
            .build();

        let topic = IdentTopic::new("texas-holdem");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        // Configurar listeners
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let peer_id = *swarm.local_peer_id();
        println!("Local peer ID: {}", peer_id);
        let mut num_players = 1;

        let m = 2;
        let n = 26;
        let num_of_cards = m * n;
        let rng = &mut thread_rng();
        let parameters = CardProtocol::setup(rng, generator(), m, n)?;

        // Iniciar el bucle principal en un hilo separado
        let swarm_topic = topic.clone();

        let mut player_keys_proof_info = Vec::new();
        let player_keys_proof_info_arc = Arc::new(Mutex::new(player_keys_proof_info));
        let player_keys_clone = Arc::clone(&player_keys_proof_info_arc);
        
        let card_mapping: Option<HashMap<Card, ClassicPlayingCard>> = None;
        let card_mapping_arc = Arc::new(Mutex::new(card_mapping));
        let card_mapping_clone = Arc::clone(&card_mapping_arc);
        
        let mut joint_pk = None;
        // Leer argumentos de la línea de comandos
        let args: Vec<String> = env::args().collect();
        let is_dealer = args.iter().any(|arg| arg == "--dealer"); // Verificar si el argumento dealer es "yes"
        tokio::spawn(async move {
            loop {
                select! {
                    message = to_swarm_rx.next() => {
                        if let Some(message) = message {
                            let serialized = serde_json::to_string(&message).unwrap();
                            if let Err(e) = swarm
                                .behaviour_mut().gossipsub
                                .publish(swarm_topic.clone(), serialized.as_bytes()) {
                                println!("Publish error: {e:?}");
                            }
                        }
                    }
                    event = swarm.select_next_some() => match event {
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, _multiaddr) in list {
                                println!("mDNS discovered a new peer: {peer_id}");
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            }
                        },
                        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _multiaddr) in list {
                                println!("mDNS discover peer has expired: {peer_id}");
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        },
                        // SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        //     propagation_source: peer_id,
                        //     message_id: _id,
                        //     message,
                        // })) => {
                        //     match serde_json::from_slice::<ProtocolMessage>(&message.data) {
                        //         Ok(protocol_message) => {
                        //             println!("Received message from {}: {:?}", peer_id, protocol_message);
                        //             if let Err(e) = from_swarm_tx.try_send((peer_id, protocol_message)) {
                        //                 println!("Error forwarding message: {:?}", e);
                        //             }
                        //         },
                        //         Err(e) => println!("Error deserializing message: {:?}", e),
                        //     }
                        // },

                        SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source: peer_id,
                            message_id: _id,
                            message,
                        })) => {
                            match serde_json::from_slice::<ProtocolMessage>(&message.data) {
                                Ok(protocol_message) => {
                                    // println!("Received message from {}: {:?}", peer_id, protocol_message);

                                    // if let ProtocolMessage::PublicKey(key) = protocol_message.clone() {
                                    //     match deserialize_canonical::<PublicKey>(&key) {
                                    //         Ok(pk) => println!("Received public key from {}: {:?}", peer_id, pk),
                                    //         Err(e) => println!("Error deserializing public key: {:?}", e),
                                    //     }
                                    // }

                                    if let ProtocolMessage::PublicKeyInfo(public_key_info) = protocol_message.clone() {
                                        let mut pk = None;
                                        let mut proof_key = None;
                                        let mut name = String::new();

                                        match deserialize_canonical::<PublicKey>(&public_key_info.public_key) {
                                            Ok(decoded_pk) => pk = Some(decoded_pk),
                                            Err(e) => println!("Error deserializing public key: {:?}", e),
                                        }

                                        match deserialize_canonical::<ProofKeyOwnership>(&public_key_info.proof_key) {
                                            Ok(decoded_proof) => proof_key = Some(decoded_proof),
                                            Err(e) => println!("Error deserializing proof key: {:?}", e),
                                        }

                                        name = String::from_utf8(public_key_info.name).unwrap_or_default();

                                        if let (Some(pk_val), Some(proof_val)) = (pk, proof_key) {
                                            // println!("Received public key info from:");
                                            // println!("proof_key random_commit: {:?}", proof_val.random_commit.to_string());
                                            // println!("proof_key opening: {:?}", proof_val.opening.to_string());
                                            let name_bytes = to_bytes![name.as_bytes()].unwrap();
                                            player_keys_clone.lock().unwrap().push((pk_val, proof_val, name_bytes));
                                            println!("players keys: {:?}", player_keys_clone);
                                            num_players += 1;
                                            println!("Number of players: {:?}", num_players);
                                            if num_players == 3 {
                                                match CardProtocol::compute_aggregate_key(&parameters, &player_keys_clone.lock().unwrap()) {
                                                    Ok(aggregate_key) => {
                                                        joint_pk = Some(aggregate_key);
                                                        println!("joint_pk: {:?}", joint_pk);
                                                    },
                                                    Err(e) => println!("Error computing aggregate key: {:?}", e),
                                                }
                                                if is_dealer {
                                                    self.deal_cards().await?;
                                                }
                                            }

                                            // verify public key ownership
                                            // match CardProtocol::verify_key_ownership(&parameters, &pk_val, &name_bytes, &proof_val) {
                                            //     Ok(_) => println!("Key ownership verified successfully!"),
                                            //     Err(e) => println!("Key ownership verification failed: {:?}", e),
                                            // }

                                        }
                                    }

                                    if let ProtocolMessage::EncodedCards(encoded_cards) = protocol_message.clone() {
                                        match deserialize_canonical::<Vec<Card>>(&encoded_cards) {
                                            Ok(decoded_cards) => {
                                                let encode_cards = encode_cards_ext(decoded_cards);
                                                let list_of_cards = encode_cards.keys().cloned().collect::<Vec<_>>();

                                                // Debería verificar que son puntos validos de la curva!!!

                                            },
                                            Err(e) => println!("Error deserializing encoded cards: {:?}", e),
                                        }
                                    }

                                    if let ProtocolMessage::DeckAndProofs(deck_and_proofs) = protocol_message.clone() {
                                        match deserialize_canonical::<Vec<(MaskedCard, RemaskingProof)>>(&deck_and_proofs) {
                                            Ok(decoded_deck_and_proofs) => {
                                                println!("Received deck and proofs: {:?}", decoded_deck_and_proofs.len());
                                                for (masked_card, remasking_proof) in decoded_deck_and_proofs {
                                                    println!("masked_card: {:?}", masked_card.0.to_string());
                                                    println!("remasking_proof a: {:?}", remasking_proof.a.to_string());
                                                    println!("remasking_proof b : {:?}", remasking_proof.b.to_string());
                                                    println!("remasking_proof c: {:?}", remasking_proof.c.to_string());
                                                }
                                            }
                                            Err(e) => println!("Error deserializing deck and proofs: {:?}", e),
                                        }
                                    }

                                    if let Err(e) = from_swarm_tx.try_send((peer_id, protocol_message)) {
                                        println!("Error forwarding message: {:?}", e);
                                    }
                                },
                                Err(e) => println!("Error deserializing message: {:?}", e),
                            }
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Local node is listening on {address}");
                        }


                        _ => {}
                    }
                }
            }
        });

    
        Ok(Self {
            sender: to_swarm_tx,
            receiver: from_swarm_rx,
            peer_id,
            is_dealer,
            num_players,
            player_keys_proof_info: Arc::clone(&player_keys_proof_info_arc),
            joint_pk,
        })
    }

    pub async fn deal_cards(&mut self) -> Result<(), Box<dyn Error>> {
        println!("El jugador es el dealer.");
        let rng = &mut thread_rng();  
        let m = 2;
        let n = 26;
        let num_of_cards = m * n;


        let list_of_cards = generate_list_of_cards(rng, num_of_cards);
        let encoded_cards = encode_cards_ext(list_of_cards.clone());

        for (i, (card, value)) in encoded_cards.iter().enumerate().take(52) {
            println!("{:?} -> {:?}", card.0.to_string(), value);
        }

        let encoded_cards_bytes = serialize_canonical(&list_of_cards)?;
        self.send_encoded_cards(&encoded_cards_bytes).await?;

         // Solo importa el generator en este caso
         let parameters = CardProtocol::setup(rng, generator(), m, n)?;


         let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = encoded_cards
             .keys()
             .map(|card| CardProtocol::mask(rng, &parameters, self.joint_pk.as_ref().unwrap(), &card, &Scalar::one()))
             .filter_map(Result::ok) 
             .collect();

        let serialized_deck_and_proofs = serialize_canonical(&deck_and_proofs)?;
        self.send_message(ProtocolMessage::DeckAndProofs(serialized_deck_and_proofs)).await?;
             
        println!("Cartas enmascaradas y pruebas enviadas: {} elementos", deck_and_proofs.len());


        Ok(())

    }

    pub async fn start_game(&mut self) -> Result<(), Box<dyn Error>> {
        // Setup the parameters for the card protocol
        let m = 2;
        let n = 26;
        let num_of_cards = m * n;
        let rng = &mut thread_rng();
        let args: Vec<String> = env::args().collect();
        let name = args
            .iter()
            .position(|arg| arg == "--name")
            .and_then(|index| args.get(index + 1))
            .cloned()
            .unwrap_or_else(|| "DefaultName".to_string());

        let parameters = CardProtocol::setup(rng, generator(), m, n)?;
        let player = InternalPlayer::new(rng, &parameters, &to_bytes![name.as_bytes()].unwrap())?;

        // Puedes usar is_dealer para decidir el comportamiento del jugador
        // if self.is_dealer {
        //     let list_of_cards = generate_list_of_cards(rng, num_of_cards);
        //     let encoded_cards = encode_cards_ext(list_of_cards.clone());

        //     for (i, (card, value)) in encoded_cards.iter().enumerate().take(52) {
        //         println!("{:?} -> {:?}", card.0.to_string(), value);
        //     }

        //     let encoded_cards_bytes = serialize_canonical(&list_of_cards)?;
        //     self.send_encoded_cards(&encoded_cards_bytes).await?;
        //     println!("El jugador es el dealer.");
        // } else {
        //     println!("El jugador no es el dealer.");
        // }

        let pk_bytes = serialize_canonical(&player.pk)?;

        let pk_proof: &ProofKeyOwnership = &player.proof_key;
        let pk_proof_bytes = serialize_canonical::<ProofKeyOwnership>(pk_proof)?;

        let test_pk_proof_deserialized =
            deserialize_canonical::<ProofKeyOwnership>(&pk_proof_bytes)?;

        self.num_players += 1;
        self.player_keys_proof_info.lock().unwrap().push((
            player.pk,
            player.proof_key,
            to_bytes![name.as_bytes()].unwrap(),
        ));

        let public_key_info = PublicKeyInfo {
            name: player.name,
            public_key: pk_bytes,
            proof_key: pk_proof_bytes,
        };
        println!("public_key_info serialized: {:?}", player.pk);

        self.send_public_key_info(public_key_info).await?;

        Ok(())
    }
    // Obtener el peer ID localñ
    pub fn local_peer_id(&self) -> PeerId {
        self.peer_id
    }

    // Enviar un mensaje del protocolo
    pub async fn send_message(&self, message: ProtocolMessage) -> Result<(), Box<dyn Error>> {
        self.sender.clone().try_send(message)?;
        Ok(())
    }

    pub async fn send_encoded_cards(&self, encoded_cards: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::EncodedCards(encoded_cards.to_vec()))
            .await
    }

    // Enviar una clave pública
    pub async fn send_public_key(&self, public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::PublicKey(public_key.to_vec()))
            .await
    }

    pub async fn send_public_key_info(
        &self,
        public_key_info: PublicKeyInfo,
    ) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::PublicKeyInfo(public_key_info))
            .await
    }

    // Enviar una prueba
    pub async fn send_proof(&self, proof: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::Proof(proof.to_vec()))
            .await
    }

    // Enviar un token de revelación
    pub async fn send_reveal_token(&self, token: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::RevealToken(token.to_vec()))
            .await
    }

    // Enviar una carta
    pub async fn send_card(&self, card: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::Card(card.to_vec()))
            .await
    }

    // Enviar una acción del juego
    pub async fn send_action(&self, action: GameAction) -> Result<(), Box<dyn Error>> {
        self.send_message(ProtocolMessage::Action(action)).await
    }

    // Recibir un mensaje (bloquea hasta recibir uno)
    pub async fn receive_message(
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    ) -> Option<(PeerId, ProtocolMessage)> {
        let mut receiver = receiver.lock().unwrap();
        futures::executor::block_on(receiver.next())
    }

    // Recibir un tipo específico de mensaje (bloquea hasta recibir uno del tipo deseado)
    pub async fn receive_specific<T, F>(
        &self,
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
        extractor: F,
    ) -> Option<(PeerId, T)>
    where
        F: Fn(&ProtocolMessage) -> Option<T>,
        T: Clone,
    {
        loop {
            if let Some((peer_id, message)) = P2PConnection::receive_message(receiver).await {
                if let Some(extracted) = extractor(&message) {
                    return Some((peer_id, extracted));
                }
            } else {
                return None;
            }
        }
    }

    // Función específica para recibir una clave pública
    pub async fn receive_public_key(
        self: &Self,
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    ) -> Option<(PeerId, Vec<u8>)> {
        self.receive_specific(receiver, |msg| {
            if let ProtocolMessage::PublicKey(key) = msg {
                Some(key.clone())
            } else {
                None
            }
        })
        .await
    }

    // Función específica para recibir una prueba
    pub async fn receive_proof(
        self: &Self,
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    ) -> Option<(PeerId, Vec<u8>)> {
        self.receive_specific(receiver, |msg| {
            if let ProtocolMessage::Proof(proof) = msg {
                Some(proof.clone())
            } else {
                None
            }
        })
        .await
    }

    // Función específica para recibir un token de revelación
    pub async fn receive_reveal_token(
        self: &Self,
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    ) -> Option<(PeerId, Vec<u8>)> {
        self.receive_specific(receiver, |msg| {
            if let ProtocolMessage::RevealToken(token) = msg {
                Some(token.clone())
            } else {
                None
            }
        })
        .await
    }

    // Función específica para recibir una carta
    pub async fn receive_card(
        self: &Self,
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    ) -> Option<(PeerId, Vec<u8>)> {
        self.receive_specific(receiver, |msg| {
            if let ProtocolMessage::Card(card) = msg {
                Some(card.clone())
            } else {
                None
            }
        })
        .await
    }

    // Función específica para recibir una acción del juego
    pub async fn receive_action(
        self: &Self,
        receiver: &Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    ) -> Option<(PeerId, GameAction)> {
        self.receive_specific(receiver, |msg| {
            if let ProtocolMessage::Action(action) = msg {
                Some(action.clone())
            } else {
                None
            }
        })
        .await
    }

    // Función para obtener el valor de is_dealer
    pub fn is_dealer(&self) -> bool {
        self.is_dealer
    }
}

// Función de utilidad para convertir cualquier struct serializable en bytes
pub fn serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(serde_json::to_vec(data)?)
}

// Función de utilidad para convertir bytes en un struct deserializable
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(bytes)?)
}

pub fn deserialize_canonical<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let mut reader = &bytes[..];
    let value = T::deserialize(&mut reader)?;
    Ok(value)
}

pub fn serialize_canonical<T: CanonicalSerialize>(data: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut buffer = Vec::new();
    data.serialize(&mut buffer)?;
    Ok(buffer)
}

// Función para verificar la serialización/deserialización
pub fn verify_serialization<
    T: CanonicalSerialize + CanonicalDeserialize + std::fmt::Debug + PartialEq,
>(
    original: &T,
) -> Result<bool, Box<dyn Error>> {
    // Serializar
    let serialized = serialize_canonical(original)?;

    // Deserializar
    let deserialized = deserialize_canonical::<T>(&serialized)?;

    // Imprimir información detallada para comparación
    println!("Original: {:?}", original);
    println!("Serialized bytes: {:?}", serialized);
    println!("Deserialized: {:?}", deserialized);
    println!("¿Son iguales? {}", original == &deserialized);

    Ok(original == &deserialized)
}
