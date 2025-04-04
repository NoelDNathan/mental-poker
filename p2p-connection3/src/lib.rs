use ark_ff::to_bytes;
use ark_std::rand::thread_rng;
use ark_std::{rand::Rng, One};
use babyjubjub::{EdwardsAffine, EdwardsProjective};
use barnett_smart_card_protocol;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use rand::SeedableRng;

use rand;
use std::collections::HashMap;
use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, generator, Card, CardProtocol, ClassicPlayingCard,
    InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey, RemaskingProof, Scalar,
    ZKProofShuffle,
};

use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
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
    ShuffledAndRemaskedCards(Vec<u8>, Vec<u8>),
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
    sender: mpsc::Sender<ProtocolMessage>,
    receiver: Arc<Mutex<mpsc::Receiver<(PeerId, ProtocolMessage)>>>,
    peer_id: PeerId,
    is_dealer: bool,
    num_players: u8,
    player_keys_proof_info: Arc<Mutex<Vec<(PublicKey, ProofKeyOwnership, Vec<u8>)>>>,
    joint_pk: Arc<Mutex<Option<PublicKey>>>,
    encoded_cards: Arc<Mutex<HashMap<Card, ClassicPlayingCard>>>,
    deck: Arc<Mutex<Vec<MaskedCard>>>,
}

// El comportamiento de red combina Gossipsub y mDNS
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

impl P2PConnection {
    // Inicializa la conexión P2P
    pub async fn init() -> Result<Self, Box<dyn Error>> {
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

        // Leer argumentos de la línea de comandos
        let args: Vec<String> = env::args().collect();
        let is_dealer = args.iter().any(|arg| arg == "--dealer"); // Verificar si el argumento dealer es "yes"

        let mut player_keys_proof_info = Vec::new();
        let player_keys_proof_info_arc = Arc::new(Mutex::new(player_keys_proof_info));
        let player_keys_clone = Arc::clone(&player_keys_proof_info_arc);

        let mut joint_pk = None;
        let joint_pk_arc = Arc::new(Mutex::new(joint_pk));
        let joint_pk_clone = Arc::clone(&joint_pk_arc);

        let deck_arc = Arc::new(Mutex::new(Vec::new()));
        let deck_clone = Arc::clone(&deck_arc);

        let encoded_cards_arc = Arc::new(Mutex::new(HashMap::new()));
        let encoded_cards_clone = Arc::clone(&encoded_cards_arc);

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
                        SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source: peer_id,
                            message_id: _id,
                            message,
                        })) => {
                            match serde_json::from_slice::<ProtocolMessage>(&message.data) {
                                Ok(protocol_message) => {

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
                                            if num_players == 2 {
                                                match CardProtocol::compute_aggregate_key(&parameters, &player_keys_clone.lock().unwrap()) {
                                                    Ok(aggregate_key) => {
                                                        joint_pk = Some(aggregate_key);
                                                        if is_dealer {
                                                            let aggregate_key_clone = aggregate_key.clone();
                                                            // P2PConnection::dealt_cards(&to_swarm_tx, &aggregate_key_clone).await;
                                                        }
                                                    },
                                                    Err(e) => println!("Error computing aggregate key: {:?}", e),
                                                }
                                            }
                                        }
                                    }

                                    if let ProtocolMessage::EncodedCards(encoded_cards_bytes) = protocol_message.clone() {
                                        // Debería verificar que lo envia el dealer
                                        match deserialize_canonical::<Vec<Card>>(&encoded_cards_bytes) {
                                            Ok(decoded_cards) => {
                                                let encode_cards_decoded: HashMap<Card, ClassicPlayingCard> = encode_cards_ext(decoded_cards);
                                                let guard = joint_pk_clone.lock().unwrap();
                                                let joint_pk_val = guard.as_ref().unwrap();
                                                let mut local_rng = rand::thread_rng();

                                                let deck_and_proofs = match encode_cards_decoded
                                                .keys()
                                                .map(|card| CardProtocol::mask(&mut local_rng, &parameters, &joint_pk_val, &card, &Scalar::one()))
                                                .collect::<Result<Vec<_>, _>>() {
                                                    Ok(results) => results,
                                                    Err(e) => {
                                                        println!("Error masking cards: {:?}", e);
                                                        return;
                                                    }
                                                };

                                                let deck = deck_and_proofs
                                                .iter()
                                                .map(|x| x.0)
                                                .collect::<Vec<MaskedCard>>();

                                                for (card, value) in encode_cards_decoded.iter() {
                                                    encoded_cards_clone.lock().unwrap().insert(card.clone(), value.clone());
                                                }

                                                for card in deck.iter() {
                                                    deck_clone.lock().unwrap().push(card.clone());
                                                }

                                                // Debería verificar que son puntos validos de la curva!!!

                                            },
                                            Err(e) => println!("Error deserializing encoded cards: {:?}", e),
                                        }
                                    }

                                    if let ProtocolMessage::ShuffledAndRemaskedCards(shuffled_cards, proof_bytes) = protocol_message.clone() {

                                        let shuffled_cards_decoded = match deserialize_canonical::<Vec<MaskedCard>>(&shuffled_cards) {
                                            Ok(decoded) => decoded,
                                            Err(e) => {
                                                println!("Error deserializing shuffled cards: {:?}", e);
                                                return;
                                            }
                                        };

                                        let proof_decoded = match deserialize_canonical::<ZKProofShuffle>(&proof_bytes) {
                                            Ok(decoded) => decoded,
                                            Err(e) => {
                                                println!("Error deserializing proof: {:?}", e);
                                                return;
                                            }
                                        };

                                        let m = 2;
                                        let n = 26;
                                        let num_of_cards = m * n;
                                        let seed = [0; 32];
                                        let rng = &mut rand::rngs::StdRng::from_seed(seed);
                                        let pp = CardProtocol::setup(rng, generator(), m, n).unwrap();

                                        let guard = joint_pk_clone.lock().unwrap();
                                        let joint_pk_val = guard.as_ref().unwrap();

                                        match CardProtocol::verify_shuffle(&pp, &joint_pk_val, &deck_clone.lock().unwrap(), &shuffled_cards_decoded, &proof_decoded) {
                                            Ok(_) => println!("Shuffle verified successfully!"),
                                            Err(e) => println!("Shuffle verification failed: {:?}", e),
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
                        // Aqui deberíamos recibir las public keys


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
            joint_pk: Arc::clone(&joint_pk_arc),
            encoded_cards: Arc::clone(&encoded_cards_arc),
            deck: Arc::clone(&deck_arc),
        })
    }

    pub async fn dealt_cards(
        sender: &mpsc::Sender<ProtocolMessage>,
        joint_pk: &PublicKey,
    ) -> Result<(), Box<dyn Error>> {
        println!("El jugador es el dealer.");
        let joint_pk_val = joint_pk.clone();
        let m = 2;
        let n = 26;
        let num_of_cards = m * n;
        let seed = [0; 32];
        let rng = &mut rand::rngs::StdRng::from_seed(seed);
        let parameters = CardProtocol::setup(rng, generator(), m, n)?;

        let list_of_cards = generate_list_of_cards(rng, num_of_cards);
        let encoded_cards = encode_cards_ext(list_of_cards.clone());

        for (i, (card, value)) in encoded_cards.iter().enumerate().take(52) {
            println!("{:?} -> {:?}", card.0.to_string(), value);
        }

        let encoded_cards_bytes = serialize_canonical(&list_of_cards)?;
        P2PConnection::send_encoded_cards(&sender, &encoded_cards_bytes).await?;

        let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = encoded_cards
            .keys()
            .map(|card| CardProtocol::mask(rng, &parameters, &joint_pk_val, &card, &Scalar::one()))
            .collect::<Result<Vec<_>, _>>()?;

        let deck = deck_and_proofs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<MaskedCard>>();

        let permutation = Permutation::new(rng, m * n);
        let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

        // (a_shuffled_deck, a_shuffle_proof): (Vec<MaskedCard>, Vec<RemaskingProof>) =
        match CardProtocol::shuffle_and_remask(
            rng,
            &parameters,
            &joint_pk_val,
            &deck,
            &masking_factors,
            &permutation,
        ) {
            Ok((a, b)) => {
                let shuffled_deck: Vec<MaskedCard> = a;
                let shuffle_proof: ZKProofShuffle = b;
                let remasked_bytes = serialize_canonical(&shuffled_deck)?;
                let proof_bytes = serialize_canonical(&shuffle_proof)?;
                P2PConnection::send_message(
                    &sender,
                    ProtocolMessage::ShuffledAndRemaskedCards(remasked_bytes, proof_bytes),
                )
                .await?;
            }
            Err(e) => {
                println!("Error shuffling and remasking: {:?}", e);
                return Err(e.into());
            }
        };

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
        //     // let list_of_cards = encoded_cards.keys().cloned().collect::<Vec<_>>();

        //     let encoded_cards_bytes = serialize_canonical(&list_of_cards)?;
        //     P2PConnection::send_encoded_cards(&self.sender, &encoded_cards_bytes).await?;
        //     println!("El jugador es el dealer.");
        // } else {
        //     println!("El jugador no es el dealer.");
        // }

        let pk_bytes = serialize_canonical(&player.pk)?;

        let pk_proof: &ProofKeyOwnership = &player.proof_key;
        let pk_proof_bytes = serialize_canonical::<ProofKeyOwnership>(pk_proof)?;

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

    pub async fn send_message(
        sender: &mpsc::Sender<ProtocolMessage>,
        message: ProtocolMessage,
    ) -> Result<(), Box<dyn Error>> {
        sender.clone().try_send(message)?;
        Ok(())
    }

    pub async fn send_encoded_cards(
        sender: &mpsc::Sender<ProtocolMessage>,
        encoded_cards: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        P2PConnection::send_message(
            sender,
            ProtocolMessage::EncodedCards(encoded_cards.to_vec()),
        )
        .await
    }

    // Enviar un mensaje del protocolo
    pub async fn send_message_internal(
        &self,
        message: ProtocolMessage,
    ) -> Result<(), Box<dyn Error>> {
        self.sender.clone().try_send(message)?;
        Ok(())
    }

    // Enviar una clave pública
    pub async fn send_public_key(&self, public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message_internal(ProtocolMessage::PublicKey(public_key.to_vec()))
            .await
    }

    pub async fn send_public_key_info(
        &self,
        public_key_info: PublicKeyInfo,
    ) -> Result<(), Box<dyn Error>> {
        self.send_message_internal(ProtocolMessage::PublicKeyInfo(public_key_info))
            .await
    }

    // Enviar una prueba
    pub async fn send_proof(&self, proof: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message_internal(ProtocolMessage::Proof(proof.to_vec()))
            .await
    }

    // Enviar un token de revelación
    pub async fn send_reveal_token(&self, token: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message_internal(ProtocolMessage::RevealToken(token.to_vec()))
            .await
    }

    // Enviar una carta
    pub async fn send_card(&self, card: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_message_internal(ProtocolMessage::Card(card.to_vec()))
            .await
    }

    // Enviar una acción del juego
    pub async fn send_action(&self, action: GameAction) -> Result<(), Box<dyn Error>> {
        self.send_message_internal(ProtocolMessage::Action(action))
            .await
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
