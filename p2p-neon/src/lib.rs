// - CallBack para revelar community card
// - Callback para revelar cartas privadas del jugador
use neon::event::TaskBuilder;
use once_cell::sync::Lazy;
use std::sync::Arc;

use ark_ff::to_bytes;
use ark_std::One;
use babyjubjub::Fr;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use futures::stream::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use neon::prelude::*;
use num_bigint::BigUint;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use rand::thread_rng;
use rand::Rng;
use rand::SeedableRng;
use regex::Regex;
use std::str::FromStr;
use std::sync::Mutex;
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::{io, io::AsyncBufReadExt, select, time::interval};
use tracing_subscriber::EnvFilter;

const ERROR_PLAYER_ID_NOT_SET: &str = "Player ID should be set";
const ERROR_NAME_BYTES_NOT_SET: &str = "name_bytes should be set";
const ERROR_PLAYER_NOT_SET: &str = "Player should be initialized";

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use std::collections::HashMap;

use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, generator, open_card, Bn254Fr, Card, CardParameters,
    CardProtocol, ClassicPlayingCard, InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey,
    RemaskingProof, RevealProof, RevealToken, Scalar, SecretKey, ZKProofShuffle,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use std::{env, thread};

use barnett_smart_card_protocol::error::CardProtocolError;
use zk_reshuffle::{deserialize_proof, serialize_proof, CircomProver, Proof as ZKProofCardRemoval};

// Add new structures for JSON generation
#[derive(Debug, Serialize)]
struct Point {
    x: String,
    y: String,
}

#[derive(Debug, Serialize)]
struct SchnorrProof {
    commitment: Point,
    response: String,
}

#[derive(Debug, Serialize)]
struct ChaumPedersenProof {
    A: Point,
    B: Point,
    r: String,
}

#[derive(Debug, Serialize)]
struct ZKProof {
    proofA: Vec<String>,
    proofB: Vec<Vec<String>>,
    proofC: Vec<String>,
    pubSignals: String,
}

#[derive(Debug, Serialize)]
struct Tokens {
    player1ToPlayer2: PlayerCards,
    player2ToPlayer1: PlayerCards,
    communityCardsFromPlayer1: Vec<Point>,
    communityCardsFromPlayer2: Vec<Point>,
}

#[derive(Debug, Serialize)]
struct PlayerCards {
    card1: Point,
    card2: Point,
}

#[derive(Debug, Serialize)]
struct PokerCryptographyJSON {
    description: String,
    publicKeys: HashMap<String, Point>,
    schnorrProofs: HashMap<String, SchnorrProof>,
    chaumPedersenProofs: HashMap<String, ChaumPedersenProof>,
    zkProofs: HashMap<String, ZKProof>,
    cardMappings: String,
    encryptedCards: String,
    tokens: Tokens,
    generator: Point,
    encGenerator: Point,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyInfoEncoded {
    name: Vec<u8>,
    public_key: Vec<u8>,
    proof_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMessage {
    Text(Vec<u8>),
    Proof(Vec<u8>),
    RevealToken(u8, Vec<u8>, Vec<u8>),
    RevealTokenCommunityCards(Vec<Vec<u8>>, Vec<u8>),
    Card(Vec<u8>),
    EncodedCards(Vec<u8>),
    PublicKeyInfo(PublicKeyInfoEncoded),
    ShuffledAndRemaskedCards(Vec<u8>, Vec<u8>),
    RevealAllCards(Vec<Vec<u8>>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    ZKProofRemoveAndRemaskChunk(u8, u8, Vec<u8>),
    ZKProofRemoveAndRemaskProof(Vec<u8>),
    ZKProofShuffleChunk(u8, u8, Vec<u8>),
    ZKProofShuffleProof(Vec<u8>),
}

pub struct PlayerInfo {
    name: String,
    id: u8,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: [Option<MaskedCard>; 2],
    cards_public: [Option<MaskedCard>; 2],
    reveal_tokens: [Vec<(RevealToken, RevealProof, PublicKey)>; 2],
}

// Guardamos el sender en un static seguro para neon
static CMD_SENDER: Lazy<Mutex<Option<UnboundedSender<String>>>> = Lazy::new(|| Mutex::new(None));

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // Exportamos la tarea asíncrona y el enviador de líneas
    cx.export_function("poker_client_async", poker_client_async)?;
    cx.export_function("send_line", send_line)?;
    Ok(())
}

#[allow(non_snake_case)]
fn poker_client_async(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let verify_public_key = cx.argument::<JsFunction>(1)?;
    let verify_shuffling = cx.argument::<JsFunction>(2)?;
    let verify_reveal_token = cx.argument::<JsFunction>(3)?;
    let cb_comm = cx.argument::<JsFunction>(4)?;
    let cb_priv = cx.argument::<JsFunction>(5)?;

    let verify_public_key = verify_public_key.root(&mut cx);
    let verify_shuffling = verify_shuffling.root(&mut cx);
    let verify_reveal_token = verify_reveal_token.root(&mut cx);
    let set_comm = cb_comm.root(&mut cx);
    let set_priv = cb_priv.root(&mut cx);
    let channel = cx.channel();

    // Creamos el canal Tokio unbounded
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    {
        let mut guard = CMD_SENDER.lock().unwrap();
        *guard = Some(tx);
    }

    // Pasamos `rx` por valor (no &mut) para poder usarlo en el select!
    let promise = cx
        .task(move || {
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(async move {
                poker_client(
                    channel,
                    verify_public_key,
                    verify_shuffling,
                    verify_reveal_token,
                    set_comm,
                    set_priv,
                    rx,
                )
                .await
            })
            .map_err(|e| e.to_string())
        })
        .promise(|mut cx, result| match result {
            Ok(_) => Ok(cx.undefined()),
            Err(e) => cx.throw_error(&e),
        });

    Ok(promise)
}

fn send_line(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let line = cx.argument::<JsString>(0)?.value(&mut cx);
    let guard = CMD_SENDER.lock().unwrap();
    if let Some(tx) = &*guard {
        tx.send(line).unwrap();
    } else {
        panic!("poker_client_async no ha sido llamado aún");
    }
    Ok(cx.undefined())
}

#[allow(non_snake_case)]
async fn poker_client(
    channel: Channel,
    verifyPublicKey: Root<JsFunction>,
    verifyShuffling: Root<JsFunction>,
    verifyRevealToken: Root<JsFunction>,
    setCommunityCard: Root<JsFunction>,
    setPrivateCards: Root<JsFunction>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message
                // signing)
                // .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(MyBehaviour { gossipsub, mdns })
        })?
        .build();

    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("test-net");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    // swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");

    // Añade un HashMap para rastrear los peers y sus nombres
    let m = 2;
    let n = 26;
    let num_of_cards = m * n;
    let seed = [0; 32];
    let rng = &mut rand::rngs::StdRng::from_seed(seed);
    let pp = CardProtocol::setup(rng, generator(), m, n)?;

    let args: Vec<String> = env::args().collect();

    let mut player_id: Option<String> = None;
    let mut name: Option<String> = None; // Player address
    let mut name_bytes: Option<Vec<u8>> = None;

    let mut player: Option<InternalPlayer> = None;

    // Initializate poker game variables
    let mut pk_proof_info_array: Vec<(PublicKey, ProofKeyOwnership, Vec<u8>)> = Vec::new();
    let mut joint_pk: Option<PublicKey> = None;
    let mut card_mapping: Option<HashMap<Card, ClassicPlayingCard>> = None;
    let mut deck: Option<Vec<MaskedCard>> = None;

    // Initialize two provers: one for reshuffle, one for shuffle
    let mut prover_reshuffle = CircomProver::new(
        "../circom-circuit/card_cancellation/card_cancellation_v5.wasm",
        "../circom-circuit/card_cancellation/card_cancellation_v5.r1cs",
        "../circom-circuit/card_cancellation/card_cancellation_v5_0001.zkey",
    )
    .map_err(|e| CardProtocolError::Other(format!("{}", e)))?;

    let mut prover_shuffle = CircomProver::new(
        "../circom-circuit/shuffling/shuffling.wasm",
        "../circom-circuit/shuffling/shuffling.r1cs",
        "../circom-circuit/shuffling/shuffling_0001.zkey",
    )
    .map_err(|e| CardProtocolError::Other(format!("{}", e)))?;

    println!(
        "Prover initialized: {:?}",
        prover_reshuffle.builder.is_some()
    );

    let mut num_players_expected = 2;
    let mut current_dealer = 0;
    let mut players_connected = 1;
    let mut current_shuffler = 0;
    let mut current_reshuffler = 0;

    let mut num_received_reveal_tokens = 0;
    let mut received_reveal_tokens1: Vec<(RevealToken, RevealProof, PublicKey)> = Vec::new();
    let mut received_reveal_tokens2: Vec<(RevealToken, RevealProof, PublicKey)> = Vec::new();

    let mut community_cards_tokens: Vec<Vec<(RevealToken, RevealProof, PublicKey)>> =
        vec![Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];

    // Estructura para rastrear la última vez que se vio actividad de cada peer
    let mut peer_last_seen: HashMap<libp2p::PeerId, Instant> = HashMap::new();

    // Intervalo para verificar peers inactivos (cada 10 segundos)
    let mut heartbeat_interval = interval(Duration::from_secs(1));

    // Tiempo máximo sin actividad antes de considerar a un peer desconectado (30 segundos)
    let timeout_duration = Duration::from_secs(10);

    let mut connected_peers: HashMap<libp2p::PeerId, PlayerInfo> = HashMap::new();

    let mut public_reshuffle_bytes: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut proof_reshuffle_bytes: Vec<u8> = Vec::new();

    let mut is_reshuffling = false;
    let mut is_all_public_reshuffle_bytes_received = false;

    let verifyPublicKey = Arc::new(verifyPublicKey);
    let verifyShuffling = Arc::new(verifyShuffling);
    let verifyRevealToken = Arc::new(verifyRevealToken);
    let setPrivateCards = Arc::new(setPrivateCards);
    let setCommunityCard = Arc::new(setCommunityCard);

    // Add new variables for shuffle proof chunks
    let mut public_shuffle_bytes: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut proof_shuffle_bytes: Vec<u8> = Vec::new();
    let mut is_all_public_shuffle_bytes_received = false;

    // Kick it off
    loop {
        let setPrivateCards = Arc::clone(&setPrivateCards);
        let verifyPublicKey = Arc::clone(&verifyPublicKey);
        let verifyShuffling = Arc::clone(&verifyShuffling);
        let verifyRevealToken = Arc::clone(&verifyRevealToken);
        let setCommunityCard = Arc::clone(&setCommunityCard);

        tokio::select! {
            _ = heartbeat_interval.tick() => {
                // Aquí puedes agregar la lógica para verificar la actividad de los peers
                let now = Instant::now();
                let mut disconnected_peers = Vec::new();

                if connected_peers.len() > 0{
                    if let Err(e) = send_protocol_message(&mut swarm, &topic, &ProtocolMessage::Ping(vec![])) {
                        println!("Error sending ping: {:?}", e);
                    }
                }

                for (peer_id, last_seen) in &peer_last_seen {
                    // println!("peer {} has been seen: {:?}", peer_id, last_seen);

                    if now.duration_since(*last_seen) > timeout_duration && !is_reshuffling{
                        disconnected_peers.push(*peer_id);
                        // println!("Peer desconectado: {}", peer_id);
                    }
                }

                // println!("Connected peers: {:?}", connected_peers);
                // Procesar peers desconectados
                for peer_id in disconnected_peers {
                    println!("disconnected:{}", peer_id);
                    // println!("connected_peers {:?}", connected_peers);
                    if let Some(player_info) = connected_peers.remove(&peer_id) {
                        println!(
                            "¡Jugador desconectado por inactividad!: {} ({})",
                            player_info.name, peer_id
                        );
                        players_connected -= 1;
                        peer_last_seen.remove(&peer_id);
                        is_reshuffling = true;
                        match handle_disconnected_player(rng,
                            &mut swarm,
                            &topic,
                            &mut prover_reshuffle,
                            &pp,
                            &mut deck,
                            &mut card_mapping,
                            player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET),
                            &player.as_ref().expect(ERROR_PLAYER_NOT_SET),
                            &mut joint_pk,
                            &connected_peers,
                            current_dealer){
                            Ok((reshuffled_deck, aggregate_key, current_reshuffler_val)) => {
                                deck = Some(reshuffled_deck);
                                joint_pk = Some(aggregate_key);
                                current_reshuffler = current_reshuffler_val;
                                num_players_expected -=1;
                            }
                            Err(e) => {
                                println!("Error handling disconnected player: {:?}", e);
                            }
                        }
                    }

                }
            }
            Some(cmd) = rx.recv() => {

                    match cmd.as_str() {
                        "exit" | "q" => {
                            println!("(Rust) >> Exit command received, terminating client");
                            break;
                        }

                        "sendPublicKey" => {
                            if let Some((command, player_address)) = cmd.split_once(' ') {
                                if command == "sendPublicKey" {
                                    name = Some(player_address.to_string());
                                    name_bytes = Some(to_bytes![player_address.as_bytes()].unwrap());
                                    let rng2 = &mut thread_rng();
                                    let mut _player = InternalPlayer::new(rng2, &pp, &name_bytes.as_ref().expect(ERROR_NAME_BYTES_NOT_SET)).expect("Failed to create player");
                                    player = Some(_player.clone());

                                    // 1) enviar public key info
                                    println!("(Rust) >> Enviando PublicKeyInfo");

                                    let player_clone = player.as_ref().expect(ERROR_PLAYER_NOT_SET).clone();
                                    let _ = channel.send(move |mut cx| {
                                        let cb = verifyPublicKey.clone();
                                        let this = cx.undefined();

                                        let r = cx.string(format!("{:?}", player_clone.proof_key.random_commit.to_string()));
                                        let s = cx.string(format!("{:?}", player_clone.proof_key.opening.to_string()));

                                        let public_key_value = cx.string(format!("{:?}", player_clone.pk.to_string()));
                                        let args = vec![public_key_value.upcast::<JsValue>(), r.upcast::<JsValue>(), s.upcast::<JsValue>()];
                                        cb.to_inner(&mut cx).call(&mut cx, this, args)?;
                                        Ok(())
                                    });


                                    let public_key_info = PublicKeyInfoEncoded {
                                        name: name_bytes.as_ref().expect(ERROR_NAME_BYTES_NOT_SET).clone(),
                                        public_key: serialize_canonical(&player.as_ref().expect(ERROR_PLAYER_NOT_SET).pk).unwrap(),
                                        proof_key: serialize_canonical(&player.as_ref().expect(ERROR_PLAYER_NOT_SET).proof_key).unwrap(),
                                    };
                                    let message = ProtocolMessage::PublicKeyInfo(public_key_info);
                                    if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                        println!("Error sending public key info: {:?}", e);
                                    }



                                }
                            } else {
                                println!("Error: setPlayerId requiere un argumento");
                            }
                        }
                        "setPlayerId" => {
                            if let Some((command, player_id_arg)) = cmd.split_once(' ') {
                                if command == "setPlayerId" {
                                    player_id = Some(player_id_arg.to_string());
                                }
                            } else {
                                println!("Error: setPlayerId requiere un argumento");
                            }
                        }
                        "flop" => {
                            println!("(Rust) >> Flop!");
                            if let Some(current_deck) = &deck {
                                let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                let reveal_token_flop1: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[0])?;
                                let reveal_token_flop2: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[1])?;
                                let reveal_token_flop3: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[2])?;

                                let reveal_token_flop1_bytes = serialize_canonical(&reveal_token_flop1)?;
                                let reveal_token_flop2_bytes = serialize_canonical(&reveal_token_flop2)?;
                                let reveal_token_flop3_bytes = serialize_canonical(&reveal_token_flop3)?;

                                let message = ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_flop1_bytes, reveal_token_flop2_bytes, reveal_token_flop3_bytes], vec![0, 1, 2]);


                                if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                    println!("Error sending reveal token community cards: {:?}", e);
                                }
                            }
                            else{
                                println!("No se puede revelar la carta: deck aún no está inicializada");
                            }
                        }
                        "turn" => {
                            println!("(Rust) >> Turn!");
                            if let Some(current_deck) = &deck {
                                let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                let reveal_token_turn: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[3])?;

                                let reveal_token_turn_bytes = serialize_canonical(&reveal_token_turn)?;

                                let message = ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_turn_bytes], vec![3]);

                                if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                    println!("Error sending reveal token community cards: {:?}", e);
                                }
                            }
                            else{
                                println!("No se puede revelar la carta: deck aún no está inicializada");
                            }
                        }
                        "river" => {
                            println!("(Rust) >> River!");
                            if let Some(current_deck) = &deck {
                                let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                let reveal_token_river: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[4])?;

                                let reveal_token_river_bytes = serialize_canonical(&reveal_token_river)?;

                                let message = ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_river_bytes], vec![4]);

                                if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                    println!("Error sending reveal token community cards: {:?}", e);
                                }
                            }
                            else{
                                println!("No se puede revelar la carta: deck aún no está inicializada");
                            }
                        }
                        "reveal_all_cards" => {
                            if let Some(current_deck) = &deck {
                                let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                let mut reveal_all_cards_bytes = vec![];
                                for card in current_deck {
                                    let reveal_token: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &card)?;
                                    let reveal_token_bytes = serialize_canonical(&reveal_token)?;
                                    reveal_all_cards_bytes.push(reveal_token_bytes);
                                }
                                let message = ProtocolMessage::RevealAllCards(reveal_all_cards_bytes);
                                if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                    println!("Error sending reveal all cards: {:?}", e);
                                }
                            }
                            else{
                                println!("No se puede revelar la carta: deck aún no está inicializada");
                            }
                        }
                        "generate_json" => {
                            println!("(Rust) >> Generating cryptography JSON...");
                            let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                            let player_id = player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET);
                            match generate_cryptography_json(
                                &connected_peers,
                                &player,
                                &pp,
                                &deck,
                                &card_mapping,
                                &community_cards_tokens,
                                &public_shuffle_bytes,
                                &proof_shuffle_bytes,
                                &public_reshuffle_bytes,
                                &proof_reshuffle_bytes,
                            ) {
                                Ok(json) => {
                                    let filename = format!("poker_cryptography_{}.json", player_id);
                                    if let Err(e) = save_cryptography_json(&json, &filename) {
                                        println!("Error saving JSON: {:?}", e);
                                    } else {
                                        println!("Cryptography JSON generated and saved successfully!");
                                    }
                                }
                                Err(e) => {
                                    println!("Error generating JSON: {:?}", e);
                                }
                            }
                        }
                        other => eprintln!("Comando desconocido: {}", other),
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
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Conexión establecida con peer: {peer_id}");
                    peer_last_seen.insert(peer_id, Instant::now());
                    // Aquí solo registramos la conexión, el nombre se asociará cuando recibamos su PublicKeyInfo
                },

                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    if let Some(player_info) = connected_peers.remove(&peer_id) {
                        println!("¡Jugador desconectado!: {} ({})", player_info.name, peer_id);
                        players_connected -= 1;
                        peer_last_seen.remove(&peer_id);
                        is_reshuffling = true;

                         match handle_disconnected_player(rng,
                            &mut swarm, &topic,
                            &mut prover_reshuffle,
                            &pp,
                            &mut deck,
                            &mut card_mapping,
                            &player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET),
                            &player.as_ref().expect(ERROR_PLAYER_NOT_SET),
                            &mut joint_pk,
                            &connected_peers,
                            current_dealer){
                            Ok((reshuffled_deck, aggregate_key, current_reshuffler_val)) => {
                                deck = Some(reshuffled_deck);
                                joint_pk = Some(aggregate_key);
                                current_reshuffler = current_reshuffler_val;
                                num_players_expected -=1;
                            }
                            Err(e) => {
                                println!("Error handling disconnected player: {:?}", e);
                            }
                        }
                    } else {
                        println!("Conexión cerrada con peer desconocido: {peer_id}");
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    peer_last_seen.insert(peer_id, Instant::now());
                    match serde_json::from_slice::<ProtocolMessage>(&message.data) {
                        Ok(protocol_message) => {
                            match protocol_message {
                                ProtocolMessage::Text(text) => {
                                    let text_str = String::from_utf8(text).unwrap();

                                    println!("Got Text message: {:?}", text_str);
                                }
                                ProtocolMessage::PublicKeyInfo(public_key_info) => {

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

                                    name = String::from_utf8(public_key_info.name.clone()).unwrap_or_default();


                                    if let (Some(pk_val), Some(proof_val)) = (pk, proof_key) {
                                        players_connected += 1;
                                        let name_bytes = to_bytes![name.as_bytes()].unwrap();
                                        pk_proof_info_array.push((pk_val, proof_val, name_bytes));

                                        let new_player_id = match name.strip_prefix("Player ") {
                                            Some(id_str) => id_str.parse::<u8>().unwrap_or(players_connected as u8),
                                            None => players_connected as u8,
                                        };


                                        println!("Number of players: {:?}", players_connected);

                                        match CardProtocol::verify_key_ownership(&pp, &pk_val, &name.as_bytes(), &proof_val){
                                            Ok(_) => {
                                                // Asocia el nombre del jugador con su peer_id
                                                connected_peers.insert(peer_id, PlayerInfo{name: name.clone(), id: new_player_id , pk: pk_val.clone(), proof_key: proof_val.clone(), cards: [None, None], cards_public: [None, None], reveal_tokens: [vec![], vec![]]});
                                            },
                                            Err(e) => println!("Error verifying proof key ownership: {:?}", e),
                                        }

                                        if players_connected == num_players_expected {
                                            let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                            let player_id = player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET);

                                            pk_proof_info_array.push((player.pk, player.proof_key, player.name.clone()));
                                            match CardProtocol::compute_aggregate_key(&pp, &pk_proof_info_array) {
                                                Ok(aggregate_key) => {
                                                    joint_pk = Some(aggregate_key);
                                                    println!("Joint public key: {:?}", aggregate_key.to_string());

                                                    if is_dealer(current_dealer, &player_id){
                                                        println!("All players connected, starting game");
                                                        let (shuffled_deck, card_mapping_val) = dealt_cards(&mut swarm, &topic, &mut prover_shuffle, &pp, rng, &aggregate_key, Some(&channel), Some(&verifyShuffling)).unwrap();
                                                        deck = Some(shuffled_deck.clone());
                                                        card_mapping = Some(card_mapping_val);
                                                    }
                                                },
                                                Err(e) => println!("Error computing aggregate key: {:?}", e),
                                            }
                                        }
                                    }


                                }
                                ProtocolMessage::EncodedCards(card_mapping_bytes) => {
                                    println!("Got encoded cards");
                                    let list_of_cards = deserialize_canonical::<Vec<Card>>(&card_mapping_bytes)?;

                                    card_mapping = Some(encode_cards_ext(list_of_cards.clone()));
                                    // for (i, (card, value)) in card_mapping.as_ref().unwrap().iter().enumerate().take(52) {
                                    //     println!("{:?} -> {:?}", card.0.to_string(), value);
                                    // }



                                    if let Some(pk) = &joint_pk {
                                        let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards.iter()
                                            .map(|card| CardProtocol::mask(rng, &pp, pk, &card, &Scalar::one()))
                                            .collect::<Result<Vec<_>, _>>()?;

                                        deck = Some(deck_and_proofs
                                            .iter()
                                            .map(|x| x.0)
                                            .collect::<Vec<MaskedCard>>());
                                    } else {
                                        println!("No se puede procesar las cartas: joint_pk aún no está inicializada");
                                    }
                                }
                                ProtocolMessage::ShuffledAndRemaskedCards(remasked_bytes, proof_bytes) => {
                                    println!("Got shuffled and remasked cards");
                                    let remasked_cards = deserialize_canonical::<Vec<MaskedCard>>(&remasked_bytes)?;
                                    let proof = deserialize_canonical::<ZKProofShuffle>(&proof_bytes)?;

                                    if let Some(pk) = &joint_pk {
                                        if let Some(current_deck) = &deck {
                                            match CardProtocol::verify_shuffle(&pp, &pk, &current_deck, &remasked_cards, &proof){
                                                Ok(_) => {
                                                    deck = Some(remasked_cards.clone());


                                                current_shuffler += 1;

                                                if current_shuffler == player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).parse::<usize>().unwrap(){
                                                    let shuffle_deck = shuffle_remask_and_send(&mut swarm, &topic, &mut prover_shuffle, &pp, &joint_pk.as_ref().unwrap(), rng, &remasked_cards, m, n, Some(&channel), Some(&verifyShuffling) ).unwrap();
                                                    deck = Some(shuffle_deck);
                                                }

                                                if current_shuffler == num_players_expected - 1
                                                {
                                                    if is_reshuffling {
                                                        is_reshuffling = false;
                                                    } else {
                                                        current_shuffler = 0;
                                                        println!("All players shuffled, revealing cards");
                                                        let id = player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).parse::<u8>().unwrap();
                                                        if let Some(deck) = &deck {
                                                            let player = player.as_mut().expect(ERROR_PLAYER_NOT_SET);
                                                            player.receive_card(deck[id as usize * 2 + 5]);
                                                            player.receive_card(deck[id as usize * 2 + 1 + 5]);
                                                            for i in 0..num_players_expected{
                                                                if i == id as usize{
                                                                    continue;
                                                                }

                                                                    let card1 = deck[i as usize * 2 + 5];
                                                                    let card2 = deck[i as usize * 2 + 5 + 1];
                                                                    // encuentra el player con la id igual a i, y asignale las cartas
                                                                    let peer_id_to_update = connected_peers.iter()
                                                                        .find(|(_, player_info)| player_info.id == i as u8)
                                                                        .map(|(peer_id, _)| *peer_id);

                                                                    if let Some(peer_id) = peer_id_to_update {
                                                                        println!("Found player with id {}", i);
                                                                        if let Some(player_info_mut) = connected_peers.get_mut(&peer_id) {
                                                                            player_info_mut.cards = [Some(card1), Some(card2)];
                                                                        }
                                                                    }

                                                                    let reveal_token1: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &card1)?;
                                                                    let reveal_token2: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &card2)?;
                                                                    let reveal_token1_bytes = serialize_canonical(&reveal_token1)?;
                                                                    let reveal_token2_bytes = serialize_canonical(&reveal_token2)?;

                                                                    // No se puede clonar el token, y necesitaba usarlo dos veces
                                                                    let new_token1 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token1_bytes)?;
                                                                    let new_token2 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token2_bytes)?;

                                                                    println!("Pushing reveal tokens to player {}", i);

                                                                    match find_player_by_id(&mut connected_peers, i as u8){
                                                                        Some((peer_id, player_info)) => {
                                                                            player_info.reveal_tokens[0].push(new_token1);
                                                                            player_info.reveal_tokens[1].push(new_token2);
                                                                        }
                                                                        None => {
                                                                            println!("No se encontró al jugador con id {}", i);
                                                                        }
                                                                    }

                                                                    println!("send Reveal token 1 from {:?} to {:?}: {:?}", player_id, i , reveal_token1.0.0.to_string());
                                                                    println!("send Reveal token 2 from {:?} to {:?}: {:?}", player_id, i , reveal_token2.0.0.to_string());

                                                                    let message = ProtocolMessage::RevealToken(i as u8, reveal_token1_bytes, reveal_token2_bytes);
                                                                    if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                                                        println!("Error sending reveal token: {:?}", e);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                println!("Shuffle verified")
                                            },
                                                Err(e) => println!("Error verifying shuffle: {:?}", e),
                                            }

                                        } else {
                                            println!("No se puede verificar el shuffle: deck aún no está inicializada");
                                        }
                                    } else {
                                        println!("No se puede verificar el shuffle: joint_pk aún no está inicializada");
                                    }

                                }
                                ProtocolMessage::RevealToken(id, reveal_token1_bytes, reveal_token2_bytes) => {
                                    if id != player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).parse::<u8>().unwrap(){
                                        let reveal_token1 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token1_bytes)?;
                                        let reveal_token2 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token2_bytes)?;

                                        match find_player_by_id(&mut connected_peers, id) {
                                            Some((peer_id_ref, player_info)) => {
                                                    println!("Received reveal token from player {}", id);
                                                    println!("Received reveal token from player {}", id);
                                                    player_info.reveal_tokens[0].push(reveal_token1);
                                                    player_info.reveal_tokens[1].push(reveal_token2);

                                                                                            if player_info.reveal_tokens[0].len() == num_players_expected -1{

                                            println!("Todos los tokens recibidos para el jugador {}", player_info.id);

                                            let card1 = player_info.cards[0];
                                            let card2 = player_info.cards[1];
                                            if let (Some(card1), Some(card2)) = (card1, card2) {

                                                match CardProtocol::partial_unmask(&pp, &player_info.reveal_tokens[0], &card1) {
                                                    Ok(opened_card1) => player_info.cards_public[0] = Some(opened_card1),
                                                    Err(e) => println!("Error al revelar la carta 1: {:?}", e)
                                                }

                                                match CardProtocol::partial_unmask(&pp, &player_info.reveal_tokens[1], &card2) {
                                                    Ok(opened_card2) => player_info.cards_public[1] = Some(opened_card2),
                                                    Err(e) => println!("Error al revelar la carta 2: {:?}", e)
                                                }
                                            }

                                            // Auto-generate JSON when all cards are revealed
                                            if let Ok(json) = generate_cryptography_json(
                                                &connected_peers,
                                                &player.as_ref().expect(ERROR_PLAYER_NOT_SET),
                                                &pp,
                                                &deck,
                                                &card_mapping,
                                                &community_cards_tokens,
                                                &public_shuffle_bytes,
                                                &proof_shuffle_bytes,
                                                &public_reshuffle_bytes,
                                                &proof_reshuffle_bytes,
                                            ) {
                                                let filename = format!("poker_cryptography_auto_{}.json", player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET));
                                                if let Err(e) = save_cryptography_json(&json, &filename) {
                                                    println!("Error auto-saving JSON: {:?}", e);
                                                } else {
                                                    println!("Auto-generated cryptography JSON saved!");
                                                }
                                            }
                                        }
                                                }
                                            None => {
                                                panic!("Error: No se encontró al jugador con id {}", current_reshuffler)
                                            }
                                        }
                                        continue;
                                    }
                                    println!("Got reveal token");
                                    let reveal_token1 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token1_bytes)?;
                                    let reveal_token2 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token2_bytes)?;

                                    println!("Received reveal token 1 length: {:?}", received_reveal_tokens1.len());
                                    received_reveal_tokens1.push(reveal_token1);
                                    received_reveal_tokens2.push(reveal_token2);

                                    num_received_reveal_tokens += 1;

                                    if num_received_reveal_tokens == num_players_expected - 1 {
                                        println!("All tokens received, revealing cards");
                                        let player_id = player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).parse::<usize>().unwrap();
                                        let index1 = player_id * 2 + 5;
                                        let index2 = player_id * 2 + 1 + 5;

                                        if let Some(card_mapping) = &card_mapping {
                                            if let Some(deck) = &deck {
                                                // Peek at both cards first
                                                let player = player.as_mut().expect(ERROR_PLAYER_NOT_SET);
                                                let card1_result = player.peek_at_card(&pp, &mut received_reveal_tokens1, &card_mapping, &deck[index1 as usize]);
                                                let card2_result = player.peek_at_card(&pp, &mut received_reveal_tokens2, &card_mapping, &deck[index2 as usize]);

                                                // Check if both cards were successfully peeked
                                                match (card1_result, card2_result) {
                                                    (Ok(card1), Ok(card2)) => {
                                                        println!("Card 1: {:?}", card1);
                                                        println!("Card 2: {:?}", card2);
                                                        println!("Both cards revealed successfully");

                                                        let setPrivateCards_clone = Arc::clone(&setPrivateCards);
                                                        let _ = channel.send(move |mut cx| {
                                                            let cb = setPrivateCards_clone.clone();
                                                            let this = cx.undefined();

                                                            // Create an array with both cards
                                                            let cards_array = cx.empty_array();
                                                            let card1_value = cx.string(format!("{:?}", card1));
                                                            let card2_value = cx.string(format!("{:?}", card2));
                                                            cards_array.set(&mut cx, 0, card1_value)?;
                                                            cards_array.set(&mut cx, 1, card2_value)?;

                                                            let args = vec![cards_array.upcast::<JsValue>()];
                                                            cb.to_inner(&mut cx).call(&mut cx, this, args)?;
                                                            Ok(())
                                                        });
                                                    },
                                                    (Err(e1), Ok(_)) => println!("Error peeking at card 1: {:?}", e1),
                                                    (Ok(_), Err(e2)) => println!("Error peeking at card 2: {:?}", e2),
                                                    (Err(e1), Err(e2)) => println!("Error peeking at both cards: {:?}, {:?}", e1, e2),
                                                }
                                            }
                                            else {
                                                println!("No se puede revelar la carta: deck aún no está inicializada");
                                            }
                                        }
                                        else{
                                            println!("No se puede revelar la carta: card_mapping aún no está inicializada");
                                        }
                                    }
                                }
                                ProtocolMessage::RevealTokenCommunityCards(reveal_token_bytes, index_bytes) => {
                                    println!("Got reveal token community cards");

                                    // Deserializar cada token de revelación individualmente
                                    for i in 0..reveal_token_bytes.len() {
                                        let token_bytes = &reveal_token_bytes[i];
                                        let index = index_bytes[i] as usize;

                                        let token = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&token_bytes)?;
                                        community_cards_tokens[index].push(token);

                                        if community_cards_tokens[index].len() == num_players_expected - 1 {
                                            println!("All tokens received, revealing cards");
                                            if let Some(card_mapping) = &card_mapping {
                                                if let Some(deck) = &deck {
                                                    let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                                    match player.compute_reveal_token(rng, &pp, &deck[index]) {
                                                        Ok(token) => {
                                                            community_cards_tokens[index].push(token);
                                                            match open_card(&pp, &community_cards_tokens[index], &card_mapping, &deck[index]) {
                                                                Ok(card) => {
                                                                    println!("Card xxx: {:?}", card);

                                                                    let setCommunityCard_clone = Arc::clone(&setCommunityCard);
                                                                    let _ = channel.send(move |mut cx| {
                                                                        let cb = setCommunityCard_clone.clone();
                                                                        let this = cx.undefined();
                                                                        let index_value = cx.string(format!("{:?}", index));
                                                                        let card_value = cx.string(format!("{:?}", card));
                                                                        let args = vec![index_value.upcast::<JsValue>(), card_value.upcast::<JsValue>()];
                                                                        cb.to_inner(&mut cx).call(&mut cx, this, args)?;
                                                                        Ok(())
                                                                    });

                                                                    // Auto-generate JSON after community card is revealed
                                                                    if let Ok(json) = generate_cryptography_json(
                                                                        &connected_peers,
                                                                        &player,
                                                                        &pp,
                                                                        &Some(deck.clone()),
                                                                        &Some(card_mapping.clone()),
                                                                        &community_cards_tokens,
                                                                        &public_shuffle_bytes,
                                                                        &proof_shuffle_bytes,
                                                                        &public_reshuffle_bytes,
                                                                        &proof_reshuffle_bytes,
                                                                    ) {
                                                                        let filename = format!("poker_cryptography_community_{}_{}.json", player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET), index);
                                                                        if let Err(e) = save_cryptography_json(&json, &filename) {
                                                                            println!("Error auto-saving community card JSON: {:?}", e);
                                                                        } else {
                                                                            println!("Auto-generated community card cryptography JSON saved!");
                                                                        }
                                                                    }

                                                                }
                                                                Err(e) => println!("Error opening card: {:?}", e),
                                                            }
                                                        }
                                                        Err(e) => println!("Error computing reveal token: {:?}", e),
                                                    }
                                                }
                                                else {
                                                    println!("No se puede revelar la carta: deck aún no está inicializada");
                                                }
                                            }
                                            else {
                                                println!("No se puede revelar la carta: card_mapping aún no está inicializada");
                                            }

                                        }
                                    }
                                }
                                ProtocolMessage::RevealAllCards(reveal_all_cards_bytes) => {
                                    println!("Got reveal all cards");

                                    if let Some(deck) = &deck {
                                        if let Some(card_mapping) = &card_mapping {
                                            let player = player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                                            for i in 0..reveal_all_cards_bytes.len() {
                                                let reveal_token = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_all_cards_bytes[i])?;
                                                let player_token = player.compute_reveal_token(rng, &pp, &deck[i as usize])?;
                                                let tokens = vec![reveal_token, player_token];
                                                let card = open_card(&pp, &tokens, &card_mapping, &deck[i as usize])?;
                                                // println!("Card: {:?}", card);
                                            }
                                        }
                                        else{
                                            println!("No se puede revelar la carta: card_mapping aún no está inicializada");
                                        }
                                    }
                                    else{
                                        println!("No se puede revelar la carta: deck aún no está inicializada");
                                    }
                                }
                                ProtocolMessage::ZKProofRemoveAndRemaskChunk(i, length, chunk) => {
                                    public_reshuffle_bytes.push((i, chunk.clone()));

                                    if i == length - 1{
                                        is_all_public_reshuffle_bytes_received = true;
                                        if proof_reshuffle_bytes.len() > 0 {
                                            println!("No proof reshuffle bytes");
                                        }
                                        else if proof_reshuffle_bytes.len() == 1 {

                                            match process_reshuffle_verification(
                                                &mut connected_peers,
                                                current_reshuffler,
                                                &mut swarm,
                                                &topic,
                                                &mut prover_shuffle,
                                                &mut prover_reshuffle,
                                                &pp,
                                                &mut card_mapping,
                                                &public_reshuffle_bytes,
                                                &proof_reshuffle_bytes,
                                                joint_pk.as_ref().unwrap(),
                                                deck.as_ref().unwrap(),
                                                &player.as_ref().expect(ERROR_PLAYER_NOT_SET),
                                                &player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET),
                                                current_dealer,
                                                m,
                                                n,
                                                rng,
                                                Some(&channel),
                                                Some(&verifyShuffling),
                                            ){
                                                Ok((reshuffled_deck, new_reshuffler)) => {
                                                    deck = Some(reshuffled_deck);
                                                    current_reshuffler = new_reshuffler;
                                                }
                                                Err(e) => {
                                                    println!("Error en proceso de verificación de reshuffle: {:?}", e);
                                                }
                                            }
                                        }
                                        else{
                                            println!("No proof reshuffle bytes");
                                        }
                                    }
                                }
                                ProtocolMessage::ZKProofRemoveAndRemaskProof(proof_bytes) => {
                                    proof_reshuffle_bytes = proof_bytes;

                                    if is_all_public_reshuffle_bytes_received {
                                        match process_reshuffle_verification(
                                            &mut connected_peers,
                                            current_reshuffler,
                                            &mut swarm,
                                            &topic,
                                            &mut prover_shuffle,
                                            &mut prover_reshuffle,
                                            &pp,
                                            &mut card_mapping,
                                            &public_reshuffle_bytes,
                                            &proof_reshuffle_bytes,
                                            joint_pk.as_ref().unwrap(),
                                            deck.as_ref().unwrap(),
                                            &player.as_ref().expect(ERROR_PLAYER_NOT_SET),
                                            &player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET),
                                            current_dealer,
                                            m,
                                            n,
                                            rng,
                                            Some(&channel),
                                            Some(&verifyShuffling),
                                        ) {
                                            Ok((reshuffled_deck, new_reshuffler)) => {
                                                deck = Some(reshuffled_deck);
                                                current_reshuffler = new_reshuffler;
                                            }
                                            Err(e) => {
                                                println!("Error en proceso de verificación de reshuffle: {:?}", e);
                                            }
                                        }
                                    } else {
                                        println!("No all public reshuffle bytes");
                                    }
                                }

                                // Handle new shuffle proof chunk messages
                                ProtocolMessage::ZKProofShuffleChunk(i, length, chunk) => {
                                    public_shuffle_bytes.push((i, chunk.clone()));

                                    if i == length - 1 {
                                        is_all_public_shuffle_bytes_received = true;
                                        if proof_shuffle_bytes.is_empty() {
                                            println!("No shuffle proof bytes yet");
                                        } else {
                                            if validate_chunks(&public_shuffle_bytes, length) {
                                            // Call process_shuffle_verification here
                                            match process_shuffle_verification(
                                                &mut prover_shuffle,
                                                &pp,
                                                joint_pk.as_ref().unwrap(),
                                                &mut deck,
                                                &public_shuffle_bytes,
                                                &proof_shuffle_bytes,
                                                &mut current_shuffler,
                                                &player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET),
                                                num_players_expected,
                                                &mut player.as_mut().expect(ERROR_PLAYER_NOT_SET),
                                                &mut connected_peers,
                                                &mut swarm,
                                                &topic,
                                                rng,
                                                m,
                                                n,
                                                Some(&channel),
                                                Some(&verifyShuffling),
                                                Some(&verifyRevealToken),
                                            ) {
                                                Ok(_) => {
                                                    println!("Shuffle verification completed");
                                                }
                                                Err(e) => {
                                                    println!("Error in shuffle verification: {:?}", e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                ProtocolMessage::ZKProofShuffleProof(proof_bytes) => {
                                    proof_shuffle_bytes = proof_bytes;
                                    if is_all_public_shuffle_bytes_received {
                                        match process_shuffle_verification(
                                            &mut prover_shuffle,
                                            &pp,
                                            joint_pk.as_ref().unwrap(),
                                            &mut deck,
                                            &public_shuffle_bytes,
                                            &proof_shuffle_bytes,
                                            &mut current_shuffler,
                                            &player_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET),
                                            num_players_expected,
                                            &mut player.as_mut().expect(ERROR_PLAYER_NOT_SET),
                                            &mut connected_peers,
                                            &mut swarm,
                                            &topic,
                                            rng,
                                            m,
                                            n,
                                            Some(&channel),
                                            Some(&verifyShuffling),
                                            Some(&verifyRevealToken),
                                        ) {
                                            Ok(_) => {
                                                println!("Shuffle verification completed");
                                            }
                                            Err(e) => {
                                                println!("Error in shuffle verification: {:?}", e);
                                            }
                                        }
                                    } else {
                                        println!("Not all public shuffle bytes received yet");
                                    }
                                }
                                ProtocolMessage::Ping(ping_data) => {
                                    // Responder con un pong
                                    if let Err(e) = send_protocol_message(&mut swarm, &topic, &ProtocolMessage::Pong(ping_data.clone())) {
                                        println!("Error enviando pong: {:?}", e);
                                    }
                                },
                                ProtocolMessage::Pong(_) => {
                                    // No necesitamos hacer nada especial aquí, ya actualizamos peer_last_seen arriba
                                },
                                _ => {}
                            }
                        }
                        Err(e) => {
                            println!("Error deserializing protocol message: {:?}", e);
                        }
                    }
                },

                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }

        }
    }
    println!("(Rust) >> Terminando cliente");
    Ok(())
}

fn find_player_by_id(
    connected_peers: &mut HashMap<libp2p::PeerId, PlayerInfo>,
    id: u8,
) -> Option<(&libp2p::PeerId, &mut PlayerInfo)> {
    connected_peers
        .iter_mut()
        .find(|(_, player_info)| player_info.id == id)
        .map(|(peer_id, player_info)| (peer_id, player_info))
}

fn dealt_cards(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    prover_shuffle: &mut CircomProver,
    pp: &CardParameters,
    rng: &mut rand::rngs::StdRng,
    joint_pk: &PublicKey,
    channel: Option<&Channel>,
    verifyShuffling: Option<&Arc<Root<JsFunction>>>,
) -> Result<(Vec<MaskedCard>, HashMap<Card, ClassicPlayingCard>), Box<dyn Error>> {
    let m = 2;
    let n = 26;
    let num_of_cards = m * n;

    println!("El jugador es el dealer.");

    let list_of_cards = generate_list_of_cards(rng, num_of_cards);
    let card_mapping = encode_cards_ext(list_of_cards.clone());

    // for (i, (card, value)) in card_mapping.iter().enumerate().take(52) {
    //     println!("{:?} -> {:?}", card.0.to_string(), value);
    // }

    let card_mapping_bytes = serialize_canonical(&list_of_cards)?;
    if let Err(e) = send_protocol_message(
        swarm,
        topic,
        &ProtocolMessage::EncodedCards(card_mapping_bytes),
    ) {
        println!("Error sending encoded cards: {:?}", e);
    }

    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards
        .iter()
        .map(|card| CardProtocol::mask(rng, &pp, &joint_pk, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    println!("Initial deck:");
    for card in deck.iter() {
        println!("{:?}", card.0.to_string());
    }

    let shuffled_deck = shuffle_remask_and_send(
        swarm,
        &topic,
        prover_shuffle,
        &pp,
        &joint_pk,
        rng,
        &deck,
        m,
        n,
        channel,
        verifyShuffling,
    )?;

    Ok((shuffled_deck, card_mapping))
}

#[allow(non_snake_case)]
fn shuffle_remask_and_send(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    prover_shuffle: &mut CircomProver,
    pp: &CardParameters,
    shared_key: &PublicKey,
    rng: &mut rand::rngs::StdRng,
    deck: &[MaskedCard],
    m: usize,
    n: usize,
    channel: Option<&Channel>,
    verifyShuffling: Option<&Arc<Root<JsFunction>>>,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    println!("=== DEBUG: Starting shuffle_remask_and_send ===");
    println!(
        "DEBUG: Input parameters - m: {}, n: {}, deck_size: {}",
        m,
        n,
        deck.len()
    );
    println!(
        "DEBUG: Channel available: {}, verifyShuffling available: {}",
        channel.is_some(),
        verifyShuffling.is_some()
    );

    println!("send shuffled and remasked cards");
    let permutation = Permutation::new(rng, m * n);
    println!("DEBUG: Created permutation for size: {}", m * n);

    let rng_r_prime = &mut thread_rng();

    let base: u128 = 2;
    let exponent: u32 = 100;
    let max_value: u128 = base.pow(exponent);
    println!(
        "DEBUG: Generating r_prime values with max_value: {}",
        max_value
    );

    let mut r_prime = Vec::new();
    for _ in 0..52 {
        let random_value = rng_r_prime.gen_range(0..max_value); // Generar un número aleatorio en el rango [0, 2^162)
        let r = Scalar::from(random_value); // Convertir el número aleatorio a Self::Scalar
        r_prime.push(r);
    }
    println!("DEBUG: Generated {} r_prime values", r_prime.len());

    match CardProtocol::shuffle_and_remask2(
        prover_shuffle,
        &permutation,
        &mut r_prime,
        pp,
        shared_key,
        &deck.to_vec(),
    ) {
        Ok((public, proof)) => {
            println!(
                "DEBUG: shuffleAndRemask2 succeeded, public size: {}",
                public.len()
            );
            let chunk_size = 50; // Ajusta este valor según sea necesario
            let serializable_public: Vec<String> = public.iter().map(|fr| fr.to_string()).collect();
            println!(
                "DEBUG: Serialized public to {} strings",
                serializable_public.len()
            );

            let chunks = serializable_public.chunks(chunk_size).collect::<Vec<_>>();
            let length = chunks.len();
            println!("DEBUG: Split into {} chunks of size {}", length, chunk_size);

            let serialized_chunks: Vec<Vec<u8>> = chunks
                .iter()
                .map(|chunk| serde_json::to_vec(chunk).unwrap_or_default())
                .collect();
            println!(
                "DEBUG: Serialized chunks to bytes, total size: {} bytes",
                serialized_chunks
                    .iter()
                    .map(|chunk| chunk.len())
                    .sum::<usize>()
            );

            let public_strings = deserializar_chunks_a_strings(serialized_chunks.clone())?;
            println!("DEBUG: Deserialized chunks back to strings successfully");

            for (i, chunk) in serialized_chunks.iter().enumerate() {
                println!(
                    "DEBUG: Sending chunk {}/{} ({} bytes)",
                    i + 1,
                    length,
                    chunk.len()
                );
                if let Err(e) = send_protocol_message(
                    swarm,
                    topic,
                    &ProtocolMessage::ZKProofShuffleChunk(i as u8, length as u8, chunk.clone()),
                ) {
                    println!("Error sending zk proof chunk {}: {:?}", i, e);
                    return Err(e.into());
                }
                println!("DEBUG: Successfully sent chunk {}/{}", i + 1, length);
            }

            // Enviar la prueba por separado
            println!("DEBUG: Serializing proof...");
            let proof_bytes = serialize_proof(&proof)?;
            println!("DEBUG: Proof serialized to {} bytes", proof_bytes.len());

            if let Err(e) = send_protocol_message(
                swarm,
                topic,
                &ProtocolMessage::ZKProofShuffleProof(proof_bytes),
            ) {
                println!("Error sending zk proof: {:?}", e);
                return Err(e.into());
            }
            println!("DEBUG: Successfully sent proof");

            println!("DEBUG: Verifying shuffle and remask...");
            match CardProtocol::verify_shuffle_remask2(
                prover_shuffle,
                pp,
                shared_key,
                &deck.to_vec(),
                public.clone(),
                proof.clone(),
            ) {
                Ok(shuffled_deck) => {
                    println!(
                        "DEBUG: Verification succeeded, shuffled deck size: {}",
                        shuffled_deck.len()
                    );

                    // Call the JavaScript callback to verify shuffling if available
                    if let (Some(channel), Some(verifyShuffling)) = (channel, verifyShuffling) {
                        println!("DEBUG: Calling JavaScript verifyShuffling callback...");
                        let verifyShuffling_clone = Arc::clone(verifyShuffling);
                        let public_clone = public.clone();
                        let proof_clone = proof.clone();
                        let _ = channel.send(move |mut cx| {
                            let cb = verifyShuffling_clone.clone();
                            let this = cx.undefined();

                            let a = (proof_clone.a.x, proof_clone.a.y);
                            let b = (
                                proof_clone.b.x.c0,
                                proof_clone.b.x.c1,
                                proof_clone.b.y.c0,
                                proof_clone.b.y.c1,
                            );
                            // let b = (proof_clone.b.x.c0, proof_clone.b.y.c0, proof_clone.b.x.c1, proof_clone.b.y.c1);
                            let c = (proof_clone.c.x, proof_clone.c.y);

                            let public_str = cx.string(format!("{:?}", public_clone));
                            let proof_str = cx.string(format!("{:?}", (a, b, c)));

                            let args = vec![
                                public_str.upcast::<JsValue>(),
                                proof_str.upcast::<JsValue>(),
                            ];

                            // let proof_str = prover_shuffle.format_proof_for_solidity(&proof_clone, &public_clone)?;
                            // let proof_str = cx.string(proof_str);
                            let args = vec![
                                public_str.upcast::<JsValue>(),
                                proof_str.upcast::<JsValue>(),
                            ];

                            cb.to_inner(&mut cx).call(&mut cx, this, args)?;
                            Ok(())
                        });
                        println!("DEBUG: JavaScript callback sent successfully");
                    } else {
                        println!("DEBUG: No JavaScript callback available");
                    }

                    println!("DEBUG: shuffle_remask_and_send completed successfully");
                    Ok(shuffled_deck)
                }
                Err(e) => {
                    println!("DEBUG: Verification failed with error: {:?}", e);
                    println!("Error verifying shuffle: {:?}", e);
                    Err(Box::new(e))
                }
            }
        }
        Err(e) => {
            println!("DEBUG: shuffleAndRemask2 failed with error: {:?}", e);
            println!("Error remasking for reshuffle: {:?}", e);
            Err(Box::new(e))
        }
    }
}

fn send_protocol_message(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    message: &ProtocolMessage,
) -> Result<(), Box<dyn Error>> {
    let serialized: String = serde_json::to_string(&message)?;
    send_message(swarm, topic, &serialized.as_bytes())
}

fn send_message(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    message: &[u8],
) -> Result<(), Box<dyn Error>> {
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), message)
    {
        return Err(e.into());
    }
    Ok(())
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

fn deserialize_chunks(chunks: &[(u8, Vec<u8>)]) -> Result<Vec<String>, Box<dyn Error>> {
    // Crear una copia mutable del vector para ordenarlo
    let mut sorted_chunks = chunks.to_vec();
    sorted_chunks.sort_by_key(|(i, _)| *i);

    let result = deserializar_chunks_a_strings(
        sorted_chunks
            .iter()
            .map(|(_, chunk)| chunk.clone())
            .collect(),
    );

    result
}

fn send_remask_for_reshuffle(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    prover: &mut CircomProver,
    pp: &CardParameters,
    shared_key: &PublicKey,
    new_deck: &Vec<MaskedCard>,
    player: &InternalPlayer,
    m_list: &Vec<Card>,
) -> Result<(Vec<Bn254Fr>, ZKProofCardRemoval), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let base: u128 = 2;
    let exponent: u32 = 100;
    let max_value: u128 = base.pow(exponent);

    let mut r_prime = Vec::new();
    for _ in 0..52 {
        let random_value = rng.gen_range(0..max_value); // Generar un número aleatorio en el rango [0, 2^162)
        let r = Scalar::from(random_value); // Convertir el número aleatorio a Self::Scalar
        r_prime.push(r);
    }

    match CardProtocol::remask_for_reshuffle(
        prover,
        &mut r_prime,
        &pp,
        shared_key,
        new_deck,
        &player.cards_public,
        &player.sk,
        &player.pk,
        m_list,
    ) {
        Ok((public, proof)) => {
            // println!("Proof: {:?}", proof);

            // Dividir los datos públicos en fragmentos más pequeños
            let chunk_size = 50; // Ajusta este valor según sea necesario
            let serializable_public: Vec<String> = public.iter().map(|fr| fr.to_string()).collect();

            // Enviar los datos en fragmentos
            let chunks = serializable_public.chunks(chunk_size).collect::<Vec<_>>();
            let length = chunks.len();

            let serialized_chunks: Vec<Vec<u8>> = chunks
                .iter()
                .map(|chunk| serde_json::to_vec(chunk).unwrap_or_default())
                .collect();

            let public_strings = deserializar_chunks_a_strings(serialized_chunks.clone())?;
            // println!("Public strings: {:?}", public_strings);

            for (i, chunk) in serialized_chunks.iter().enumerate() {
                if let Err(e) = send_protocol_message(
                    swarm,
                    topic,
                    &ProtocolMessage::ZKProofRemoveAndRemaskChunk(
                        i as u8,
                        length as u8,
                        chunk.clone(),
                    ),
                ) {
                    println!("Error sending zk proof chunk {}: {:?}", i, e);
                    return Err(e.into());
                }
            }

            // Enviar la prueba por separado
            let proof_bytes = serialize_proof(&proof)?;
            if let Err(e) = send_protocol_message(
                swarm,
                topic,
                &ProtocolMessage::ZKProofRemoveAndRemaskProof(proof_bytes),
            ) {
                println!("Error sending zk proof: {:?}", e);
                return Err(e.into());
            }

            Ok((public, proof))
        }
        Err(e) => {
            println!("Error remasking for reshuffle: {:?}", e);
            Err(Box::new(e))
        }
    }
}

fn handle_disconnected_player(
    rng: &mut rand::rngs::StdRng,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    prover: &mut CircomProver,
    pp: &CardParameters,
    deck: &mut Option<Vec<MaskedCard>>,
    _card_mapping: &mut Option<HashMap<Card, ClassicPlayingCard>>,
    player_id: &String,
    player: &InternalPlayer,
    joint_pk: &mut Option<PublicKey>,
    connected_peers: &HashMap<libp2p::PeerId, PlayerInfo>,
    current_dealer: u8,
) -> Result<(Vec<MaskedCard>, PublicKey, u8), Box<dyn Error>> {
    println!("Starting reshuffle");

    let seed = [1; 32];
    let mut reshuffle_rng = rand::rngs::StdRng::from_seed(seed);

    let mut pk_proof_info_array = connected_peers
        .values()
        .map(|player_info| {
            (
                player_info.pk,
                player_info.proof_key,
                to_bytes![player_info.name.clone().as_bytes()].unwrap(),
            )
        })
        .collect::<Vec<_>>();

    pk_proof_info_array.push((player.pk, player.proof_key, player.name.clone()));
    match CardProtocol::compute_aggregate_key(&pp, &pk_proof_info_array) {
        Ok(aggregate_key) => {
            *joint_pk = Some(aggregate_key);
            println!("Joint public key: {:?}", aggregate_key.to_string());

            if let Some(card_mapping) = _card_mapping {
                let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = card_mapping
                    .keys()
                    .map(|card| {
                        CardProtocol::mask(
                            &mut reshuffle_rng,
                            &pp,
                            &aggregate_key,
                            &card,
                            &Scalar::one(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let new_deck = deck_and_proofs
                    .iter()
                    .map(|x| x.0)
                    .collect::<Vec<MaskedCard>>();

                let m_list = card_mapping.keys().cloned().collect::<Vec<Card>>();

                if is_dealer(current_dealer, &player_id) {
                    match send_remask_for_reshuffle(
                        swarm,
                        topic,
                        prover,
                        pp,
                        &aggregate_key,
                        &new_deck,
                        player,
                        &m_list,
                    ) {
                        Ok((public, proof)) => {
                            let public_cards_1 = player.cards_public[0].clone().unwrap();
                            let public_cards_2 = player.cards_public[1].clone().unwrap();
                            println!("Public cards 1: {:?}", public_cards_1.0.to_string());
                            println!("Public cards 2: {:?}", public_cards_2.0.to_string());

                            let reshuffled_deck = CardProtocol::verify_reshuffle_remask(
                                prover,
                                pp,
                                joint_pk.as_ref().unwrap(),
                                &new_deck,
                                &player
                                    .cards_public
                                    .iter()
                                    .filter_map(|card| card.clone())
                                    .collect::<Vec<_>>(),
                                &player.pk,
                                &m_list,
                                public,
                                proof,
                            )?;
                            // Si es dealer, suma a current_reshuffler (1)
                            Ok((reshuffled_deck, aggregate_key, 1))
                        }
                        Err(e) => {
                            println!("Error sending remask for reshuffle: {:?}", e);
                            Err(e.into())
                        }
                    }
                } else {
                    // Si no es dealer, no suma a current_reshuffler
                    Ok((new_deck, aggregate_key, 0))
                }
            } else {
                Err("No card mapping available".into())
            }
        }

        Err(e) => {
            println!("Error computing aggregate key: {:?}", e);
            Err(Box::new(e))
        }
    }
}

pub fn verify_remask_for_reshuffle(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    prover: &mut CircomProver,
    pp: &CardParameters,
    card_mapping: &mut Option<HashMap<Card, ClassicPlayingCard>>,
    public_bytes: &[(u8, Vec<u8>)],
    proof_bytes: &[u8],
    joint_pk: &PublicKey,
    new_deck: &Vec<MaskedCard>,
    player_cards: &Vec<MaskedCard>,
    pk: &PublicKey,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    let public_strings = deserialize_chunks(public_bytes)?;
    println!("verify_remask_for_reshuffle");

    let public_cards_1 = player_cards[0].clone();
    let public_cards_2 = player_cards[1].clone();
    println!("player_cards 1: {:?}", public_cards_1.0.to_string());
    println!("player_cards 2: {:?}", public_cards_2.0.to_string());

    if let Some(card_mapping) = &card_mapping {
        let m_list = card_mapping.keys().cloned().collect::<Vec<Card>>();
        let proof = deserialize_proof(&proof_bytes)?;

        let public_fr: Vec<Bn254Fr> = public_strings
            .iter()
            .map(|s| {
                // Eliminar cualquier espacio en blanco o caracteres adicionales
                let cleaned_str = s.trim();
                match Bn254Fr::from_str(cleaned_str) {
                    Ok(fr) => fr,
                    Err(e) => {
                        println!("Error parsing string '{}': {:?}", cleaned_str, e);
                        Bn254Fr::from(0u64)
                    }
                }
            })
            .collect();

        match CardProtocol::verify_reshuffle_remask(
            prover,
            &pp,
            &joint_pk,
            &new_deck,
            player_cards,
            pk,
            &m_list,
            public_fr,
            proof,
        ) {
            Ok(reshuffled_deck) => Ok(reshuffled_deck),
            Err(e) => {
                println!("Error verifying reshuffle remask: {:?}", e);
                Err(Box::new(e))
            }
        }
    } else {
        Err(Box::new(CardProtocolError::CardMappingError()))
    }
}

fn deserializar_chunks_a_strings(
    bytes_chunks: Vec<Vec<u8>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut resultado = Vec::new();

    for chunk_bytes in bytes_chunks {
        // Deserializar cada fragmento de bytes a un Vec<String>
        let chunk: Vec<String> = serde_json::from_slice(&chunk_bytes)?;
        resultado.extend(chunk);
    }

    Ok(resultado)
}

fn is_dealer(current_dealer: u8, player_id: &String) -> bool {
    current_dealer == player_id.parse::<u8>().unwrap()
}

fn process_reshuffle_verification(
    connected_peers: &mut HashMap<libp2p::PeerId, PlayerInfo>,
    current_reshuffler: u8,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    prover_shuffle: &mut CircomProver,
    prover_reshuffle: &mut CircomProver,
    pp: &CardParameters,
    card_mapping: &mut Option<HashMap<Card, ClassicPlayingCard>>,
    public_reshuffle_bytes: &[(u8, Vec<u8>)],
    proof_reshuffle_bytes: &[u8],
    joint_pk: &PublicKey,
    deck: &Vec<MaskedCard>,
    player: &InternalPlayer,
    player_id: &String,
    current_dealer: u8,
    m: usize,
    n: usize,
    rng: &mut rand::rngs::StdRng,
    channel: Option<&Channel>,
    verifyShuffling: Option<&Arc<Root<JsFunction>>>,
) -> Result<(Vec<MaskedCard>, u8), Box<dyn Error>> {
    match find_player_by_id(connected_peers, current_reshuffler) {
        Some((_, player_info)) => {
            let cards_vec: Vec<MaskedCard> = player_info
                .cards_public
                .iter()
                .filter_map(|card| card.clone())
                .collect();

            match verify_remask_for_reshuffle(
                swarm,
                topic,
                prover_reshuffle,
                pp,
                card_mapping,
                public_reshuffle_bytes,
                proof_reshuffle_bytes,
                joint_pk,
                deck,
                &cards_vec,
                &player_info.pk,
            ) {
                Ok(reshuffled_deck) => {
                    let new_reshuffler = current_reshuffler + 1;

                    if is_dealer(new_reshuffler, player_id) {
                        if let Some(card_mapping_val) = card_mapping {
                            let m_list = card_mapping_val.keys().cloned().collect::<Vec<Card>>();
                            match send_remask_for_reshuffle(
                                swarm,
                                topic,
                                prover_reshuffle,
                                pp,
                                joint_pk,
                                &reshuffled_deck,
                                player,
                                &m_list,
                            ) {
                                Ok((public, proof)) => {
                                    let final_deck = CardProtocol::verify_reshuffle_remask(
                                        prover_reshuffle,
                                        pp,
                                        joint_pk,
                                        &reshuffled_deck,
                                        &player
                                            .cards_public
                                            .iter()
                                            .filter_map(|card| card.clone())
                                            .collect::<Vec<_>>(),
                                        &player.pk,
                                        &m_list,
                                        public,
                                        proof,
                                    )?;

                                    if new_reshuffler == 2 {
                                        println!("All reshuffled");

                                        // Auto-generate JSON after reshuffling is complete
                                        if let Ok(json) = generate_cryptography_json(
                                            connected_peers,
                                            player,
                                            pp,
                                            &Some(final_deck.clone()),
                                            &None, // card_mapping not available in this scope
                                            &vec![vec![], vec![], vec![], vec![], vec![]], // Empty community cards for now
                                            &vec![], // Empty shuffle bytes for now
                                            &vec![], // Empty shuffle proof for now
                                            public_reshuffle_bytes,
                                            proof_reshuffle_bytes,
                                        ) {
                                            let filename = format!(
                                                "poker_cryptography_reshuffle_{}.json",
                                                player_id
                                            );
                                            if let Err(e) = save_cryptography_json(&json, &filename)
                                            {
                                                println!(
                                                    "Error auto-saving reshuffle JSON: {:?}",
                                                    e
                                                );
                                            } else {
                                                println!("Auto-generated reshuffle cryptography JSON saved!");
                                            }
                                        }

                                        if is_dealer(current_dealer, player_id) {
                                            println!("Starting shuffling and remasking");
                                            let shuffled_deck = shuffle_remask_and_send(
                                                swarm,
                                                topic,
                                                prover_shuffle,
                                                pp,
                                                joint_pk,
                                                rng,
                                                &final_deck,
                                                m,
                                                n,
                                                channel,
                                                verifyShuffling,
                                            )?;
                                            return Ok((shuffled_deck, new_reshuffler));
                                        }
                                    }

                                    Ok((final_deck, new_reshuffler))
                                }
                                Err(e) => {
                                    println!("Error sending remask for reshuffle: {:?}", e);
                                    Err(e.into())
                                }
                            }
                        } else {
                            println!("No se puede revelar la carta: card_mapping aún no está inicializada");
                            Ok((reshuffled_deck, new_reshuffler))
                        }
                    } else {
                        println!("current_reshuffler: {:?}", new_reshuffler);
                        if new_reshuffler == 2 {
                            println!("All reshuffled");

                            // Auto-generate JSON after reshuffling is complete
                            if let Ok(json) = generate_cryptography_json(
                                connected_peers,
                                player,
                                pp,
                                &Some(reshuffled_deck.clone()),
                                &None, // card_mapping not available in this scope
                                &vec![vec![], vec![], vec![], vec![], vec![]], // Empty community cards for now
                                &vec![], // Empty shuffle bytes for now
                                &vec![], // Empty shuffle proof for now
                                public_reshuffle_bytes,
                                proof_reshuffle_bytes,
                            ) {
                                let filename =
                                    format!("poker_cryptography_reshuffle_{}.json", player_id);
                                if let Err(e) = save_cryptography_json(&json, &filename) {
                                    println!("Error auto-saving reshuffle JSON: {:?}", e);
                                } else {
                                    println!("Auto-generated reshuffle cryptography JSON saved!");
                                }
                            }

                            if is_dealer(current_dealer, player_id) {
                                println!("Starting shuffling and remasking");
                                let shuffled_deck = shuffle_remask_and_send(
                                    swarm,
                                    topic,
                                    prover_shuffle,
                                    &pp,
                                    joint_pk,
                                    rng,
                                    &reshuffled_deck,
                                    m,
                                    n,
                                    channel,
                                    verifyShuffling,
                                )?;
                                return Ok((shuffled_deck, new_reshuffler));
                            }
                        }

                        Ok((reshuffled_deck, new_reshuffler))
                    }
                }
                Err(e) => {
                    println!("Error verifying reshuffle remask: {:?}", e);
                    Err(e.into())
                }
            }
        }
        None => Err(format!(
            "Error: No se encontró al jugador con id {}",
            current_reshuffler
        )
        .into()),
    }
}

fn process_shuffle_verification(
    prover_shuffle: &mut CircomProver,
    pp: &CardParameters,
    joint_pk: &PublicKey,
    deck: &mut Option<Vec<MaskedCard>>,
    public_shuffle_bytes: &[(u8, Vec<u8>)],
    proof_shuffle_bytes: &[u8],
    current_shuffler: &mut usize,
    player_id: &str,
    num_players_expected: usize,
    player: &mut InternalPlayer,
    connected_peers: &mut HashMap<libp2p::PeerId, PlayerInfo>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    rng: &mut rand::rngs::StdRng,
    m: usize,
    n: usize,
    channel: Option<&Channel>,
    verifyShuffling: Option<&Arc<Root<JsFunction>>>,
    verifyRevealToken: Option<&Arc<Root<JsFunction>>>,
) -> Result<(), Box<dyn Error>> {
    let public_strings = deserialize_chunks(public_shuffle_bytes)?;
    let public_fr: Vec<Bn254Fr> = public_strings
        .iter()
        .map(|s| {
            let cleaned_str = s.trim();
            match Bn254Fr::from_str(cleaned_str) {
                Ok(fr) => fr,
                Err(e) => {
                    println!("Error parsing string '{}': {:?}", cleaned_str, e);
                    Bn254Fr::from(0u64)
                }
            }
        })
        .collect();

    let proof = deserialize_proof(proof_shuffle_bytes)?;

    match CardProtocol::verify_shuffle_remask2(
        prover_shuffle,
        pp,
        joint_pk,
        deck.as_ref().unwrap(),
        public_fr,
        proof,
    ) {
        Ok(shuffled_deck) => {
            *deck = Some(shuffled_deck.clone());
            *current_shuffler += 1;

            if *current_shuffler == player_id.parse::<usize>().unwrap() {
                // Call shuffle_remask_and_send as before
                match shuffle_remask_and_send(
                    swarm,
                    topic,
                    prover_shuffle,
                    pp,
                    joint_pk,
                    rng,
                    &shuffled_deck,
                    m,
                    n,
                    channel,
                    verifyShuffling,
                ) {
                    Ok(new_deck) => {
                        *deck = Some(new_deck);
                    }
                    Err(e) => {
                        println!("Error in shuffle verification: {:?}", e);
                    }
                }
            }

            if *current_shuffler == num_players_expected - 1 {
                *current_shuffler = 0;
                println!("All players shuffled, revealing cards");
                let id = player_id.parse::<u8>().unwrap();
                if let Some(deck) = deck {
                    player.receive_card(deck[id as usize * 2 + 5]);
                    player.receive_card(deck[id as usize * 2 + 1 + 5]);

                    for i in 0..num_players_expected {
                        if i == id as usize {
                            continue;
                        }
                        let card1 = deck[i * 2 + 5];
                        let card2 = deck[i * 2 + 5 + 1];
                        let peer_id_to_update = connected_peers
                            .iter()
                            .find(|(_, player_info)| player_info.id == i as u8)
                            .map(|(peer_id, _)| *peer_id);

                        if let Some(peer_id) = peer_id_to_update {
                            println!("Found player with id {}", i);
                            if let Some(player_info_mut) = connected_peers.get_mut(&peer_id) {
                                player_info_mut.cards = [Some(card1), Some(card2)];
                            }
                        }

                        let reveal_token1: (RevealToken, RevealProof, PublicKey) =
                            player.compute_reveal_token(rng, pp, &card1)?;
                        let reveal_token2: (RevealToken, RevealProof, PublicKey) =
                            player.compute_reveal_token(rng, pp, &card2)?;
                        let reveal_token1_bytes = serialize_canonical(&reveal_token1)?;
                        let reveal_token2_bytes = serialize_canonical(&reveal_token2)?;

                        if let (Some(channel), Some(verifyRevealToken)) =
                            (channel, verifyRevealToken)
                        {
                            let card1_string = card1.0.to_string();
                            let card2_string = card2.0.to_string();
                            let generator_string = pp.enc_parameters.generator.to_string();

                            let player_pk_string = player.pk.to_string();
                            let verify_reveal_token_clone = verifyRevealToken.clone();
                            let _ = channel.send(move |mut cx| {
                                let cb = verify_reveal_token_clone;
                                let this = cx.undefined();

                                let token1 = reveal_token1.0;
                                let token2 = reveal_token2.0;

                                let proof1 = reveal_token1.1;
                                let proof2 = reveal_token2.1;

                                let G_card1 = cx.string(format!("{:?}", card1_string));
                                let G_card2 = cx.string(format!("{:?}", card2_string));

                                let H = cx.string(format!("{:?}", generator_string));

                                let statement1_card1 =
                                    cx.string(format!("{:?}", token1.0.to_string()));
                                let statement1_card2 =
                                    cx.string(format!("{:?}", token2.0.to_string()));

                                let statement2 = cx.string(format!("{:?}", player_pk_string));

                                let A_card1 = cx.string(format!("{:?}", proof1.a.to_string()));
                                let B_card1 = cx.string(format!("{:?}", proof1.b.to_string()));
                                let r_card1 = cx.string(format!("{:?}", proof1.r.to_string()));

                                let A_card2 = cx.string(format!("{:?}", proof2.a.to_string()));
                                let B_card2 = cx.string(format!("{:?}", proof2.b.to_string()));
                                let r_card2 = cx.string(format!("{:?}", proof2.r.to_string()));
                                let receiver_chair = cx.string(format!("{:?}", i));

                                let args1 = vec![
                                    receiver_chair.upcast::<JsValue>(), // Receiver id
                                    G_card1.upcast::<JsValue>(),
                                    G_card2.upcast::<JsValue>(),
                                    H.upcast::<JsValue>(),
                                    statement1_card1.upcast::<JsValue>(),
                                    statement1_card2.upcast::<JsValue>(),
                                    statement2.upcast::<JsValue>(),
                                    A_card1.upcast::<JsValue>(),
                                    B_card1.upcast::<JsValue>(),
                                    r_card1.upcast::<JsValue>(),
                                    A_card2.upcast::<JsValue>(),
                                    B_card2.upcast::<JsValue>(),
                                    r_card2.upcast::<JsValue>(),
                                ];

                                cb.to_inner(&mut cx).call(&mut cx, this, args1)?;
                                Ok(())
                            });
                        }

                        let new_token1 =
                            deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
                                &reveal_token1_bytes,
                            )?;
                        let new_token2 =
                            deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
                                &reveal_token2_bytes,
                            )?;

                        println!("Pushing reveal tokens to player {}", i);

                        match find_player_by_id(connected_peers, i as u8) {
                            Some((peer_id, player_info)) => {
                                player_info.reveal_tokens[0].push(new_token1);
                                player_info.reveal_tokens[1].push(new_token2);
                            }
                            None => {
                                println!("Player with id {} not found", i);
                            }
                        }

                        println!(
                            "send Reveal token 1 from {:?} to {:?}: {:?}",
                            player_id,
                            i,
                            reveal_token1.0 .0.to_string()
                        );
                        println!(
                            "send Reveal token 2 from {:?} to {:?}: {:?}",
                            player_id,
                            i,
                            reveal_token2.0 .0.to_string()
                        );

                        let message = ProtocolMessage::RevealToken(
                            i as u8,
                            reveal_token1_bytes,
                            reveal_token2_bytes,
                        );
                        if let Err(e) = send_protocol_message(swarm, topic, &message) {
                            println!("Error sending reveal token: {:?}", e);
                        }
                    }

                    // Auto-generate JSON after shuffling is complete
                    if let Ok(json) = generate_cryptography_json(
                        connected_peers,
                        &player,
                        &pp,
                        &Some(deck.clone()),
                        &None, // card_mapping not available in this scope
                        &vec![vec![], vec![], vec![], vec![], vec![]], // Empty community cards for now
                        &public_shuffle_bytes,
                        &proof_shuffle_bytes,
                        &vec![], // Empty reshuffle bytes for now
                        &vec![], // Empty reshuffle proof for now
                    ) {
                        let filename = format!("poker_cryptography_shuffle_{}.json", player_id);
                        if let Err(e) = save_cryptography_json(&json, &filename) {
                            println!("Error auto-saving shuffle JSON: {:?}", e);
                        } else {
                            println!("Auto-generated shuffle cryptography JSON saved!");
                        }
                    }
                }
            }
            println!("Shuffle verified");
            Ok(())
        }
        Err(e) => {
            println!("Error verifying shuffle remask: {:?}", e);
            Err(Box::new(e))
        }
    }
}

// Agregar validación de chunks completos
fn validate_chunks(chunks: &[(u8, Vec<u8>)], expected_length: u8) -> bool {
    if chunks.len() != expected_length as usize {
        return false;
    }

    let mut indices: Vec<u8> = chunks.iter().map(|(i, _)| *i).collect();
    indices.sort();

    for (i, &index) in indices.iter().enumerate() {
        if index != i as u8 {
            return false;
        }
    }
    true
}

// Add this helper function before the generate_cryptography_json function
fn field_to_decimal(field_element: &str) -> String {
    // Extract the hexadecimal part from the field element string
    // Format: "Fp256 \"(0BB77A6AD63E739B4EACB2E09D6277C12AB8D8010534E0B62893F3F6BB957051)\""
    let re = Regex::new(r"\(([0-9A-Fa-f]+)\)").unwrap();
    if let Some(caps) = re.captures(field_element) {
        let hex_str = caps.get(1).unwrap().as_str();
        // Convert hexadecimal to decimal using parse_bytes
        let decimal = BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap();
        decimal.to_string()
    } else {
        // If no parentheses found, try to parse as direct hex
        field_element
            .trim_matches(|c| c == '"' || c == '\\')
            .to_string()
    }
}

fn generate_cryptography_json(
    connected_peers: &HashMap<libp2p::PeerId, PlayerInfo>,
    player: &InternalPlayer,
    pp: &CardParameters,
    deck: &Option<Vec<MaskedCard>>,
    card_mapping: &Option<HashMap<Card, ClassicPlayingCard>>,
    community_cards_tokens: &[Vec<(RevealToken, RevealProof, PublicKey)>],
    public_shuffle_bytes: &[(u8, Vec<u8>)],
    proof_shuffle_bytes: &[u8],
    public_reshuffle_bytes: &[(u8, Vec<u8>)],
    proof_reshuffle_bytes: &[u8],
) -> Result<PokerCryptographyJSON, Box<dyn Error>> {
    let mut public_keys = HashMap::new();
    let mut schnorr_proofs = HashMap::new();
    let mut chaum_pedersen_proofs = HashMap::new();
    let mut zk_proofs = HashMap::new();

    // Add current player
    let player_id = format!("player{}", 1); // Assuming current player is player1
    public_keys.insert(
        player_id.clone(),
        Point {
            x: field_to_decimal(&player.pk.x.to_string()),
            y: field_to_decimal(&player.pk.y.to_string()),
        },
    );

    schnorr_proofs.insert(
        player_id.clone(),
        SchnorrProof {
            commitment: Point {
                x: field_to_decimal(&player.proof_key.random_commit.x.to_string()),
                y: field_to_decimal(&player.proof_key.random_commit.y.to_string()),
            },
            response: field_to_decimal(&player.proof_key.opening.to_string()),
        },
    );

    // Add connected peers
    for (_, player_info) in connected_peers.iter() {
        let peer_id = format!("player{}", player_info.id);
        public_keys.insert(
            peer_id.clone(),
            Point {
                x: field_to_decimal(&player_info.pk.x.to_string()),
                y: field_to_decimal(&player_info.pk.y.to_string()),
            },
        );

        schnorr_proofs.insert(
            peer_id.clone(),
            SchnorrProof {
                commitment: Point {
                    x: field_to_decimal(&player_info.proof_key.random_commit.x.to_string()),
                    y: field_to_decimal(&player_info.proof_key.random_commit.y.to_string()),
                },
                response: field_to_decimal(&player_info.proof_key.opening.to_string()),
            },
        );

        // Add Chaum-Pedersen proofs for player cards
        if let (Some(card1), Some(card2)) = (player_info.cards[0], player_info.cards[1]) {
            // For card1
            if let Some(token) = player_info.reveal_tokens[0].first() {
                chaum_pedersen_proofs.insert(
                    format!("{}Card1", peer_id),
                    ChaumPedersenProof {
                        A: Point {
                            x: field_to_decimal(&token.1.a.x.to_string()),
                            y: field_to_decimal(&token.1.a.y.to_string()),
                        },
                        B: Point {
                            x: field_to_decimal(&token.1.b.x.to_string()),
                            y: field_to_decimal(&token.1.b.y.to_string()),
                        },
                        r: field_to_decimal(&token.1.r.to_string()),
                    },
                );
            }

            // For card2
            if let Some(token) = player_info.reveal_tokens[1].first() {
                chaum_pedersen_proofs.insert(
                    format!("{}Card2", peer_id),
                    ChaumPedersenProof {
                        A: Point {
                            x: field_to_decimal(&token.1.a.x.to_string()),
                            y: field_to_decimal(&token.1.a.y.to_string()),
                        },
                        B: Point {
                            x: field_to_decimal(&token.1.b.x.to_string()),
                            y: field_to_decimal(&token.1.b.y.to_string()),
                        },
                        r: field_to_decimal(&token.1.r.to_string()),
                    },
                );
            }
        }
    }

    // Add current player's Chaum-Pedersen proofs
    if let Some(deck) = deck {
        let player_id_num = 1; // Assuming current player is player1
        let card1_index = player_id_num * 2 + 5;
        let card2_index = player_id_num * 2 + 1 + 5;

        if card1_index < deck.len() && card2_index < deck.len() {
            // Generate tokens for current player's cards
            let rng = &mut thread_rng();
            if let Ok((token1, proof1, _)) =
                player.compute_reveal_token(rng, pp, &deck[card1_index])
            {
                chaum_pedersen_proofs.insert(
                    "player1Card1".to_string(),
                    ChaumPedersenProof {
                        A: Point {
                            x: field_to_decimal(&proof1.a.x.to_string()),
                            y: field_to_decimal(&proof1.a.y.to_string()),
                        },
                        B: Point {
                            x: field_to_decimal(&proof1.b.x.to_string()),
                            y: field_to_decimal(&proof1.b.y.to_string()),
                        },
                        r: field_to_decimal(&proof1.r.to_string()),
                    },
                );
            }

            if let Ok((token2, proof2, _)) =
                player.compute_reveal_token(rng, pp, &deck[card2_index])
            {
                chaum_pedersen_proofs.insert(
                    "player1Card2".to_string(),
                    ChaumPedersenProof {
                        A: Point {
                            x: field_to_decimal(&proof2.a.x.to_string()),
                            y: field_to_decimal(&proof2.a.y.to_string()),
                        },
                        B: Point {
                            x: field_to_decimal(&proof2.b.x.to_string()),
                            y: field_to_decimal(&proof2.b.y.to_string()),
                        },
                        r: field_to_decimal(&proof2.r.to_string()),
                    },
                );
            }
        }
    }

    // Add community cards Chaum-Pedersen proofs
    for (i, tokens) in community_cards_tokens.iter().enumerate() {
        if !tokens.is_empty() {
            let card_name = match i {
                0 => "flop".to_string(),
                1 => "flop".to_string(),
                2 => "flop".to_string(),
                3 => "turn".to_string(),
                4 => "river".to_string(),
                _ => continue,
            };

            if let Some(token) = tokens.first() {
                let proof_name = if i < 3 {
                    format!("{}[{}]", card_name, i)
                } else {
                    card_name
                };

                chaum_pedersen_proofs.insert(
                    format!("communityCards.{}", proof_name),
                    ChaumPedersenProof {
                        A: Point {
                            x: field_to_decimal(&token.1.a.x.to_string()),
                            y: field_to_decimal(&token.1.a.y.to_string()),
                        },
                        B: Point {
                            x: field_to_decimal(&token.1.b.x.to_string()),
                            y: field_to_decimal(&token.1.b.y.to_string()),
                        },
                        r: field_to_decimal(&token.1.r.to_string()),
                    },
                );
            }
        }
    }

    // Add ZK proofs
    if !public_shuffle_bytes.is_empty() && !proof_shuffle_bytes.is_empty() {
        let public_strings = deserialize_chunks(public_shuffle_bytes)?;
        let proof = deserialize_proof(proof_shuffle_bytes)?;

        zk_proofs.insert(
            "shuffling".to_string(),
            ZKProof {
                proofA: vec![proof.a.x.to_string(), proof.a.y.to_string()],
                proofB: vec![
                    vec![proof.b.x.c0.to_string(), proof.b.x.c1.to_string()],
                    vec![proof.b.y.c0.to_string(), proof.b.y.c1.to_string()],
                ],
                proofC: vec![proof.c.x.to_string(), proof.c.y.to_string()],
                pubSignals: format!("{}_ELEMENTS", public_strings.len()),
            },
        );
    }

    if !public_reshuffle_bytes.is_empty() && !proof_reshuffle_bytes.is_empty() {
        let public_strings = deserialize_chunks(public_reshuffle_bytes)?;
        let proof = deserialize_proof(proof_reshuffle_bytes)?;

        zk_proofs.insert(
            "reshuffling".to_string(),
            ZKProof {
                proofA: vec![proof.a.x.to_string(), proof.a.y.to_string()],
                proofB: vec![
                    vec![proof.b.x.c0.to_string(), proof.b.x.c1.to_string()],
                    vec![proof.b.y.c0.to_string(), proof.b.y.c1.to_string()],
                ],
                proofC: vec![proof.c.x.to_string(), proof.c.y.to_string()],
                pubSignals: format!("{}_ELEMENTS", public_strings.len()),
            },
        );
    }

    // Generate tokens structure
    let mut player1_to_player2 = PlayerCards {
        card1: Point {
            x: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            y: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        },
        card2: Point {
            x: "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            y: "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
        },
    };

    let mut player2_to_player1 = PlayerCards {
        card1: Point {
            x: "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            y: "6666666666666666666666666666666666666666666666666666666666666666".to_string(),
        },
        card2: Point {
            x: "7777777777777777777777777777777777777777777777777777777777777777".to_string(),
            y: "8888888888888888888888888888888888888888888888888888888888888888".to_string(),
        },
    };

    // Try to get real token values if available
    if let Some(deck) = deck {
        let rng = &mut thread_rng();

        // Generate tokens for player1 to player2
        if deck.len() > 6 {
            if let Ok((token1, _, _)) = player.compute_reveal_token(rng, pp, &deck[6]) {
                player1_to_player2.card1 = Point {
                    x: field_to_decimal(&token1.0.x.to_string()),
                    y: field_to_decimal(&token1.0.y.to_string()),
                };
            }
            if let Ok((token2, _, _)) = player.compute_reveal_token(rng, pp, &deck[7]) {
                player1_to_player2.card2 = Point {
                    x: field_to_decimal(&token2.0.x.to_string()),
                    y: field_to_decimal(&token2.0.y.to_string()),
                };
            }
        }

        // Generate tokens for player2 to player1
        if deck.len() > 4 {
            if let Ok((token1, _, _)) = player.compute_reveal_token(rng, pp, &deck[4]) {
                player2_to_player1.card1 = Point {
                    x: field_to_decimal(&token1.0.x.to_string()),
                    y: field_to_decimal(&token1.0.y.to_string()),
                };
            }
            if let Ok((token2, _, _)) = player.compute_reveal_token(rng, pp, &deck[5]) {
                player2_to_player1.card2 = Point {
                    x: field_to_decimal(&token2.0.x.to_string()),
                    y: field_to_decimal(&token2.0.y.to_string()),
                };
            }
        }
    }

    let tokens = Tokens {
        player1ToPlayer2: player1_to_player2,
        player2ToPlayer1: player2_to_player1,
        communityCardsFromPlayer1: vec![
            Point {
                x: "9999999999999999999999999999999999999999999999999999999999999999".to_string(),
                y: "1010101010101010101010101010101010101010101010101010101010101010".to_string(),
            },
            Point {
                x: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                y: "1212121212121212121212121212121212121212121212121212121212121212".to_string(),
            },
            Point {
                x: "1313131313131313131313131313131313131313131313131313131313131313".to_string(),
                y: "1414141414141414141414141414141414141414141414141414141414141414".to_string(),
            },
            Point {
                x: "1515151515151515151515151515151515151515151515151515151515151515".to_string(),
                y: "1616161616161616161616161616161616161616161616161616161616161616".to_string(),
            },
            Point {
                x: "1717171717171717171717171717171717171717171717171717171717171717".to_string(),
                y: "1818181818181818181818181818181818181818181818181818181818181818".to_string(),
            },
        ],
        communityCardsFromPlayer2: vec![
            Point {
                x: "1919191919191919191919191919191919191919191919191919191919191919".to_string(),
                y: "2020202020202020202020202020202020202020202020202020202020202020".to_string(),
            },
            Point {
                x: "2121212121212121212121212121212121212121212121212121212121212121".to_string(),
                y: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            },
            Point {
                x: "2323232323232323232323232323232323232323232323232323232323232323".to_string(),
                y: "2424242424242424242424242424242424242424242424242424242424242424".to_string(),
            },
            Point {
                x: "2525252525252525252525252525252525252525252525252525252525252525".to_string(),
                y: "2626262626262626262626262626262626262626262626262626262626262626".to_string(),
            },
            Point {
                x: "2727272727272727272727272727272727272727272727272727272727272727".to_string(),
                y: "2828282828282828282828282828282828282828282828282828282828282828".to_string(),
            },
        ],
    };

    let json = PokerCryptographyJSON {
        description: "Mock cryptographic values for PokerCryptography tests. Replace with real values when available.".to_string(),
        publicKeys: public_keys,
        schnorrProofs: schnorr_proofs,
        chaumPedersenProofs: chaum_pedersen_proofs,
        zkProofs: zk_proofs,
        cardMappings: "PLACEHOLDER_52_CARDS".to_string(),
        encryptedCards: "PLACEHOLDER_52_ENCRYPTED_CARDS".to_string(),
        tokens,
        generator: Point {
            x: field_to_decimal(&pp.generator.0.x.to_string()),
            y: field_to_decimal(&pp.generator.0.y.to_string()),
        },
        encGenerator: Point {
            x: field_to_decimal(&pp.enc_parameters.generator.x.to_string()),
            y: field_to_decimal(&pp.enc_parameters.generator.y.to_string()),
        },
    };

    Ok(json)
}

fn save_cryptography_json(
    json: &PokerCryptographyJSON,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    // Create cryptography-results directory if it doesn't exist
    let crypto_dir = "cryptography-results";
    std::fs::create_dir_all(crypto_dir)?;

    // Construct full path
    let full_path = format!("{}/{}", crypto_dir, filename);

    let json_string = serde_json::to_string_pretty(json)?;
    std::fs::write(&full_path, json_string)?;
    println!("Cryptography JSON saved to {}", full_path);
    Ok(())
}
