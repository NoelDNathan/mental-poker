use ark_ff::to_bytes;
use ark_std::One;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use futures::stream::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use rand::thread_rng;
use rand::SeedableRng;
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};
use tokio::{io, io::AsyncBufReadExt, select, time::interval};
use tracing_subscriber::EnvFilter;

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use std::collections::HashMap;

use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, generator, open_card, Card, CardParameters,
    CardProtocol, ClassicPlayingCard, InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey,
    RemaskingProof, RevealProof, RevealToken, Scalar, ZKProofShuffle,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use std::{env, thread};

use rand;

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
}


pub struct PlayerInfo{
    name: String,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
    let player_id = args
        .iter()
        .position(|arg| arg == "--id")
        .and_then(|index| args.get(index + 1))
        .cloned()
        .unwrap_or_else(|| "DefaultName".to_string());

    let name = format!("Player {}", player_id);
    let name_bytes = to_bytes![name.as_bytes()].unwrap();

    let rng2 = &mut thread_rng();
    let mut player = InternalPlayer::new(rng2, &pp, &name_bytes).unwrap();

    // Initializate poker game variables
    let mut pk_proof_info_array: Vec<(PublicKey, ProofKeyOwnership, Vec<u8>)> = Vec::new();
    let mut joint_pk: Option<PublicKey> = None;
    let mut card_mapping: Option<HashMap<Card, ClassicPlayingCard>> = None;
    let mut deck: Option<Vec<MaskedCard>> = None;

    let mut first_message = true;
    let mut num_players_expected = 3;
    let mut current_dealer = 0;
    let mut players_connected = 1;
    let mut current_shuffler = 0;
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


    // Kick it off
    loop {
        select! {
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
                    if now.duration_since(*last_seen) > timeout_duration {
                        disconnected_peers.push(*peer_id);
                        println!("Peer desconectado: {}", peer_id);
                    }
                }

                // println!("Connected peers: {:?}", connected_peers);
                // Procesar peers desconectados
                for peer_id in disconnected_peers {
                    if let Some(player_info) = connected_peers.remove(&peer_id) {
                        println!("¡Jugador desconectado por inactividad!: {} ({})", player_info.name, peer_id);
                        players_connected -= 1;
                        peer_last_seen.remove(&peer_id);

                        if players_connected > 1{

                            println!("Starting reshuffle");

                            

                        }
                    }
                }
            }
            Ok(Some(line)) = stdin.next_line() => {
                println!("Line: {:?}", line);
                if first_message{
                    println!("Sending public key info");
                    let public_key_info = PublicKeyInfoEncoded {
                        name: name_bytes.clone(),
                        public_key: serialize_canonical(&player.pk).unwrap(),
                        proof_key: serialize_canonical(&player.proof_key).unwrap(),
                    };
                    let message = ProtocolMessage::PublicKeyInfo(public_key_info);
                    if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                        println!("Error sending public key info: {:?}", e);
                    }
                    first_message = false;
                }else{
                    if line == "flop"{

                        if let Some(current_deck) = &deck {

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
                    else if line == "turn"{
                        if let Some(current_deck) = &deck {
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
                    else if line == "river"{
                        if let Some(current_deck) = &deck {
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
                    else if line == "reveal_all_cards"{
                        if let Some(current_deck) = &deck {
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

                    if let Err(e) = send_protocol_message(&mut swarm, &topic, &ProtocolMessage::Text(line.as_bytes().to_vec())) {
                        println!("Error sending text message: {:?}", e);
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
                        // Aquí puedes añadir lógica adicional para manejar la desconexión
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



                                        println!("Number of players: {:?}", players_connected);

                                        match CardProtocol::verify_key_ownership(&pp, &pk_val, &player.name.clone(), &proof_val){
                                            Ok(_) => {
                                                // Asocia el nombre del jugador con su peer_id
                                                connected_peers.insert(peer_id, PlayerInfo{name: name.clone(), pk: pk_val.clone(), proof_key: proof_val.clone()});
                                            },
                                            Err(e) => println!("Error verifying proof key ownership: {:?}", e),
                                        }

                                        if players_connected == num_players_expected {

                                            pk_proof_info_array.push((player.pk, player.proof_key, player.name.clone()));
                                            match CardProtocol::compute_aggregate_key(&pp, &pk_proof_info_array) {
                                                Ok(aggregate_key) => {
                                                    joint_pk = Some(aggregate_key);
                                                    println!("Joint public key: {:?}", aggregate_key.to_string());

                                                    if current_dealer == player_id.parse::<u8>().unwrap(){
                                                        println!("All players connected, starting game");
                                                        let (shuffled_deck, card_mapping_val) = dealt_cards(&mut swarm, &topic, &pp, rng, &aggregate_key).unwrap();
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

                                                if current_shuffler == player_id.parse::<usize>().unwrap(){
                                                    let shuffle_deck = shuffle_remask_and_send(&mut swarm, &topic, &pp, rng, &joint_pk.as_ref().unwrap(), &remasked_cards, m, n ).unwrap();
                                                    deck = Some(shuffle_deck);
                                                }

                                                if current_shuffler == num_players_expected - 1
                                                {
                                                    println!("All players shuffled, revealing cards");
                                                    let id = player_id.parse::<u8>().unwrap();
                                                    if let Some(deck) = &deck {
                                                        player.receive_card(deck[id as usize * 2 + 5]);
                                                        player.receive_card(deck[id as usize * 2 + 1 + 5]);
                                                        for i in 0..num_players_expected{
                                                            if i == id as usize{
                                                                continue;
                                                            }

                                                                let reveal_token1: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &deck[i as usize * 2 + 5])?;
                                                                let reveal_token2: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &deck[i as usize * 2 + 1 + 5])?;
                                                                println!("Reveal token 1: {:?}", reveal_token1.0.0.to_string());
                                                                println!("Reveal token 2: {:?}", reveal_token2.0.0.to_string());
                                                                let reveal_token1_bytes = serialize_canonical(&reveal_token1)?;
                                                                let reveal_token2_bytes = serialize_canonical(&reveal_token2)?;
                                                                let message = ProtocolMessage::RevealToken(i as u8, reveal_token1_bytes, reveal_token2_bytes);
                                                                if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
                                                                    println!("Error sending reveal token: {:?}", e);
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
                                    if id != player_id.parse::<u8>().unwrap(){
                                        continue;
                                    }
                                    println!("Got reveal token");
                                    let reveal_token1 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token1_bytes)?;
                                    let reveal_token2 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token2_bytes)?;

                                    received_reveal_tokens1.push(reveal_token1);
                                    received_reveal_tokens2.push(reveal_token2);

                                    num_received_reveal_tokens += 1;
                                    println!("Num received reveal tokens: {:?}", num_received_reveal_tokens);
                                    println!("Num players expected: {:?}", num_players_expected);

                                    if num_received_reveal_tokens == num_players_expected - 1 {
                                        println!("All tokens received, revealing cards");
                                        let index1 = player_id.parse::<usize>().unwrap() * 2 + 5;
                                        let index2 = player_id.parse::<usize>().unwrap() * 2 + 1 + 5;
                                        println!("index1: {:?}", index1);
                                        println!("index2: {:?}", index2);
                                        if let Some(card_mapping) = &card_mapping {
                                            if let Some(deck) = &deck {
                                                // println!("Player cards: {:?}", player.cards);
                                                // println!("Player cards public: {:?}", player.cards_public);
                                                // println!("Player opened cards: {:?}", player.opened_cards);

                                                match player.peek_at_card(&pp, &mut received_reveal_tokens1, &card_mapping, &deck[index1 as usize]) {
                                                    Ok(card1) => println!("Card 1 xxx: {:?}", player.opened_cards),
                                                    Err(e) => println!("Error peeking at card 1: {:?}", e),
                                                }

                                                match player.peek_at_card(&pp, &mut received_reveal_tokens2, &card_mapping, &deck[index2 as usize]) {
                                                    Ok(card2) => println!("Card 2 xxx: {:?}", player.opened_cards),
                                                    Err(e) => println!("Error peeking at card 2: {:?}", e),
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

                                                    match player.compute_reveal_token(rng, &pp, &deck[index]) {
                                                        Ok(token) => {
                                                            community_cards_tokens[index].push(token);
                                                            match open_card(&pp, &community_cards_tokens[index], &card_mapping, &deck[index]) {
                                                                Ok(card) => println!("Card xxx: {:?}", card),
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
                                            for i in 0..reveal_all_cards_bytes.len() {
                                                let reveal_token = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_all_cards_bytes[i])?;
                                                let player_token = player.compute_reveal_token(rng, &pp, &deck[i as usize])?;
                                                let tokens = vec![reveal_token, player_token];
                                                let card = open_card(&pp, &tokens, &card_mapping, &deck[i as usize])?;
                                                println!("Card: {:?}", card);
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
}

fn dealt_cards(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    pp: &CardParameters,
    rng: &mut rand::rngs::StdRng,
    joint_pk: &PublicKey,
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

    let shuffled_deck = shuffle_remask_and_send(swarm, topic, pp, rng, joint_pk, &deck, m, n)?;

    Ok((shuffled_deck, card_mapping))
}

fn shuffle_remask_and_send(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    pp: &CardParameters,
    rng: &mut rand::rngs::StdRng,
    joint_pk: &PublicKey,
    deck: &[MaskedCard],
    m: usize,
    n: usize,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    println!("send shuffled and remasked cards");
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    match CardProtocol::shuffle_and_remask(
        rng,
        pp,
        joint_pk,
        &deck.to_vec(),
        &masking_factors,
        &permutation,
    ) {
        Ok((shuffled_deck, shuffle_proof)) => {
            let remasked_bytes = serialize_canonical(&shuffled_deck)?;
            let proof_bytes = serialize_canonical(&shuffle_proof)?;

            if let Err(e) = send_protocol_message(
                swarm,
                topic,
                &ProtocolMessage::ShuffledAndRemaskedCards(remasked_bytes, proof_bytes),
            ) {
                println!("Error sending shuffled and remasked cards: {:?}", e);
            }
            Ok(shuffled_deck)
        }
        Err(e) => {
            println!("Error shuffling and remasking: {:?}", e);
            Err(e.into())
        }
    }
}

fn send_protocol_message(
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    message: &ProtocolMessage,
) -> Result<(), Box<dyn Error>> {
    let serialized = serde_json::to_string(&message)?;
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
