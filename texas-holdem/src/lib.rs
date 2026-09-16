use barnett_smart_card_protocol::discrete_log_cards;
use barnett_smart_card_protocol::error::CardProtocolError;
use barnett_smart_card_protocol::BarnettSmartProtocol;

use anyhow;
use ark_ff::{to_bytes, UniformRand};
use ark_std::{rand::Rng, One};
use proof_essentials::homomorphic_encryption::el_gamal::arithmetic_definitions::plaintext;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::arguments::shuffle;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use rand::thread_rng;
use std::collections::HashMap;
use std::iter::Iterator;
use thiserror::Error;
// use zk_reshuffle::{CircomProver};

use ark_ec::{AffineCurve, ProjectiveCurve};
use babyjubjub::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use std::str::FromStr;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Write, Read, SerializationError};
use ark_groth16::Groth16;
use ark_bn254::{Bn254, Fr as inputBn254Fr};


type Curve = EdwardsProjective;
pub type Scalar = Fr;



// Instantiate concrete type for our card protocol
pub type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
pub type CardParameters = discrete_log_cards::Parameters<Curve>;
pub type PublicKey = discrete_log_cards::PublicKey<Curve>;
pub type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

pub type Card = discrete_log_cards::Card<Curve>;
pub type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
pub type RevealToken = discrete_log_cards::RevealToken<Curve>;

pub type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
pub type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
pub type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
pub type ZKProofShuffle = proof_essentials::zkp::arguments::shuffle::proof::Proof<ark_ff::Fp256<babyjubjub::FrParameters>, proof_essentials::homomorphic_encryption::el_gamal::ElGamal<ark_ec::twisted_edwards_extended::GroupProjective<babyjubjub::EdwardsParameters>>, proof_essentials::vector_commitment::pedersen::PedersenCommitment<ark_ec::twisted_edwards_extended::GroupProjective<babyjubjub::EdwardsParameters>>>;
pub type Bn254Fr = inputBn254Fr;

#[derive(Error, Debug, PartialEq)]
pub enum GameErrors {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("Invalid card")]
    InvalidCard,
}

#[derive(PartialEq, Clone, Copy, Eq)]
pub enum Suite {
    Club,
    Diamond,
    Heart,
    Spade,
}

impl Suite {
    const VALUES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];

    pub fn symbol(self) -> &'static str {
        match self {
            Suite::Club => "♣",
            Suite::Diamond => "♦",
            Suite::Heart => "♥",
            Suite::Spade => "♠",
        }
    }
}

#[derive(PartialEq, PartialOrd, Clone, Copy, Eq)]
pub enum Value {
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Ten,
    Jack,
    Queen,
    King,
    Ace,
}

impl Value {
    const VALUES: [Self; 13] = [
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Ten,
        Self::Jack,
        Self::Queen,
        Self::King,
        Self::Ace,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Value::Two => "2",
            Value::Three => "3",
            Value::Four => "4",
            Value::Five => "5",
            Value::Six => "6",
            Value::Seven => "7",
            Value::Eight => "8",
            Value::Nine => "9",
            Value::Ten => "10",
            Value::Jack => "J",
            Value::Queen => "Q",
            Value::King => "K",
            Value::Ace => "A",
        }
    }
}

#[derive(PartialEq, Clone, Eq, Copy)]
pub struct ClassicPlayingCard {
    value: Value,
    suite: Suite,
}

impl ClassicPlayingCard {
    pub fn new(value: Value, suite: Suite) -> Self {
        Self { value, suite }
    }

    pub fn value(self) -> Value {
        self.value
    }

    pub fn suite(self) -> Suite {
        self.suite
    }

    pub fn rank_label(self) -> &'static str {
        self.value.label()
    }

    pub fn suite_symbol(self) -> &'static str {
        self.suite.symbol()
    }
}

impl std::fmt::Debug for ClassicPlayingCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Club => "♣",
            Suite::Diamond => "♦",
            Suite::Heart => "♥",
            Suite::Spade => "♠",
        };

        let val = match self.value {
            Value::Two => "2",
            Value::Three => "3",
            Value::Four => "4",
            Value::Five => "5",
            Value::Six => "6",
            Value::Seven => "7",
            Value::Eight => "8",
            Value::Nine => "9",
            Value::Ten => "10",
            Value::Jack => "J",
            Value::Queen => "Q",
            Value::King => "K",
            Value::Ace => "A",
        };

        write!(f, "{}{}", val, suite)
    }
}

#[derive(Clone)]
pub struct InternalPlayer {
    pub name: Vec<u8>,
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub proof_key: ProofKeyOwnership,
    pub cards: Vec<MaskedCard>,
    pub cards_public: Vec<Option<MaskedCard>>,
    pub opened_cards: Vec<Option<ClassicPlayingCard>>,
}




impl InternalPlayer {
    pub fn new<R: Rng>(rng: &mut R, pp: &CardParameters, name: &Vec<u8>) -> anyhow::Result<Self> {
        let (pk, sk) = CardProtocol::player_keygen(rng, pp)?;
        let proof_key = CardProtocol::prove_key_ownership(rng, pp, &pk, &sk, name)?;
        Ok(Self {
            name: name.clone(),
            sk,
            pk,
            proof_key,
            cards: vec![],
            cards_public: vec![],
            opened_cards: vec![],
        })
    }

    pub fn receive_card(&mut self, card: MaskedCard) {
        self.cards.push(card);
        self.opened_cards.push(None);
        self.cards_public.push(None);
    }

    pub fn peek_at_card(
        &mut self,
        parameters: &CardParameters,
        reveal_tokens: &mut Vec<(RevealToken, RevealProof, PublicKey)>,
        card_mappings: &HashMap<Card, ClassicPlayingCard>,
        card: &MaskedCard,
    ) -> Result<(ClassicPlayingCard), anyhow::Error> {

        let i: Option<usize> = self.cards.iter().position(|&x| x == *card);

        let i = i.ok_or(GameErrors::CardNotFound)?;

        println!("pee at card:");
        let public_card = CardProtocol::partial_unmask(&parameters, reveal_tokens, card)?;

        self.cards_public[i] = Some(public_card);

        //TODO add function to create that without the proof
        let rng = &mut thread_rng();
        let own_reveal_token = self.compute_reveal_token(rng, parameters, card)?;
        reveal_tokens.push(own_reveal_token);

        // println!("Reveal tokens 1: {:?}", reveal_tokens[0].0.0.cards_publicto_string());

        let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
        // println!("Unmasked card: {:?}", unmasked_card.0.to_string());

        // for (card, value) in card_mappings.iter() {
        //     println!("{:?} -> {:?}", card.0.to_string(), value);
        // }

        println!("Unmasked card: {:?}", unmasked_card.0.to_string());
        let opened_card = card_mappings.get(&unmasked_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;
        
        self.opened_cards[i] = Some(*opened_card);
        Ok(*opened_card)
    }

    pub fn compute_reveal_token<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
        card: &MaskedCard,
    ) -> anyhow::Result<(RevealToken, RevealProof, PublicKey)> {
        let (reveal_token, reveal_proof) =
            CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, card)?;
        Ok((reveal_token, reveal_proof, self.pk))
    }
}
//Every player will have to calculate this function for cards that are in play
pub fn open_card(
    parameters: &CardParameters,
    reveal_tokens: &Vec<(RevealToken, RevealProof, PublicKey)>,
    card_mappings: &HashMap<Card, ClassicPlayingCard>,
    card: &MaskedCard,
) -> Result<ClassicPlayingCard, anyhow::Error> {
    let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
    println!("Unmasked card: {:?}", unmasked_card.0.to_string());
    let opened_card = card_mappings.get(&unmasked_card);
    let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;

    Ok(*opened_card)
}
pub fn generate_list_of_cards<R: Rng>(rng: &mut R, num_of_cards: usize) -> Vec<Card> {
    let mut list_of_cards: Vec<Card> = Vec::new();
    for _ in 0..num_of_cards {
        list_of_cards.push(Card::rand(rng));
    }
    list_of_cards
}

// =============================================================================
// MAZO CANONICO DETERMINISTA (nothing-up-my-sleeve)
// =============================================================================
//
// El mapping punto→carta es el ALFABETO del protocolo, no un secreto: se
// difunde en claro y el secreto vive entero en la permutacion + re-cifrado de
// cada ronda de shuffle. Que lo generase el dealer con `Card::rand` por mano
// tenia tres costes sin ninguna ganancia:
//   1. el dealer ELIGE los 52 puntos (nadie los valida: puede escogerlos con
//      relaciones algebraicas entre si),
//   2. puede equivocar (mapas distintos a peers distintos),
//   3. al ser un dato transmitido y no derivado, negarse a enviarlo bloquea la
//      mesa pre-cadena sin reclamo posible (nadie mas puede abrir startGame ZK).
//
// La semilla es una constante ASCII publicada: cualquiera recomputa el mazo y
// verifica que nadie tuvo libertad para elegir los puntos. ChaCha20 garantiza
// flujo reproducible entre versiones de rand_chacha, y `Card::rand` deriva
// puntos del subgrupo primo (C::rand). El mismo mazo queda persistido on-chain
// (cardMapping) y volcado a JSON (examples/dump_canonical_deck.rs) para el
// deploy y los tests de contrato — el test `canonical_deck_golden_pin` vigila
// cualquier deriva entre las tres copias.

/// Semilla de dominio del mazo canonico. Exactamente 32 bytes ASCII.
pub const CANONICAL_DECK_SEED: [u8; 32] = *b"dog-poker-club/canonical-deck/v1";

/// Deriva el mazo canonico completo. Determinista: misma salida siempre,
/// en cualquier cliente, sin RNG externo.
pub fn generate_canonical_deck(num_of_cards: usize) -> Vec<Card> {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(CANONICAL_DECK_SEED);
    generate_list_of_cards(&mut rng, num_of_cards)
}

/// Coordenadas afines (x, y) de una carta como enteros decimales — el formato
/// que esperan el contrato (BabyJubJub.Point) y el deploy/tests de Hardhat.
pub fn card_coords_decimal(card: &Card) -> (String, String) {
    use num_bigint::BigUint;
    let x_bytes = to_bytes![card.0.x].expect("serialize x");
    let y_bytes = to_bytes![card.0.y].expect("serialize y");
    (
        BigUint::from_bytes_le(&x_bytes).to_string(),
        BigUint::from_bytes_le(&y_bytes).to_string(),
    )
}

/// Coordenadas afines (x, y) de una carta ENMASCARADA (Ca, Cb) en decimal:
/// el formato wire del contrato/frontend (`getEncryptedCards`). Diagnostico.
pub fn masked_card_coords_decimal(card: &MaskedCard) -> [String; 4] {
    use num_bigint::BigUint;
    let dec = |v: &<Curve as ark_ec::ProjectiveCurve>::BaseField| {
        let bytes = to_bytes![v].expect("serialize coord");
        BigUint::from_bytes_le(&bytes).to_string()
    };
    [dec(&card.0.x), dec(&card.0.y), dec(&card.1.x), dec(&card.1.y)]
}

pub fn encode_cards<R: Rng>(rng: &mut R, num_of_cards: usize) -> HashMap<Card, ClassicPlayingCard> {
    let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
    let plaintexts = (0..num_of_cards)
        .map(|_| Card::rand(rng))
        .collect::<Vec<_>>();

    let mut i = 0;
    for value in Value::VALUES.iter().copied() {
        for suite in Suite::VALUES.iter().copied() {
            let current_card = ClassicPlayingCard::new(value, suite);
            map.insert(plaintexts[i], current_card);
            i += 1;
        }
    }

    map
}

pub fn encode_cards_ext(plaintexts:Vec<Card>) -> HashMap<Card, ClassicPlayingCard> {
    let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
    let mut i = 0;
    for value in Value::VALUES.iter().copied() {
        for suite in Suite::VALUES.iter().copied() {
            let current_card = ClassicPlayingCard::new(value, suite);
            map.insert(plaintexts[i], current_card);
            i += 1;
        }
    }

    map
}


pub fn generator() -> EdwardsAffine {
    EdwardsAffine::new(
        Fq::from_str(
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        )
    .unwrap(),
    Fq::from_str(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .unwrap(),
    )
}


pub enum State {
    WaitingForPlayers,
    WaitingForCards,
    WaitingForShuffle,
    WaitingForReveal,
    WaitingForEnd,
}


// pub fn shuffle_cards<R: Rng>(
//     rng: &mut R,
//     m: usize,
//     n: usize,
//     parameters: &CardParameters,
//     shared_key: &PublicKey,
//     deck: &Vec<MaskedCard>,
//     masking_factors: &Vec<Scalar>,
//     permutation: &Permutation,
// ) -> Result<(Vec<MaskedCard>, ZKProofShuffle), CardProtocolError> {

//     let permutation = Permutation::new(rng, m * n);
//     let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

//     let (a_shuffled_deck, a_shuffle_proof) = CardProtocol::shuffle_and_remask(
//         rng,
//         &parameters,
//         &shared_key,
//         &deck,
//         &masking_factors,
//         &permutation,
//     )?;
// }

#[cfg(test)]
mod canonical_deck_tests {
    use super::*;

    const NUM_OF_CARDS: usize = 52;

    #[test]
    fn canonical_deck_is_deterministic() {
        let a = generate_canonical_deck(NUM_OF_CARDS);
        let b = generate_canonical_deck(NUM_OF_CARDS);
        assert_eq!(a, b, "dos derivaciones deben producir el mismo mazo");
    }

    #[test]
    fn canonical_deck_has_52_distinct_points() {
        let deck = generate_canonical_deck(NUM_OF_CARDS);
        assert_eq!(deck.len(), NUM_OF_CARDS);
        let mut coords: Vec<(String, String)> =
            deck.iter().map(card_coords_decimal).collect();
        coords.sort();
        coords.dedup();
        assert_eq!(coords.len(), NUM_OF_CARDS, "hay puntos repetidos en el mazo");
    }

    /// Pin de oro: si la derivacion cambia (version de rand_chacha, de ark, o
    /// de la semilla), este test rompe ANTES de que el mazo del cliente deje
    /// de casar con el cardMapping persistido on-chain y el canonical-deck.json
    /// del deploy. Si rompe a proposito (cambio de dominio), regenerar el JSON
    /// con dump_canonical_deck, actualizar estas constantes y redesplegar.
    #[test]
    fn canonical_deck_golden_pin() {
        let deck = generate_canonical_deck(NUM_OF_CARDS);
        let (x0, y0) = card_coords_decimal(&deck[0]);
        let (x51, y51) = card_coords_decimal(&deck[51]);
        // GOLDEN_PIN: valores fijados en la primera derivacion (ver commit).
        assert_eq!(x0, GOLDEN_X0);
        assert_eq!(y0, GOLDEN_Y0);
        assert_eq!(x51, GOLDEN_X51);
        assert_eq!(y51, GOLDEN_Y51);
    }

    /// El `card_mapping` de una mano es exactamente el mazo canonico (mismo
    /// conjunto de 52 puntos), pero un HashMap NO conserva ese orden: las
    /// entradas publicas `m` del circuito de reshuffle deben salir del mazo
    /// canonico, nunca de `card_mapping.keys()` (2026-09-16: el primer
    /// reshuffle real fallaba con "m del bundle no coincide con m_list en la
    /// posicion 0" porque prover y verificador iteraban su propio HashMap).
    #[test]
    fn card_mapping_es_el_mazo_canonico_pero_no_su_orden() {
        let deck = generate_canonical_deck(NUM_OF_CARDS);
        let mapping = encode_cards_ext(deck.clone());
        assert_eq!(mapping.len(), NUM_OF_CARDS);
        for card in &deck {
            assert!(mapping.contains_key(card), "el mapping no contiene una carta del mazo canonico");
        }
        // Dos derivaciones independientes dan el mismo orden: es lo que hace
        // que prover y verificador coincidan sin intercambiar nada.
        assert_eq!(deck, generate_canonical_deck(NUM_OF_CARDS));
        // Un mapa reconstruido con otra insercion (como al restaurar un
        // snapshot) no tiene por que iterar igual: no hay que fiarse de
        // keys(). No se afirma que difieran (depende del hasher), solo que el
        // conjunto es el mismo — el ORDEN lo da el mazo canonico.
        let mut entries: Vec<(Card, ClassicPlayingCard)> =
            mapping.iter().map(|(card, classic)| (card.clone(), classic.clone())).collect();
        entries.reverse();
        let rebuilt: HashMap<Card, ClassicPlayingCard> = entries.into_iter().collect();
        assert_eq!(rebuilt.len(), NUM_OF_CARDS);
        for card in &deck {
            assert_eq!(rebuilt.get(card), mapping.get(card));
        }
    }

    // Fijados en la primera derivacion real 2026-07-18 (canonical_deck_print_golden,
    // stable-x86_64-pc-windows-msvc) — no inventados a mano.
    const GOLDEN_X0: &str =
        "11694183964472001047926894042924272449397587614265636681826143594141639093859";
    const GOLDEN_Y0: &str =
        "21581345873182909073841769149332526506110339946632099000480649919264535037125";
    const GOLDEN_X51: &str =
        "19003601969315543371389921540264059275493746026425554903402028743194677697307";
    const GOLDEN_Y51: &str =
        "19883967393943663021230260788008533988918422708598439811879002371669101517876";

    /// Utilidad para fijar el pin: imprime las esquinas del mazo.
    #[test]
    fn canonical_deck_print_golden() {
        let deck = generate_canonical_deck(NUM_OF_CARDS);
        let (x0, y0) = card_coords_decimal(&deck[0]);
        let (x51, y51) = card_coords_decimal(&deck[51]);
        println!("GOLDEN_X0  = {}", x0);
        println!("GOLDEN_Y0  = {}", y0);
        println!("GOLDEN_X51 = {}", x51);
        println!("GOLDEN_Y51 = {}", y51);
    }
}
