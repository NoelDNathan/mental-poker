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
use zk_reshuffle::CircomProver;

use ark_ec::{AffineCurve, ProjectiveCurve};
use babyjubjub::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use std::str::FromStr;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Write, Read, SerializationError};



type Curve = EdwardsProjective;
pub type Scalar = Fr;

// Instantiate concrete type for our card protocol
pub type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
pub type CardParameters = discrete_log_cards::Parameters<Curve>;
pub type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

pub type Card = discrete_log_cards::Card<Curve>;
pub type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
pub type RevealToken = discrete_log_cards::RevealToken<Curve>;

pub type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
pub type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
pub type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
pub type ZKProofShuffle = proof_essentials::zkp::arguments::shuffle::proof::Proof<ark_ff::Fp256<babyjubjub::FrParameters>, proof_essentials::homomorphic_encryption::el_gamal::ElGamal<ark_ec::twisted_edwards_extended::GroupProjective<babyjubjub::EdwardsParameters>>, proof_essentials::vector_commitment::pedersen::PedersenCommitment<ark_ec::twisted_edwards_extended::GroupProjective<babyjubjub::EdwardsParameters>>>;


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
    ) -> Result<(), anyhow::Error> {

        let i: Option<usize> = self.cards.iter().position(|&x| x == *card);

        let i = i.ok_or(GameErrors::CardNotFound)?;

        let public_card = CardProtocol::partial_unmask(&parameters, reveal_tokens, card)?;

        self.cards_public[i] = Some(public_card);

        //TODO add function to create that without the proof
        let rng = &mut thread_rng();
        let own_reveal_token = self.compute_reveal_token(rng, parameters, card)?;
        reveal_tokens.push(own_reveal_token);

        println!("Reveal tokens 1: {:?}", reveal_tokens[0].0.0.to_string());
        println!("Reveal tokens 2: {:?}", reveal_tokens[1].0.0.to_string());

        let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
        // println!("Unmasked card: {:?}", unmasked_card.0.to_string());

        // for (card, value) in card_mappings.iter() {
        //     println!("{:?} -> {:?}", card.0.to_string(), value);
        // }

        println!("Unmasked card: {:?}", unmasked_card.0.to_string());
        let opened_card = card_mappings.get(&unmasked_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;
        
        self.opened_cards[i] = Some(*opened_card);
        Ok(())
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