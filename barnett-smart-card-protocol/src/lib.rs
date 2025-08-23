use crate::error::CardProtocolError;
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, ToBytes};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_bn254::Fr;
use discrete_log_cards::MaskedCard;
use num::BigUint;
use proof_essentials::error::CryptoError;
use proof_essentials::homomorphic_encryption::HomomorphicEncryptionScheme;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::vector_commitment::HomomorphicCommitmentScheme;
use zk_reshuffle::CircomProver;
use std::hash::Hash;
use std::ops::{Add, Mul};

pub mod discrete_log_cards;
pub mod error;

pub trait Mask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn mask(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Result<Enc::Ciphertext, CardProtocolError>;
}

pub trait Remask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn remask(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Result<Enc::Ciphertext, CardProtocolError>;
}

pub trait Reveal<F: Field, Enc: HomomorphicEncryptionScheme<F>> {
    fn reveal(&self, cipher: &Enc::Ciphertext) -> Result<Enc::Plaintext, CardProtocolError>;
}

/// Mental Poker protocol based on the one described by Barnett and Smart (2003).
/// The protocol has been modified to make use of the argument of a correct shuffle presented
/// by Bayer and Groth (2014).
pub trait BarnettSmartProtocol {
    // Cryptography
    type Scalar: Field;
    type Parameters;
    type PlayerPublicKey: CanonicalDeserialize + CanonicalSerialize;
    type PlayerSecretKey;
    type AggregatePublicKey: CanonicalDeserialize + CanonicalSerialize;
    type Enc: HomomorphicEncryptionScheme<Self::Scalar>;
    type Comm: HomomorphicCommitmentScheme<Self::Scalar>;
    type Point: ProjectiveCurve;

    // Cards
    type Card: Copy
        + Clone
        + Mask<Self::Scalar, Self::Enc>
        + CanonicalDeserialize
        + CanonicalSerialize
        + Hash
        + Eq;
    type MaskedCard: Remask<Self::Scalar, Self::Enc> + CanonicalDeserialize + CanonicalSerialize;
    type RevealToken: Add
        + Reveal<Self::Scalar, Self::Enc>
        + Mul<Self::Scalar, Output = Self::RevealToken>
        + CanonicalDeserialize
        + CanonicalSerialize;

    // Proofs
    type ZKProofKeyOwnership: CanonicalDeserialize + CanonicalSerialize;
    type ZKProofMasking: CanonicalDeserialize + CanonicalSerialize;
    type ZKProofRemasking: CanonicalDeserialize + CanonicalSerialize;
    type ZKProofReveal: CanonicalDeserialize + CanonicalSerialize;
    type ZKProofShuffle: CanonicalDeserialize + CanonicalSerialize;
    type ZKProofGroth16;

    /// Randomly produce the scheme parameters
    fn setup<R: Rng>(
        rng: &mut R,
        generator: <Self::Point as ProjectiveCurve>::Affine,
        m: usize,
        n: usize,
    ) -> Result<Self::Parameters, CardProtocolError>;

    /// Generate keys for a player.
    fn player_keygen<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError>;

    /// Prove in zero knowledge that the owner of a public key `pk` knows the corresponding secret key `sk`
    fn prove_key_ownership<B: ToBytes, R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
        player_public_info: &B,
    ) -> Result<Self::ZKProofKeyOwnership, CryptoError>;

    /// Verify a proof od key ownership
    fn verify_key_ownership<B: ToBytes>(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        player_public_info: &B,
        proof: &Self::ZKProofKeyOwnership,
    ) -> Result<(), CryptoError>;

    /// Use all the public keys and zk-proofs to compute a verified aggregate public key
    fn compute_aggregate_key<B: ToBytes>(
        pp: &Self::Parameters,
        player_keys_proof_info: &Vec<(Self::PlayerPublicKey, Self::ZKProofKeyOwnership, B)>,
    ) -> Result<Self::AggregatePublicKey, CardProtocolError>;

    /// Use the shared public key and a (private) random scalar `alpha` to mask a card.
    /// Returns a masked card and a zk-proof that the masking operation was applied correctly.
    fn mask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_card: &Self::Card,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ZKProofMasking), CardProtocolError>;

    /// Verify a proof of masking
    fn verify_mask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        card: &Self::Card,
        masked_card: &Self::MaskedCard,
        proof: &Self::ZKProofMasking,
    ) -> Result<(), CryptoError>;

    /// Use the shared public key and a (private) random scalar `alpha` to remask a masked card.
    /// Returns a masked card and a zk-proof that the remasking operation was applied correctly.
    fn remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_masked: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ZKProofRemasking), CardProtocolError>;

    /// Verify a proof of remasking
    fn verify_remask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_masked: &Self::MaskedCard,
        remasked: &Self::MaskedCard,
        proof: &Self::ZKProofRemasking,
    ) -> Result<(), CryptoError>;

    /// Players can use this function to compute their reveal token for a given masked card.
    /// The token is accompanied by a proof that it is a valid reveal for the specified card issued
    /// by the player who ran the computation.
    fn compute_reveal_token<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        sk: &Self::PlayerSecretKey,
        pk: &Self::PlayerPublicKey,
        masked_card: &Self::MaskedCard,
    ) -> Result<(Self::RevealToken, Self::ZKProofReveal), CardProtocolError>;

    /// Verify a proof of correctly computed reveal token
    fn verify_reveal(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        reveal_token: &Self::RevealToken,
        masked_card: &Self::MaskedCard,
        proof: &Self::ZKProofReveal,
    ) -> Result<(), CryptoError>;

    /// After collecting all the necessary reveal tokens and proofs that these are correctly issued,
    /// players can unmask a masked card to recover the underlying card.
    fn unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(
            Self::RevealToken,
            Self::ZKProofReveal,
            Self::PlayerPublicKey,
        )>,
        masked_card: &Self::MaskedCard,
    ) -> Result<Self::Card, CardProtocolError>;
    
    fn partial_unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(
            Self::RevealToken,
            Self::ZKProofReveal,
            Self::PlayerPublicKey,
        )>,
        masked_card: &Self::MaskedCard,
    ) -> Result<Self::MaskedCard, CardProtocolError>;

    /// Shuffle and remask a deck of masked cards using a player-chosen permutation and vector of
    /// masking factors.
    fn shuffle_and_remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        deck: &Vec<Self::MaskedCard>,
        masking_factors: &Vec<Self::Scalar>,
        permutation: &Permutation,
    ) -> Result<(Vec<Self::MaskedCard>, Self::ZKProofShuffle), CardProtocolError>;

    /// Verify a proof of correct shuffle
    fn verify_shuffle(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_deck: &Vec<Self::MaskedCard>,
        shuffled_deck: &Vec<Self::MaskedCard>,
        proof: &Self::ZKProofShuffle,
    ) -> Result<(), CryptoError>;

    fn shuffle_and_remask2(
        prover: &mut CircomProver,
        permutation: &Permutation,
        r_prime: &mut Vec<Self::Scalar>,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        deck: &Vec<Self::MaskedCard>,
    ) -> Result<(Vec<Fr>, Self::ZKProofGroth16), CardProtocolError>;

    fn verify_shuffle_remask2(
        prover: &mut CircomProver,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_deck: &Vec<Self::MaskedCard>,
        public: Vec<Fr>,
        proof: Self::ZKProofGroth16,
    ) -> Result<Vec<Self::MaskedCard>, CardProtocolError>;


    fn parse_and_convert_to_decimal(input: &str) -> BigUint;

    fn to_hex(point: Self::Point) -> [BigUint; 2];

    fn remask_for_reshuffle(
        prover: &mut CircomProver,
        r_prime: &mut Vec<Self::Scalar>,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        deck: &Vec<Self::MaskedCard>,
        player_cards: &Vec<Option<Self::MaskedCard>>,
        sk: &Self::PlayerSecretKey,
        pk: &Self::PlayerPublicKey,
        m_list: &Vec<Self::Card>,
    ) -> Result<(Vec<Fr>, Self::ZKProofGroth16), CardProtocolError>;

    fn verify_reshuffle_remask(
        prover: &mut CircomProver,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_deck: &Vec<Self::MaskedCard>,
        player_cards: &Vec<Self::MaskedCard>,
        pk: &Self::PlayerPublicKey,
        m_list: &Vec<Self::Card>,
        public: Vec<Fr>,
        proof: Self::ZKProofGroth16,
    ) -> Result<Vec<Self::MaskedCard>, CardProtocolError>;
}
