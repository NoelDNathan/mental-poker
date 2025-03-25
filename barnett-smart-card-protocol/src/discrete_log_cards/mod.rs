use super::BarnettSmartProtocol;
use super::{Mask, Remask, Reveal};
use ark_bn254::Fr;
use ark_marlin::ahp::verifier;

use crate::error::CardProtocolError;

use anyhow::Result;
use ark_ff::{to_bytes, One, PrimeField, ToBytes};
use ark_marlin::rng::FiatShamirRng;
use ark_std::rand::Rng;
use ark_std::Zero;
use blake2::Blake2s;

use ark_std::UniformRand;
use num_bigint::BigUint;
use num_traits::Num;
use proof_essentials::error::CryptoError;
use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};

use proof_essentials::utils::permutation::Permutation;
use proof_essentials::vector_commitment::pedersen::PedersenCommitment;
use proof_essentials::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
use proof_essentials::zkp::{
    arguments::shuffle,
    proofs::{chaum_pedersen_dl_equality, schnorr_identification},
    ArgumentOfKnowledge,
};
use std::marker::PhantomData;

use babyjubjub::{self, Fq};

use regex;
use zk_reshuffle::{CircomProver, Proof};

use num_bigint::BigInt;

// mod key_ownership;
mod masking;
mod remasking;
mod reveal;
mod tests;
use ark_ec::{AffineCurve, ProjectiveCurve};

pub trait HasCoordinates {
    fn get_x(&self) -> String;
    fn get_y(&self) -> String;
}

pub trait GeneratePoints<P: ProjectiveCurve> {
    fn new(x: babyjubjub::Fq, y: babyjubjub::Fq) -> Self;
}

impl HasCoordinates for babyjubjub::EdwardsAffine {
    fn get_x(&self) -> String {
        self.x.to_string()
    }
    fn get_y(&self) -> String {
        self.y.to_string()
    }
}

impl GeneratePoints<babyjubjub::EdwardsProjective> for babyjubjub::EdwardsAffine {
    fn new(x: babyjubjub::Fq, y: babyjubjub::Fq) -> Self {
        babyjubjub::EdwardsAffine::new(x, y)
    }
}

pub struct DLCards<'a, C: ProjectiveCurve> {
    _group: &'a PhantomData<C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    m: usize,
    n: usize,
    enc_parameters: el_gamal::Parameters<C>,
    commit_parameters: pedersen::CommitKey<C>,
    generator: el_gamal::Generator<C>,
}

impl<C: ProjectiveCurve> Parameters<C> {
    pub fn new(
        m: usize,
        n: usize,
        enc_parameters: el_gamal::Parameters<C>,
        commit_parameters: pedersen::CommitKey<C>,
        generator: el_gamal::Generator<C>,
    ) -> Self {
        Self {
            m,
            n,
            enc_parameters,
            commit_parameters,
            generator,
        }
    }
}

pub type PublicKey<C> = el_gamal::PublicKey<C>;

pub type PlayerSecretKey<C> = el_gamal::SecretKey<C>;

/// An open playing card. In this Discrete Log-based implementation of the Barnett-Smart card protocol
/// a card is an el-Gamal plaintext. We create a type alias to implement the `Mask` trait on it.
pub type Card<C> = el_gamal::Plaintext<C>;

/// A masked (flipped) playing card. Note that a player masking a card will know the mapping from
/// open to masked card. All other players must remask to guarantee that the card is privately masked.
/// We create a type alias to implement the `Mask` trait on it.
pub type MaskedCard<C> = el_gamal::Ciphertext<C>;

/// A `RevealToken` is computed by players when they wish to reveal a given card. These tokens can
/// then be aggregated to reveal the card.
pub type RevealToken<C> = el_gamal::Plaintext<C>;

const KEY_OWN_RNG_SEED: &'static [u8] = b"Key Ownership Proof";
const MASKING_RNG_SEED: &'static [u8] = b"Masking Proof";
const REMASKING_RNG_SEED: &'static [u8] = b"Remasking Proof";
const REVEAL_RNG_SEED: &'static [u8] = b"Reveal Proof";
const SHUFFLE_RNG_SEED: &'static [u8] = b"Shuffle Proof";

impl<'a, C: ProjectiveCurve> BarnettSmartProtocol for DLCards<'a, C>
where
    C: ProjectiveCurve,
    C::Affine: HasCoordinates + GeneratePoints<C>,
{
    type Scalar = C::ScalarField;
    type Enc = ElGamal<C>;
    type Comm = PedersenCommitment<C>;
    type Parameters = Parameters<C>;
    type PlayerPublicKey = PublicKey<C>;
    type PlayerSecretKey = PlayerSecretKey<C>;
    type AggregatePublicKey = PublicKey<C>;

    type Card = Card<C>;
    type MaskedCard = MaskedCard<C>;
    type RevealToken = RevealToken<C>;

    type ZKProofKeyOwnership = schnorr_identification::proof::Proof<C>;
    type ZKProofMasking = chaum_pedersen_dl_equality::proof::Proof<C>;
    type ZKProofRemasking = chaum_pedersen_dl_equality::proof::Proof<C>;
    type ZKProofReveal = chaum_pedersen_dl_equality::proof::Proof<C>;
    type ZKProofShuffle = shuffle::proof::Proof<Self::Scalar, Self::Enc, Self::Comm>;
    type ZKProofCardRemoval = Proof;

    type Point = C;

    fn setup<R: Rng>(
        rng: &mut R,
        generator: C::Affine,
        m: usize,
        n: usize,
    ) -> Result<Self::Parameters, CardProtocolError> {
        let parameters = el_gamal::Parameters { generator };

        let enc_parameters = Self::Enc::setup_with_generator(parameters)?;

        let commit_parameters = Self::Comm::setup(rng, n);
        let generator = Self::Enc::generator(rng)?;

        Ok(Self::Parameters::new(
            m,
            n,
            enc_parameters,
            commit_parameters,
            generator,
        ))
    }

    fn player_keygen<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<(Self::PlayerPublicKey, Self::PlayerSecretKey), CardProtocolError> {
        let (pk, sk) = Self::Enc::keygen(&pp.enc_parameters, rng)?;

        Ok((pk, sk))
    }

    fn prove_key_ownership<B: ToBytes, R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        sk: &Self::PlayerSecretKey,
        player_public_info: &B,
    ) -> Result<Self::ZKProofKeyOwnership, CryptoError> {
        let mut fs_rng =
            FiatShamirRng::<Blake2s>::from_seed(&to_bytes![KEY_OWN_RNG_SEED, player_public_info]?);

        schnorr_identification::SchnorrIdentification::prove(
            rng,
            &pp.enc_parameters.generator,
            pk,
            sk,
            &mut fs_rng,
        )
    }

    fn verify_key_ownership<B: ToBytes>(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        player_public_info: &B,
        proof: &Self::ZKProofKeyOwnership,
    ) -> Result<(), CryptoError> {


        let mut fs_rng =
            FiatShamirRng::<Blake2s>::from_seed(&to_bytes![KEY_OWN_RNG_SEED, player_public_info]?);
        schnorr_identification::SchnorrIdentification::verify(
            &pp.enc_parameters.generator,
            pk,
            proof,
            &mut fs_rng,
        )
    }

    fn compute_aggregate_key<B: ToBytes>(
        pp: &Self::Parameters,
        player_keys_proof_info: &Vec<(Self::PlayerPublicKey, Self::ZKProofKeyOwnership, B)>,
    ) -> Result<Self::AggregatePublicKey, CardProtocolError> {
        let zero = Self::PlayerPublicKey::zero();

        let mut acc = zero;
        for (pk, proof, player_public_info) in player_keys_proof_info {
            Self::verify_key_ownership(pp, pk, player_public_info, proof)?;
            acc = acc + *pk;
        }

        Ok(acc)
    }

    fn mask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_card: &Self::Card,
        r: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ZKProofMasking), CardProtocolError> {
        let masked_card = original_card.mask(&pp.enc_parameters, shared_key, r)?;
        let gen = pp.enc_parameters.generator;

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(&gen, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Self::Scalar::one();
        let negative_original = original_card.0.mul(minus_one).into_affine();
        let statement_cipher = masked_card.1 + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&masked_card.0, &statement_cipher);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![MASKING_RNG_SEED]?);
        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            r,
            &mut fs_rng,
        )?;

        Ok((masked_card, proof))
    }

    fn verify_mask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        card: &Self::Card,
        masked_card: &Self::MaskedCard,
        proof: &Self::ZKProofMasking,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&pp.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -Self::Scalar::one();
        let negative_original = card.0.mul(minus_one).into_affine();
        let statement_cipher = masked_card.1 + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&masked_card.0, &statement_cipher);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![MASKING_RNG_SEED]?);
        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_card: &Self::MaskedCard,
        alpha: &Self::Scalar,
    ) -> Result<(Self::MaskedCard, Self::ZKProofRemasking), CardProtocolError> {
        let remasked = original_card.remask(&pp.enc_parameters, shared_key, alpha)?;

        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&pp.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -C::ScalarField::one();
        let negative_original = *original_card * minus_one;
        let statement_cipher = remasked + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REMASKING_RNG_SEED]?);
        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            alpha,
            &mut fs_rng,
        )?;

        Ok((remasked, proof))
    }

    fn verify_remask(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_masked: &Self::MaskedCard,
        remasked: &Self::MaskedCard,
        proof: &Self::ZKProofRemasking,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters =
            chaum_pedersen_dl_equality::Parameters::new(&pp.enc_parameters.generator, shared_key);

        // Map to Chaum-Pedersen statement
        let minus_one = -C::ScalarField::one();
        let negative_original = *original_masked * minus_one;
        let statement_cipher = *remasked + negative_original;
        let cp_statement =
            chaum_pedersen_dl_equality::Statement::new(&statement_cipher.0, &statement_cipher.1);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REMASKING_RNG_SEED]?);
        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn compute_reveal_token<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        sk: &Self::PlayerSecretKey,
        pk: &Self::PlayerPublicKey,
        masked_card: &Self::MaskedCard,
    ) -> Result<(Self::RevealToken, Self::ZKProofReveal), CardProtocolError> {
        let reveal_token: RevealToken<C> =
            el_gamal::Plaintext(masked_card.0.into().mul(sk.into_repr()).into_affine());

        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            &masked_card.0,
            &pp.enc_parameters.generator,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&reveal_token.0, pk);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REVEAL_RNG_SEED]?);
        let proof = chaum_pedersen_dl_equality::DLEquality::prove(
            rng,
            &cp_parameters,
            &cp_statement,
            sk,
            &mut fs_rng,
        )?;

        Ok((reveal_token, proof))
    }

    fn verify_reveal(
        pp: &Self::Parameters,
        pk: &Self::PlayerPublicKey,
        reveal_token: &Self::RevealToken,
        masked_card: &Self::MaskedCard,
        proof: &Self::ZKProofReveal,
    ) -> Result<(), CryptoError> {
        // Map to Chaum-Pedersen parameters
        let cp_parameters = chaum_pedersen_dl_equality::Parameters::new(
            &masked_card.0,
            &pp.enc_parameters.generator,
        );

        // Map to Chaum-Pedersen parameters
        let cp_statement = chaum_pedersen_dl_equality::Statement::new(&reveal_token.0, pk);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![REVEAL_RNG_SEED]?);
        chaum_pedersen_dl_equality::DLEquality::verify(
            &cp_parameters,
            &cp_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(
            Self::RevealToken,
            Self::ZKProofReveal,
            Self::PlayerPublicKey,
        )>,
        masked_card: &Self::MaskedCard,
    ) -> Result<Self::Card, CardProtocolError> {
        let zero = Self::RevealToken::zero();

        let mut aggregate_token = zero;

        for (token, proof, pk) in decryption_key {
            Self::verify_reveal(pp, pk, token, masked_card, proof)?;

            aggregate_token = aggregate_token + *token;
        }

        let decrypted = aggregate_token.reveal(masked_card)?;

        Ok(decrypted)
    }

    fn partial_unmask(
        pp: &Self::Parameters,
        decryption_key: &Vec<(
            Self::RevealToken,
            Self::ZKProofReveal,
            Self::PlayerPublicKey,
        )>,
        masked_card: &Self::MaskedCard,
    ) -> Result<Self::MaskedCard, CardProtocolError> {
        let zero = Self::RevealToken::zero();

        let mut aggregate_token = zero;

        for (token, proof, pk) in decryption_key {
            Self::verify_reveal(pp, pk, token, masked_card, proof)?;

            aggregate_token = aggregate_token + *token;
        }

        let neg_one = -C::ScalarField::one();
        let negative_token = aggregate_token.0.mul(neg_one).into_affine();
        let partial_decrypted = el_gamal::Ciphertext(masked_card.0, masked_card.1 + negative_token);

        Ok(partial_decrypted)
    }

    fn shuffle_and_remask<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        deck: &Vec<Self::MaskedCard>,
        masking_factors: &Vec<Self::Scalar>,
        permutation: &Permutation,
    ) -> Result<(Vec<Self::MaskedCard>, Self::ZKProofShuffle), CardProtocolError> {
        let permuted_deck = permutation.permute_array(&deck);
        let masked_shuffled = permuted_deck
            .iter()
            .zip(masking_factors.iter())
            .map(|(masked_card, masking_factor)| {
                masked_card.remask(&pp.enc_parameters, &shared_key, masking_factor)
            })
            .collect::<Result<Vec<_>, CardProtocolError>>()?;

        let shuffle_parameters = shuffle::Parameters::new(
            &pp.enc_parameters,
            shared_key,
            &pp.commit_parameters,
            &pp.generator,
        );

        let shuffle_statement = shuffle::Statement::new(deck, &masked_shuffled, pp.m, pp.n);

        let witness = shuffle::Witness::new(permutation, masking_factors);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![SHUFFLE_RNG_SEED]?);
        let proof = shuffle::ShuffleArgument::prove(
            rng,
            &shuffle_parameters,
            &shuffle_statement,
            &witness,
            &mut fs_rng,
        )?;

        Ok((masked_shuffled, proof))
    }

    fn verify_shuffle(
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_deck: &Vec<Self::MaskedCard>,
        shuffled_deck: &Vec<Self::MaskedCard>,
        proof: &Self::ZKProofShuffle,
    ) -> Result<(), CryptoError> {
        let shuffle_parameters = shuffle::Parameters::new(
            &pp.enc_parameters,
            shared_key,
            &pp.commit_parameters,
            &pp.generator,
        );

        let shuffle_statement = shuffle::Statement::new(original_deck, shuffled_deck, pp.m, pp.n);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&to_bytes![SHUFFLE_RNG_SEED]?);
        shuffle::ShuffleArgument::verify(
            &shuffle_parameters,
            &shuffle_statement,
            proof,
            &mut fs_rng,
        )
    }

    fn parse_and_convert_to_decimal(input: &str) -> BigUint {
        // Extraer el número hexadecimal entre paréntesis usando expresiones regulares
        let re = regex::Regex::new(r"\(([0-9A-Fa-f]+)\)").unwrap();
        let hex_str = if let Some(caps) = re.captures(input) {
            caps.get(1).unwrap().as_str()
        } else {
            // Si no hay paréntesis, asumimos que ya es un número hexadecimal
            input.trim_matches(|c| c == '"' || c == '\\')
        };

        // Convertir de hexadecimal a decimal
        let x_bigint = BigUint::from_str_radix(hex_str, 16).unwrap();

        x_bigint
    }

    fn to_hex(point: C) -> [BigUint; 2]
    where
        C::Affine: HasCoordinates,
    {
        let x = point.into_affine().get_x();
        let y = point.into_affine().get_y();

        let x_bigint = Self::parse_and_convert_to_decimal(&x);
        let y_bigint = Self::parse_and_convert_to_decimal(&y);

        [x_bigint, y_bigint]
    }

    #[allow(non_snake_case)]
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
    ) -> Result<(Vec<Fr>, Self::ZKProofCardRemoval), CardProtocolError> {
        
        if player_cards.iter().any(|card| card.is_none()) {
            return Err(CardProtocolError::Other("Player cards cannot be None".to_string()));
        }
        let player_cards = player_cards.iter().map(|card| card.unwrap()).collect::<Vec<_>>();

        
        let H = shared_key;
        let H_str = Self::to_hex(H.into_projective());
        let G = pp.enc_parameters.generator;
        let G_str = Self::to_hex(G.into_projective());

        let (Ca, Cb): (Vec<_>, Vec<_>) = deck
            .iter()
            .map(|masked_card| {
                let c1 = masked_card.0; // Ca component
                let c2 = masked_card.1; // Cb component
                (c1, c2)
            })
            .unzip();

        for i in 0..52 {
            let r = &r_prime[i];
            let r_str = Self::parse_and_convert_to_decimal(&r.to_string());
            let r_prime_G_precomputed = G.mul(*r);
            let r_prime_H_precomputed = H.mul(*r);

            let r_prime_G_precomputed_str = Self::to_hex(r_prime_G_precomputed);
            let r_prime_H_precomputed_str = Self::to_hex(r_prime_H_precomputed);

            prover.add_input(
                "r_prime_G",
                BigInt::from(r_prime_G_precomputed_str[0].clone()),
            );
            prover.add_input(
                "r_prime_G",
                BigInt::from(r_prime_G_precomputed_str[1].clone()),
            );
            prover.add_input(
                "r_prime_H",
                BigInt::from(r_prime_H_precomputed_str[0].clone()),
            );
            prover.add_input(
                "r_prime_H",
                BigInt::from(r_prime_H_precomputed_str[1].clone()),
            );
            prover.add_input("r_prime", r_str);
        }

        let Ca1_player = Self::to_hex(player_cards[0].0.into_projective());
        let Cb1_player = Self::to_hex(player_cards[0].1.into_projective());
        let Ca2_player = Self::to_hex(player_cards[1].0.into_projective());
        let Cb2_player = Self::to_hex(player_cards[1].1.into_projective());

        let Ca_list = Ca
            .iter()
            .flat_map(|point| Self::to_hex(point.into_projective()).to_vec())
            .collect::<Vec<BigUint>>();

        let Cb_list = Cb
            .iter()
            .flat_map(|point| Self::to_hex(point.into_projective()).to_vec())
            .collect::<Vec<BigUint>>();

        let pk_str = Self::to_hex(pk.into_projective());
        let sk_str = Self::parse_and_convert_to_decimal(&sk.to_string());

        prover.add_input("sk", sk_str);
        prover.add_input("H", BigInt::from(H_str[0].clone()));
        prover.add_input("H", BigInt::from(H_str[1].clone()));
        prover.add_input("pk", BigInt::from(pk_str[0].clone()));
        prover.add_input("pk", BigInt::from(pk_str[1].clone()));
        prover.add_input("G", BigInt::from(G_str[0].clone()));
        prover.add_input("G", BigInt::from(G_str[1].clone()));
        prover.add_input("Ca1_player", BigInt::from(Ca1_player[0].clone()));
        prover.add_input("Ca1_player", BigInt::from(Ca1_player[1].clone()));
        prover.add_input("Cb1_player", BigInt::from(Cb1_player[0].clone()));
        prover.add_input("Cb1_player", BigInt::from(Cb1_player[1].clone()));
        prover.add_input("Ca2_player", BigInt::from(Ca2_player[0].clone()));
        prover.add_input("Ca2_player", BigInt::from(Ca2_player[1].clone()));
        prover.add_input("Cb2_player", BigInt::from(Cb2_player[0].clone()));
        prover.add_input("Cb2_player", BigInt::from(Cb2_player[1].clone()));

        for m in m_list {
            let m_str = Self::to_hex(m.0.into_projective());
            prover.add_input("m", BigInt::from(m_str[0].clone()));
            prover.add_input("m", BigInt::from(m_str[1].clone()));
        }

        for ca in Ca_list {
            prover.add_input("Ca", ca);
        }
        for cb in Cb_list {
            prover.add_input("Cb", cb);
        }

        // let Ca_str = Ca.iter().map(|ca| ca.to_string()).collect::<Vec<String>>();
        // let Cb_str = Cb.iter().map(|cb| cb.to_string()).collect::<Vec<String>>();

        // let Ca1_player_str = Ca1_player
        //     .iter()
        //     .map(|ca| ca.to_string())
        //     .collect::<Vec<String>>();
        // let Cb1_player_str = Cb1_player
        //     .iter()
        //     .map(|cb| cb.to_string())
        //     .collect::<Vec<String>>();
        // let Ca2_player_str = Ca2_player
        //     .iter()
        //     .map(|ca| ca.to_string())
        //     .collect::<Vec<String>>();
        // let Cb2_player_str = Cb2_player
        //     .iter()
        //     .map(|cb| cb.to_string())
        //     .collect::<Vec<String>>();

        let (raw_inputs, proof) = prover
            .generate_proof()
            .map_err(|e| CardProtocolError::Other(format!("{}", e)))?;

        let inputs: Vec<Fr> = raw_inputs
            .into_iter()
            .map(|x| Fr::from(BigUint::from(x)))
            .collect();

        Ok((inputs, proof))
    }

    fn verify_reshuffle_remask(
        verifier: &mut CircomProver,
        pp: &Self::Parameters,
        shared_key: &Self::AggregatePublicKey,
        original_deck: &Vec<Self::MaskedCard>,
        player_cards: &Vec<Self::MaskedCard>,
        pk: &Self::PlayerPublicKey,
        m_list: &Vec<Self::Card>,
        public: Vec<Fr>,
        proof: Self::ZKProofCardRemoval,
    ) -> Result<Vec<Self::MaskedCard>, CardProtocolError>
    where
        C: ProjectiveCurve,
        C::Affine: HasCoordinates + GeneratePoints<C>,
    {
        let verified = verifier
            .verify_proof(&public, &proof)
            .map_err(|e| CardProtocolError::Other(format!("{}", e)))?;

        if verified {
            let pk_computed = &public[0..2];
            let Ca_out = &public[2..106];
            let Cb_out = &public[106..210];

            let pk = &public[210..212];
            let H = &public[212..214];
            let G = &public[214..216];
            let Ca1_player = &public[216..218];
            let Cb1_player = &public[218..220];
            let Ca2_player = &public[220..222];
            let Cb2_player = &public[222..224];
            let m = &public[224..328];
            let Ca = &public[328..432];
            let Cb = &public[432..536];

            // println!("Ca:out {:?}", Ca);
            // println!("Cb:out {:?}", Cb);

            // Checks
            // if(H.to_string() != shared_key.0.to_string()) {
            //     return Err(CardProtocolError::Other("H is not equal to shared_key.0".to_string()));
            //

            let mut masked_cards: Vec<Self::MaskedCard> = Vec::with_capacity(52);

            for i in 0..52 {
                let cax = Ca_out[i * 2];
                let cay = Ca_out[i * 2 + 1];
                let cbx = Cb_out[i * 2];
                let cby = Cb_out[i * 2 + 1];

                let cax = Fq::from(BigUint::from(cax));
                let cay = Fq::from(BigUint::from(cay));
                let cbx = Fq::from(BigUint::from(cbx));
                let cby = Fq::from(BigUint::from(cby));

                let ca = C::Affine::new(cax, cay);
                let cb = C::Affine::new(cbx, cby);

                let masked_card = el_gamal::Ciphertext(ca, cb);
                masked_cards.push(masked_card);
            }
            println!("Verification successful!!!");
            Ok(masked_cards)
        } else {
            Err(CardProtocolError::Other("Verification failed".to_string()))
        }
    }
}
