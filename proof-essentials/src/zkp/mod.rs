use crate::error::CryptoError;
use ark_marlin::rng::FiatShamirRng;
use ark_std::rand::Rng;
use digest::Digest;
use sha3::{Digest as Sha3Digest};
use sha3::digest::FixedOutputReset;

pub mod arguments;
pub mod proofs;
pub mod transcript;



pub trait ArgumentOfKnowledgeSchnorr {
    type CommonReferenceString;
    type Statement;
    type Witness;
    type Proof;

    fn prove<R: Rng, D: Sha3Digest + FixedOutputReset>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        hasher: &mut D,
    ) -> Result<Self::Proof, CryptoError>;

    fn verify<D: Sha3Digest + FixedOutputReset>(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        hasher: &mut D,
    ) -> Result<(), CryptoError>;
}

pub trait ArgumentOfKnowledge {
    type CommonReferenceString;
    type Statement;
    type Witness;
    type Proof;

    fn prove<R: Rng, D: Digest>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<Self::Proof, CryptoError>;

    fn verify<D: Digest>(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError>;
}
