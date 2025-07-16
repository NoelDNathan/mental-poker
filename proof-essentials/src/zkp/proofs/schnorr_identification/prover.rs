use crate::error::CryptoError;

use super::{proof::Proof, Parameters, Statement, Witness};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use sha3::Digest;
use sha3::digest::FixedOutputReset;

use std::marker::PhantomData;

pub struct Prover<C>
where
    C: ProjectiveCurve,
{
    phantom: PhantomData<C>,
}

impl<C> Prover<C>
where
    C: ProjectiveCurve,
{
    pub fn create_proof<R: Rng, D: Digest + FixedOutputReset>(
        rng: &mut R,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        hasher: &mut D,
    ) -> Result<Proof<C>, CryptoError> {
        let random = C::ScalarField::rand(rng);

        let random_commit = pp.mul(random.into_repr());

        sha3::digest::Update::update(hasher, &to_bytes![
            b"schnorr_identity",
            pp,
            statement,
            random_commit.into_affine()
        ]?);


        let c = C::ScalarField::from_be_bytes_mod_order(&hasher.finalize_reset());
        // let c = C::ScalarField::rand(fs_rng);

        let opening = random - c * witness;

        Ok(Proof {
            random_commit,
            opening,
        })
    }
}
