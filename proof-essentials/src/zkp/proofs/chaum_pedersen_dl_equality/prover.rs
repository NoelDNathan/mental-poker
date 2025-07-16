use crate::error::CryptoError;

use super::proof::Proof;
use super::{Parameters, Statement, Witness};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_marlin::rng::FiatShamirRng;
use ark_std::{rand::Rng, UniformRand};
use sha3::digest::FixedOutputReset;
use sha3::Digest;
use hex;

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
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        hasher: &mut D,
    ) -> Result<Proof<C>, CryptoError> {

        let bytes = to_bytes![
            b"chaum_pedersen",
            parameters.g,
            parameters.h,
            statement.0,
            statement.1
        ]?;

        sha3::digest::Update::update(hasher, &bytes.clone());

        let hash_bytes = hasher.finalize_reset();

        let omega = C::ScalarField::from_be_bytes_mod_order(&hash_bytes);
        let a = parameters.g.mul(omega.into_repr());
        let b = parameters.h.mul(omega.into_repr());

        let bytes2 = to_bytes![
            b"chaum_pedersen",
            parameters.g,
            parameters.h,
            statement.0,
            statement.1,
            a.into_affine(),
            b.into_affine()]?;
        sha3::digest::Update::update(hasher, &bytes2);

        let hash_bytes2 = hasher.finalize_reset();

        let c = C::ScalarField::from_be_bytes_mod_order(&hash_bytes2);

        let r = omega + c * *witness;

        Ok(Proof { a, b, r })
    }
}
