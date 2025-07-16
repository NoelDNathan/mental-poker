use super::{Parameters, Statement};
use crate::error::CryptoError;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::UniformRand;
use hex;
use sha3::digest::FixedOutputReset;
use sha3::{Digest, Keccak256};
use ark_ff::Field;

#[derive(Copy, Clone, CanonicalDeserialize, CanonicalSerialize, Debug, PartialEq, Eq)]
pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub random_commit: C,
    pub opening: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify<D: Digest + FixedOutputReset>(
        &self,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        hasher: &mut D,
    ) -> Result<(), CryptoError> {
        let bytes = to_bytes![
            b"schnorr_identity",
            pp,
            statement,
            &self.random_commit.into_affine()
        ]?;

        sha3::digest::Update::update(hasher, &bytes);

        let hash_bytes = hasher.finalize_reset();


        let c = C::ScalarField::from_be_bytes_mod_order(&hash_bytes);

        println!("................................................................");
        println!("................................................................");
        println!("c: {:?}", c.to_string());
        println!("statement (PK): {:?}", statement.to_string());
        println!("random commit (R): {:?}", self.random_commit.to_string());
        println!("opening (S): {:?}", self.opening.to_string());

        if pp.mul(self.opening.into_repr()) + statement.mul(c.into_repr()) != self.random_commit {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification",
            )));
        }

        Ok(())
    }
}
