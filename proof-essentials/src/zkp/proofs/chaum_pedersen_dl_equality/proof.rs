use crate::error::CryptoError;

use super::{Parameters, Statement};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::UniformRand;
use hex;
use sha3::digest::FixedOutputReset;
use sha3::Digest;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub a: C,
    pub b: C,
    pub r: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify<D: Digest + FixedOutputReset>(
        &self,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        hasher: &mut D,
    ) -> Result<(), CryptoError> {
        // println!("verify parameters.g (P): {:?}", parameters.g.to_string());
        // println!("verify parameters.h (Q): {:?}", parameters.h.to_string());
        // println!("verify statement.0 (R): {:?}", statement.0.to_string());
        // println!("verify statement.1 (S): {:?}", statement.1.to_string());
        // println!("verify self.a: {:?}", self.a.to_string());
        // println!("verify self.b: {:?}", self.b.to_string());
        // println!("verify self.r (s): {:?}", self.r.to_string());

        let bytes = to_bytes![
            b"chaum_pedersen",
            parameters.g,
            parameters.h,
            statement.0,
            statement.1,
            &self.a.into_affine(),
            &self.b.into_affine()
        ]?;

        println!("verify bytes: {:?}", hex::encode(bytes.clone()));

        sha3::digest::Update::update(hasher, &bytes);

        let hash_bytes = hasher.finalize_reset();

        println!("verify hash_bytes: {:?}", hex::encode(hash_bytes.clone()));

        let c = C::ScalarField::from_be_bytes_mod_order(&hash_bytes);

        println!("verify c: {:?}", c.to_string());
        // g * r ==? a + x*c
        if parameters.g.mul(self.r) != self.a + statement.0.mul(c) {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen",
            )));
        }

        // h * r ==? b + y*c
        if parameters.h.mul(self.r) != self.b + statement.1.mul(c) {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen",
            )));
        }

        Ok(())
    }
}
