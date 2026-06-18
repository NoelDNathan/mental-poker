//! R1CS + ConstraintSynthesizer sin wasmer (vendored del lab
//! `zk-bench/native-provers/legogroth16-circuit`).
//!
//! Replica EXACTAMENTE `legogroth16::circom::CircomCircuit::generate_constraints`
//! (que vive bajo la feature `circom`, la cual arrastra wasmer y no compila a
//! wasm32). Al replicarlo aqui sin wasmer, el sistema de restricciones es
//! identico: una proving key generada con `ProverCircuit` verifica proofs
//! generadas con `ProverCircuit`.
//!
//! Orden de wires (convencion circom, igual que CircomCircuit):
//!   wires[0] = 1 ; wires[1..num_public] = public ; wires[num_public..] = private

use ark_bn254::Fr;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Una restriccion `a * b - c = 0`; cada LC es lista de (indice_wire, coef).
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1csConstraint {
    pub a: Vec<(u32, Fr)>,
    pub b: Vec<(u32, Fr)>,
    pub c: Vec<(u32, Fr)>,
}

/// R1CS aplanado en un formato que controlamos en ambos extremos.
#[derive(Clone, Debug, PartialEq, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitR1cs {
    pub num_public: u32,
    pub num_private: u32,
    pub constraints: Vec<R1csConstraint>,
}

/// Circuito para generar parametros (wires = None) o probar (wires = Some).
#[derive(Clone)]
pub struct ProverCircuit {
    pub r1cs: CircuitR1cs,
    pub wires: Option<Vec<Fr>>,
}

impl ConstraintSynthesizer<Fr> for ProverCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let wires = &self.wires;
        let num_public = self.r1cs.num_public as usize;
        let num_private = self.r1cs.num_private as usize;
        let dummy = Fr::from(0u32);

        // Arkworks asigna One implicitamente; las publicas empiezan en 1.
        for i in 1..num_public {
            cs.new_input_variable(|| Ok(wires.as_ref().map(|w| w[i]).unwrap_or(dummy)))?;
        }
        for i in 0..num_private {
            cs.new_witness_variable(|| {
                Ok(wires.as_ref().map(|w| w[i + num_public]).unwrap_or(dummy))
            })?;
        }

        let make_index = |index: usize| {
            if index < num_public {
                Variable::Instance(index)
            } else {
                Variable::Witness(index - num_public)
            }
        };
        let make_lc = |terms: &[(u32, Fr)]| {
            terms.iter().fold(
                LinearCombination::<Fr>::zero(),
                |lc, (index, coeff)| lc + (*coeff, make_index(*index as usize)),
            )
        };

        for c in &self.r1cs.constraints {
            cs.enforce_constraint(make_lc(&c.a), make_lc(&c.b), make_lc(&c.c))?;
        }
        Ok(())
    }
}
