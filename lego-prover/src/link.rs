//! Generadores NUMS del cp_link y calculo de `link_d`, copiado tal cual del
//! lab (`zk-bench/native-provers/legogroth16-poc/src/main.rs`). Es la pieza que
//! debe reproducir bit a bit lo que el lab exporto a
//! `bench-results/legogroth16/link_d.json`: misma derivacion hash-to-curve,
//! mismos dominios, mismo orden de MSM.

use ark_bn254::{Bn254, Fr, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};

use legogroth16::LinkPublicGenerators;

type E = Bn254;

/// r_prime_G[104] || r_prime_H[104]: las 208 senales comprometidas, identicas
/// entre el residual y el precompute (es lo que enlaza ambas proofs).
pub const COMMIT_WITNESS_COUNT: u32 = 208;

const DOMAIN_PEDERSEN: &str = "dog-poker-club/link-gens/v1";
const DOMAIN_G1: &str = "dog-poker-club/link-g1/v1";
const DOMAIN_G2: &str = "dog-poker-club/link-g2/v1";

// Generadores Pedersen NUMS ("nothing-up-my-sleeve") por hash-to-curve
// try-and-increment: x = SHA256(dominio || indice || contador) interpretado en
// Fq; si x^3 + 3 es residuo cuadratico, el punto (x, sqrt) esta en la curva
// (BN254 G1 tiene cofactor 1: curva == subgrupo). Deterministico y auditable
// en cualquier lenguaje -> NADIE conoce relaciones de dlog entre los
// generadores y esta parte de la ceremonia desaparece.
pub fn nums_g1(domain: &str, index: u32) -> G1Affine {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};
    for ctr in 0u32..u32::MAX {
        let mut h = Sha256::new();
        h.update(domain.as_bytes());
        h.update(index.to_le_bytes());
        h.update(ctr.to_le_bytes());
        let x = ark_bn254::Fq::from_le_bytes_mod_order(&h.finalize());
        // greatest=false fijo: eleccion canonica del signo de y.
        if let Some(p) = G1Affine::get_point_from_x_unchecked(x, false) {
            return p;
        }
    }
    unreachable!("no point found");
}

// Escalar NUMS publico: para el generador G2 basta un multiplo PUBLICO del
// generador estandar (el trapdoor del subspace es k/a, no g2).
pub fn nums_fr(domain: &str) -> Fr {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    Fr::from_le_bytes_mod_order(&h.finalize())
}

/// UN solo `LinkPublicGenerators` compartido por las dos proofs (residual y
/// precompute). `count` = COMMIT_WITNESS_COUNT + 1 (el +1 es el blinding
/// `link_v`). Compartirlo es lo que hace comparables los commitments.
pub fn make_link_gens(count: u32) -> LinkPublicGenerators<E> {
    let pedersen_gens = (0..count)
        .map(|i| nums_g1(DOMAIN_PEDERSEN, i))
        .collect::<Vec<G1Affine>>();
    LinkPublicGenerators {
        pedersen_gens,
        g1: nums_g1(DOMAIN_G1, 0),
        g2: (<E as Pairing>::G2Affine::generator() * nums_fr(DOMAIN_G2)).into_affine(),
    }
}

/// Commitment Pedersen del cp_link calculado fuera del prover:
/// `link_d = MSM(link_bases, comm_wits || link_v)`. Es exactamente lo que
/// `create_random_proof_incl_cp_link` deja en `proof.link_d`.
pub fn compute_link_d(link_bases: &[G1Affine], comm_wits: &[Fr], link_v: Fr) -> G1Affine {
    use ark_ec::VariableBaseMSM;
    use ark_ff::PrimeField;
    let mut scalars: Vec<_> = comm_wits.iter().map(|f| f.into_bigint()).collect();
    scalars.push(link_v.into_bigint());
    <E as Pairing>::G1::msm_bigint(&link_bases[..scalars.len()], &scalars).into_affine()
}
