//! Fiat-Shamir del shuffle lego (challenges alpha/beta), con el MISMO encoding
//! keccak que el verifier Solidity (`VerifyShufflingLego` / el script del lab
//! `zk-bench/scripts/derive-lego-fs-challenges.mjs`):
//!
//! ```text
//! alpha = keccak256(abi.encodePacked(uint8(1), link_d.x, link_d.y, pubs)) mod r
//! beta  = keccak256(abi.encodePacked(uint8(2), link_d.x, link_d.y, pubs)) mod r
//! ```
//!
//! `pubs` son los 420 public inputs que preceden a alpha/beta (`wires[1..421]`):
//! Ca_out(104) || Cb_out(104) || H(2) || G(2) || Ca(104) || Cb(104). No
//! dependen de alpha/beta, asi que la derivacion es estable (idempotente).
//!
//! `abi.encodePacked(uint8, uint256, uint256, uint256[])` = 1 byte de tag, dos
//! palabras de 32 bytes big-endian (link_d.x, link_d.y) y la concatenacion sin
//! prefijo de cada elemento de `pubs` como 32 bytes big-endian.

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};

/// Numero de public inputs que entran en la derivacion (todos menos alpha/beta).
pub const NUM_FS_PUBLICS: usize = 420;

const TAG_ALPHA: u8 = 1;
const TAG_BETA: u8 = 2;

fn fq_be_32(f: &Fq) -> [u8; 32] {
    let mut bytes = f.into_bigint().to_bytes_be();
    // BN254 Fq cabe en 32 bytes; to_bytes_be ya da 32, pero normalizamos.
    debug_assert!(bytes.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    bytes.clear();
    out
}

fn fr_be_32(f: &Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn derive_challenge(tag: u8, link_d: &G1Affine, pubs: &[Fr]) -> Fr {
    let (x, y) = link_d.xy().expect("link_d no es identidad");
    let mut hasher = Keccak256::new();
    hasher.update([tag]);
    hasher.update(fq_be_32(x));
    hasher.update(fq_be_32(y));
    for p in pubs {
        hasher.update(fr_be_32(p));
    }
    let digest = hasher.finalize();
    // keccak (big-endian) reducido mod r: identico a `BigInt(hash) % FIELD_PRIME`.
    Fr::from_be_bytes_mod_order(&digest)
}

/// Deriva (alpha, beta) a partir del commitment `link_d` y los 420 publics que
/// preceden a los challenges. Debe llamarse ANTES de calcular el witness: los
/// challenges son inputs del circuito (commit-then-challenge).
pub fn derive_alpha_beta(link_d: &G1Affine, pubs: &[Fr]) -> (Fr, Fr) {
    assert_eq!(
        pubs.len(),
        NUM_FS_PUBLICS,
        "se esperan {NUM_FS_PUBLICS} publics para la derivacion FS"
    );
    (
        derive_challenge(TAG_ALPHA, link_d, pubs),
        derive_challenge(TAG_BETA, link_d, pubs),
    )
}
