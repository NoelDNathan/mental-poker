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

/// Version del transcript Fiat-Shamir con separacion de dominio (#5). Subir esta
/// constante invalida deliberadamente todos los challenges previos (rota la
/// compatibilidad del transcript a proposito).
const FS_DOMAIN_VERSION: &[u8] = b"dog-poker-club/fs-domain/v1";

/// Separador de dominio (#5): liga los challenges al CONTEXTO donde la proof es
/// valida, para que una proof no se pueda re-jugar en otro contexto aunque sus
/// public inputs coincidan. Es un `keccak` de los campos de contexto que TODOS
/// los peers conocen del estado compartido, asi prover y verifier lo reproducen
/// identico.
///
/// Encoding canonico (mismo que debera portar el verifier Solidity cuando la
/// verificacion on-chain sea el arbitro, capa 4):
/// ```text
/// domain_sep = keccak256(
///     FS_DOMAIN_VERSION ||
///     chain_id      (u64 big-endian, 8 bytes) ||
///     keccak256(game_id_bytes)   (32 bytes)   ||   // game_id var-len -> hash fijo
///     round         (u32 big-endian, 4 bytes) ||
///     shuffler      (u32 big-endian, 4 bytes)
/// )
/// ```
/// `game_id` se hashea aparte para que el encoding externo sea de ancho fijo (sin
/// ambiguedad de concatenar campos de longitud variable). NOTA on-chain: cuando
/// se active la capa Solidity habra que añadir aqui la direccion del contrato
/// verifier y/o la EOA del shuffler y portar EXACTAMENTE este layout a
/// `VerifyShufflingLego.sol` (un byte de desajuste = falla toda verificacion).
pub fn fs_domain_separator(chain_id: u64, game_id: &[u8], round: u32, shuffler: u32) -> [u8; 32] {
    let game_id_hash = {
        let mut h = Keccak256::new();
        h.update(game_id);
        h.finalize()
    };
    let mut h = Keccak256::new();
    h.update(FS_DOMAIN_VERSION);
    h.update(chain_id.to_be_bytes());
    h.update(game_id_hash);
    h.update(round.to_be_bytes());
    h.update(shuffler.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

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

fn derive_challenge(tag: u8, domain_sep: &[u8; 32], link_d: &G1Affine, pubs: &[Fr]) -> Fr {
    let (x, y) = link_d.xy().expect("link_d no es identidad");
    let mut hasher = Keccak256::new();
    hasher.update([tag]);
    // Separacion de dominio (#5): el contexto (chain/game/round/shuffler) entra
    // ANTES del link_d, asi una proof valida en un contexto no re-verifica en otro.
    hasher.update(domain_sep);
    hasher.update(fq_be_32(x));
    hasher.update(fq_be_32(y));
    for p in pubs {
        hasher.update(fr_be_32(p));
    }
    let digest = hasher.finalize();
    // keccak (big-endian) reducido mod r: identico a `BigInt(hash) % FIELD_PRIME`.
    Fr::from_be_bytes_mod_order(&digest)
}

/// Deriva (alpha, beta) a partir del separador de dominio (`domain_sep`, #5), el
/// commitment `link_d` y los 420 publics que preceden a los challenges. Debe
/// llamarse ANTES de calcular el witness: los challenges son inputs del circuito
/// (commit-then-challenge). El verifier re-deriva con el MISMO `domain_sep`
/// (reconstruido del estado compartido) -> una proof de otra partida/ronda/jugador
/// produce challenges distintos y NO verifica.
pub fn derive_alpha_beta(domain_sep: &[u8; 32], link_d: &G1Affine, pubs: &[Fr]) -> (Fr, Fr) {
    assert_eq!(
        pubs.len(),
        NUM_FS_PUBLICS,
        "se esperan {NUM_FS_PUBLICS} publics para la derivacion FS"
    );
    (
        derive_challenge(TAG_ALPHA, domain_sep, link_d, pubs),
        derive_challenge(TAG_BETA, domain_sep, link_d, pubs),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    /// #5: el separador de dominio cambia si cambia CUALQUIER campo del contexto.
    #[test]
    fn domain_separator_changes_with_each_field() {
        let base = fs_domain_separator(1, b"game-1", 0, 0);
        assert_ne!(base, fs_domain_separator(2, b"game-1", 0, 0), "chain_id");
        assert_ne!(base, fs_domain_separator(1, b"game-2", 0, 0), "game_id");
        assert_ne!(base, fs_domain_separator(1, b"game-1", 1, 0), "round");
        assert_ne!(base, fs_domain_separator(1, b"game-1", 0, 1), "shuffler");
        // determinista: misma entrada -> mismo separador.
        assert_eq!(base, fs_domain_separator(1, b"game-1", 0, 0));
    }

    /// #5: dos contextos distintos producen challenges distintos para los MISMOS
    /// (link_d, pubs) -> una proof de un contexto no re-verifica en otro.
    #[test]
    fn different_domain_sep_gives_different_challenges() {
        let link_d = G1Affine::generator();
        let pubs = vec![Fr::from(7u64); NUM_FS_PUBLICS];
        let ds_a = fs_domain_separator(1, b"game-A", 0, 0);
        let ds_b = fs_domain_separator(1, b"game-B", 0, 0);
        let (a1, b1) = derive_alpha_beta(&ds_a, &link_d, &pubs);
        let (a1_again, b1_again) = derive_alpha_beta(&ds_a, &link_d, &pubs);
        let (a2, b2) = derive_alpha_beta(&ds_b, &link_d, &pubs);
        assert_eq!((a1, b1), (a1_again, b1_again), "misma entrada -> mismos challenges");
        assert_ne!(a1, a2, "distinto domain_sep -> distinto alpha");
        assert_ne!(b1, b2, "distinto domain_sep -> distinto beta");
    }
}
