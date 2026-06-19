//! GATE de la capa 3.1 extendida a los TRES circuitos: shuffle, reshuffle y
//! precompute comprometen las MISMAS 208 senales r'_G || r'_H, asi que bajo el
//! mismo `link_v` producen el MISMO `link_d`. Esa igualdad es el enlace cp_link
//! del protocolo (residual <-> precompute de background).
//!
//! El gate reproduce ademas el `link_d` del lab (link_v = 0x714B): como los
//! committed witnesses son identicos en los tres, los tres reproducen el mismo
//! `link_d.json`.

use ark_bn254::Fr;

use lego_prover::{
    compute_link_d, g1_to_decimal, link_v_from_seed, make_link_gens, parse_witness, COMMIT_WITNESS_COUNT,
    PRECOMPUTE, RESHUFFLE, SHUFFLE,
};

const LINK_V_SEED: u64 = 0x714B;

static SHUFFLE_WITNESS: &str = include_str!("../artifacts/shuffle_witness.json");
static RESHUFFLE_WITNESS: &str = include_str!("../artifacts/reshuffle_witness.json");
// Del precompute solo embebemos los 208 committed witnesses (su witness completo
// son ~3.7 MB y su PK ~20 MB: se cargan bajo demanda en produccion).
static PRECOMPUTE_COMMITTED: &str = include_str!("../artifacts/precompute_committed.json");
static LINK_D_EXPECTED: &str = include_str!("../artifacts/shuffle_link_d_expected.json");

fn expected_link_d() -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(LINK_D_EXPECTED).unwrap();
    (
        v["x"].as_str().unwrap().to_string(),
        v["y"].as_str().unwrap().to_string(),
    )
}

fn committed_from_witness(witness_json: &str, num_public: usize) -> Vec<Fr> {
    let wires = parse_witness(witness_json);
    wires[num_public..num_public + COMMIT_WITNESS_COUNT as usize].to_vec()
}

#[test]
fn three_circuits_share_link_d() {
    let cw_shuffle = committed_from_witness(SHUFFLE_WITNESS, SHUFFLE.num_public);
    let cw_reshuffle = committed_from_witness(RESHUFFLE_WITNESS, RESHUFFLE.num_public);
    let cw_precompute = parse_witness(PRECOMPUTE_COMMITTED);

    assert_eq!(cw_shuffle.len(), COMMIT_WITNESS_COUNT as usize);
    assert_eq!(cw_reshuffle.len(), COMMIT_WITNESS_COUNT as usize);
    assert_eq!(cw_precompute.len(), COMMIT_WITNESS_COUNT as usize);

    // El enlace solo existe si los tres comprometen las MISMAS senales.
    assert_eq!(
        cw_shuffle, cw_reshuffle,
        "shuffle y reshuffle no comparten los committed witnesses"
    );
    assert_eq!(
        cw_shuffle, cw_precompute,
        "shuffle y precompute no comparten los committed witnesses"
    );

    // Mismo link_v + mismos committed => mismo link_d en los tres, y reproduce
    // el del lab.
    let link_gens = make_link_gens(COMMIT_WITNESS_COUNT + 1);
    let link_v = link_v_from_seed(LINK_V_SEED);
    let expected = expected_link_d();
    for (name, cw) in [
        ("shuffle", &cw_shuffle),
        ("reshuffle", &cw_reshuffle),
        ("precompute", &cw_precompute),
    ] {
        let link_d = compute_link_d(&link_gens.pedersen_gens, cw, link_v);
        assert_eq!(
            g1_to_decimal(&link_d),
            expected,
            "{name}: link_d no reproduce el del lab"
        );
    }

    // Sanity de los metadatos.
    assert!(SHUFFLE.needs_fs);
    assert!(!RESHUFFLE.needs_fs);
    assert!(!PRECOMPUTE.needs_fs);
}
