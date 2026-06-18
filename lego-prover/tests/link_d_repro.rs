//! GATE de la capa 3.1: el `link_d` que produce este crate debe reproducir bit
//! a bit el que el lab exporto a `bench-results/legogroth16/link_d.json`.
//!
//! Reproducirlo prueba que la maquinaria comun del cp_link (NUMS hash-to-curve,
//! seleccion de committed witnesses, MSM de `compute_link_d`, blinding `link_v`)
//! es identica a la del lab. `link_d` solo depende de (link_bases NUMS ||
//! committed witnesses || link_v): es independiente del setup Groth16, asi que
//! se reproduce sin re-ejecutar la ceremonia.

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use lego_prover::link::nums_g1;
use lego_prover::{
    committed_witnesses, compute_link_d, g1_to_decimal, link_v_from_seed, load_pk, load_r1cs,
    make_link_gens, parse_witness, setup_pk, verify, COMMIT_WITNESS_COUNT,
};

// Seed del blinding cp_link del lab (legogroth16-poc: LINK_V_SEED).
const LINK_V_SEED: u64 = 0x714B;

static R1CS_BYTES: &[u8] = include_bytes!("../artifacts/shuffle_r1cs.bin");
static PK_BYTES: &[u8] = include_bytes!("../artifacts/shuffle_pk.bin");
static WITNESS_JSON: &str = include_str!("../artifacts/shuffle_witness.json");
static LINK_D_EXPECTED: &str = include_str!("../artifacts/shuffle_link_d_expected.json");

fn expected_link_d() -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(LINK_D_EXPECTED).unwrap();
    (
        v["x"].as_str().unwrap().to_string(),
        v["y"].as_str().unwrap().to_string(),
    )
}

#[test]
fn link_d_reproduces_lab() {
    let r1cs = load_r1cs(R1CS_BYTES);
    let num_public = r1cs.num_public as usize;
    let wires = parse_witness(WITNESS_JSON);
    assert_eq!(
        wires.len(),
        num_public + r1cs.num_private as usize,
        "longitud del witness no cuadra con el R1CS"
    );

    let committed = committed_witnesses(&wires, num_public);
    assert_eq!(committed.len(), COMMIT_WITNESS_COUNT as usize);

    let link_v = link_v_from_seed(LINK_V_SEED);

    // 1) link_d desde los generadores NUMS recomputados por este crate.
    let link_gens = make_link_gens(COMMIT_WITNESS_COUNT + 1);
    let link_d_nums = compute_link_d(&link_gens.pedersen_gens, &committed, link_v);
    assert_eq!(
        g1_to_decimal(&link_d_nums),
        expected_link_d(),
        "el link_d desde NUMS no reproduce el del lab"
    );

    // 2) link_d desde los link_bases que el setup del lab dejo en la PK: deben
    //    coincidir con los NUMS (el setup solo copia los pedersen_gens).
    let pk = load_pk(PK_BYTES);
    let link_d_pk = compute_link_d(&pk.vk.link_bases, &committed, link_v);
    assert_eq!(
        g1_to_decimal(&link_d_pk),
        expected_link_d(),
        "el link_d desde pk.vk.link_bases no reproduce el del lab"
    );

    // 3) los link_bases de la PK son EXACTAMENTE los NUMS de este crate.
    let n = (COMMIT_WITNESS_COUNT + 1) as usize;
    assert_eq!(
        &pk.vk.link_bases[..n],
        &link_gens.pedersen_gens[..n],
        "los link_bases de la PK no son los NUMS recomputados"
    );

    // Sanity NUMS deterministico: el primer generador no es la identidad.
    assert!(!nums_g1("dog-poker-club/link-gens/v1", 0).is_zero());
}

// Camino completo setup -> prove -> verify con ProverCircuit (sin wasmer) sobre
// el residual (shuffle). Mas lento (genera una PK nueva): marcado #[ignore], se
// corre con `cargo test --release -- --ignored`. Prueba que la PK serializada
// del lab no es necesaria para probar: el crate la regenera y el link_d sigue
// reproduciendose.
#[test]
#[ignore]
fn setup_prove_verify_shuffle() {
    let r1cs = load_r1cs(R1CS_BYTES);
    let num_public = r1cs.num_public as usize;
    let wires = parse_witness(WITNESS_JSON);
    let public_inputs: Vec<Fr> = wires[1..num_public].to_vec();
    let committed = committed_witnesses(&wires, num_public);
    let link_v = link_v_from_seed(LINK_V_SEED);

    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let pk = setup_pk(&r1cs, &mut rng);

    // link_d reproducido con la PK recien generada (link_bases NUMS deterministas).
    let link_d = compute_link_d(&pk.vk.link_bases, &committed, link_v);
    assert_eq!(g1_to_decimal(&link_d), expected_link_d());

    let proof = lego_prover::prove_with_link_v(&pk, &r1cs, wires, link_v, &mut rng);
    assert_eq!(
        proof.link_d, link_d,
        "el link_d de la proof != el link_d calculado fuera del prover"
    );
    assert!(verify(&pk, &proof, &public_inputs), "la proof no verifica");
}
