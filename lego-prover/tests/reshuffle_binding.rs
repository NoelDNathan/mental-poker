//! Ligadura del remask posicional a su enunciado, sin Fiat-Shamir: una misma
//! proof real debe rechazarse al cambiar sus publics o el enlace de precompute.
//! Genera una sola proof; se ejecuta sin `--ignored`, preferiblemente en release.

use ark_bn254::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use lego_prover::{
    compute_link_d, g1_to_decimal, link_v_from_seed, load_pk, load_r1cs, parse_witness,
    prove_with_link_v, verify_reshuffle_lego, G1Json, LegoProofJson, COMMIT_WITNESS_COUNT, RESHUFFLE,
};

static PK_BYTES: &[u8] = include_bytes!("../artifacts/reshuffle_pk.bin");
static R1CS_BYTES: &[u8] = include_bytes!("../artifacts/reshuffle_r1cs.bin");
static WITNESS_JSON: &str = include_str!("../artifacts/reshuffle_witness.json");
static PRECOMPUTE_COMMITTED: &str = include_str!("../artifacts/precompute_committed.json");

#[test]
fn reshuffle_proof_is_bound_to_statement_and_precompute_link() {
    // Mismos artefactos y construccion de proof que reshuffle_prove.rs.
    let r1cs = load_r1cs(R1CS_BYTES);
    assert_eq!(r1cs.num_public as usize, RESHUFFLE.num_public);
    let pk = load_pk(PK_BYTES);
    let wires = parse_witness(WITNESS_JSON);
    let num_public = r1cs.num_public as usize;
    let public_inputs: Vec<Fr> = wires[1..num_public].to_vec();
    assert_eq!(public_inputs.len(), 536);

    let committed = &wires[num_public..num_public + COMMIT_WITNESS_COUNT as usize];
    let precompute_committed = parse_witness(PRECOMPUTE_COMMITTED);
    assert_eq!(precompute_committed.len(), COMMIT_WITNESS_COUNT as usize);
    assert!(
        committed == precompute_committed.as_slice(),
        "los fixtures de reshuffle y precompute deben compartir los committed witnesses"
    );
    let link_v = link_v_from_seed(0x714B);
    let expected_link_d = compute_link_d(&pk.vk.link_bases, &precompute_committed, link_v);

    let mut rng = StdRng::seed_from_u64(0xCA11CE);
    let proof = prove_with_link_v(&pk, &r1cs, wires, link_v, &mut rng);
    assert!(proof.link_d == expected_link_d, "el enlace original debe casar con la precompute");
    let pubs: Vec<String> = public_inputs.iter().map(|f| f.to_string()).collect();
    let json = LegoProofJson::from_proof(&proof, &pubs);
    let received = LegoProofJson::from_json_str(&json.to_json_string());
    assert!(verify_reshuffle_lego(&received), "la proof original debe verificar en P2P");

    // Indices de pubs (sin el wire constante inicial), segun verify_reshuffle_remask_lego:
    // pk_computed || Ca_out || Cb_out || pk_input || H || G || hole cards || m || Ca || Cb.
    // Cada coordenada se cambia por separado a otro Fr valido; no es un fallo de parseo.
    for (name, indices) in [
        ("pk_computed del autor", 0..2),
        ("pk_input del autor", 210..212),
        ("clave conjunta H", 212..214),
        ("generador G", 214..216),
        ("hole cards del reshuffler (Ca/Cb de ambas)", 216..224),
        ("primera carta del mapa m", 224..226),
        ("Ca de la primera carta del mazo de entrada", 328..330),
        ("Cb de la primera carta del mazo de entrada", 432..434),
    ] {
        for index in indices {
            let mut changed = received.clone();
            changed.pubs[index] = (public_inputs[index] + Fr::from(1u64)).to_string();
            assert!(
                !verify_reshuffle_lego(&changed),
                "debe rechazarse la mutacion de {name} en pubs[{index}]"
            );
        }
    }

    // Cambiar las dos copias de la pk juntas conserva pk_computed == pk_input:
    // la ligadura al autor no depende solo de comparar esas copias en el caller.
    for coordinate in 0..2 {
        let mut changed = received.clone();
        changed.pubs[coordinate] = (public_inputs[coordinate] + Fr::from(1u64)).to_string();
        changed.pubs[210 + coordinate] = changed.pubs[coordinate].clone();
        assert!(
            !verify_reshuffle_lego(&changed),
            "debe rechazarse cambiar ambas copias de la pk del autor"
        );
    }

    // Otra entrada de precompute puede usar los mismos committed con otro blinding.
    // Calculamos su link_d real sin generar una segunda proof ni cargar la PK de 20 MB.
    let other_link_d = compute_link_d(
        &pk.vk.link_bases,
        &precompute_committed,
        link_v + Fr::from(1u64),
    );
    assert!(other_link_d != proof.link_d, "la otra precompute debe tener un enlace distinto");
    let (x, y) = g1_to_decimal(&other_link_d);
    let mut changed_link = received.clone();
    changed_link.link_d = G1Json { x, y };
    assert!(
        !verify_reshuffle_lego(&changed_link),
        "la residual no debe verificar con el link_d de otra precompute"
    );
}
