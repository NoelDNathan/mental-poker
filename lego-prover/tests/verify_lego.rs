//! Gate de la VERIFICACION P2P (capa 3.4b paso 2): cada peer recibe un
//! `LegoProofJson` por WebRTC y lo verifica con `verify_{shuffle,reshuffle}_lego`.
//!
//! Cierra el lazo prover->frontera->verifier sin tipos ark cruzando: parte del
//! FULL witness (lo que produce el ark-circom del cliente), prueba, serializa a
//! JSON (la frontera real), deserializa y verifica. Tambien comprueba que una
//! proof manipulada se RECHAZA (sin panic). Corre con `--release --ignored`
//! (setup/prove pesados).

use lego_prover::{
    prove_reshuffle, prove_shuffle, verify_reshuffle_lego, verify_shuffle_lego, LegoProofJson,
};

// Seed del blinding cp_link del lab (mismo que el resto de fixtures).
const LINK_V_SEED: u64 = 0x714B;

static SHUFFLE_WITNESS: &str = include_str!("../artifacts/shuffle_witness.json");
static RESHUFFLE_WITNESS: &str = include_str!("../artifacts/reshuffle_witness.json");

fn witness_strings(json: &str) -> Vec<String> {
    serde_json::from_str(json).expect("witness.json = array de decimales")
}

/// prove -> JSON -> from_json -> verify_shuffle_lego == true, y tamper == false.
#[test]
#[ignore]
fn shuffle_bundle_roundtrip_verifies_and_rejects_tamper() {
    let wires = witness_strings(SHUFFLE_WITNESS);
    let out = prove_shuffle(&wires, LINK_V_SEED);
    assert!(out.verified, "self-check del prover");

    // Frontera real: serializa y deserializa el bundle (lo que viaja por WebRTC).
    let bytes = out.proof.to_json_string();
    let received = LegoProofJson::from_json_str(&bytes);
    assert_eq!(received, out.proof, "round-trip JSON no es identidad");

    // Verificacion del peer: cp_link + re-derivacion Fiat-Shamir de alpha/beta.
    assert!(
        verify_shuffle_lego(&received),
        "el peer debe aceptar una proof de shuffle valida"
    );

    // Tamper 1: corromper un public input (Ca_out[0].x) -> cp_link falla.
    let mut bad_pub = received.clone();
    bad_pub.pubs[0] = "123".to_string();
    assert!(!verify_shuffle_lego(&bad_pub), "pub manipulado debe rechazarse");

    // Tamper 2: corromper alpha (pubs[420]) -> rompe cp_link y/o la re-derivacion FS.
    let mut bad_alpha = received.clone();
    bad_alpha.pubs[420] = "456".to_string();
    assert!(
        !verify_shuffle_lego(&bad_alpha),
        "alpha manipulado debe rechazarse (Fiat-Shamir)"
    );

    // Tamper 3: punto malformado (link_d.x no decimal) -> false sin panic.
    let mut bad_pt = received.clone();
    bad_pt.link_d.x = "no-soy-un-numero".to_string();
    assert!(!verify_shuffle_lego(&bad_pt), "punto malformado debe rechazarse");
}

/// Igual para el reshuffle/cancellation (sin Fiat-Shamir).
#[test]
#[ignore]
fn reshuffle_bundle_roundtrip_verifies_and_rejects_tamper() {
    let wires = witness_strings(RESHUFFLE_WITNESS);
    let out = prove_reshuffle(&wires, LINK_V_SEED);
    assert!(out.verified, "self-check del prover");

    let received = LegoProofJson::from_json_str(&out.proof.to_json_string());
    assert!(
        verify_reshuffle_lego(&received),
        "el peer debe aceptar una proof de reshuffle valida"
    );

    let mut bad = received.clone();
    bad.pubs[0] = "123".to_string();
    assert!(!verify_reshuffle_lego(&bad), "pub manipulado debe rechazarse");
}
