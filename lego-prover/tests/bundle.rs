//! GATE del formato `LegoBundle` (capa 3.4b paso 3c): serde round-trip por
//! WebRTC + la comprobacion del enlace del pool (`precompute.link_d ==
//! residual.link_d`). Rapido (sin PK pesada): valida el contrato del contenedor
//! y la logica de `links_match`, no la criptografia (eso lo cubre
//! `precompute_prove.rs`).

use lego_prover::{G1Json, G2Json, LegoBundle, LegoProofJson};

fn g1(x: &str, y: &str) -> G1Json {
    G1Json {
        x: x.to_string(),
        y: y.to_string(),
    }
}

fn g2() -> G2Json {
    G2Json {
        x_c1: "1".to_string(),
        x_c0: "2".to_string(),
        y_c1: "3".to_string(),
        y_c0: "4".to_string(),
    }
}

/// Una proof de relleno con un `link_d` dado y unos `pubs` arbitrarios.
fn proof_with_link_d(link_d: G1Json, pubs: &[&str]) -> LegoProofJson {
    LegoProofJson {
        a: g1("10", "11"),
        b: g2(),
        c: g1("12", "13"),
        d: g1("14", "15"),
        link_d,
        link_pi: g1("16", "17"),
        pubs: pubs.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn bundle_roundtrip_and_link_check() {
    let shared = g1("111", "222");
    let precompute = proof_with_link_d(shared.clone(), &["5", "6", "7", "8"]);
    let residual = proof_with_link_d(shared.clone(), &["100", "200"]);

    let bundle = LegoBundle {
        precompute,
        residual,
    };

    // El enlace del pool: ambos comparten link_d.
    assert!(bundle.links_match(), "mismo link_d -> links_match");

    // Round-trip por el canal WebRTC (string JSON).
    let wire = bundle.to_json_string();
    let parsed = LegoBundle::from_json_str(&wire).expect("bundle valido debe parsear");
    assert_eq!(parsed, bundle, "round-trip serde debe preservar el bundle");
    assert!(parsed.links_match());

    // Entrada malformada de un peer: NO debe hacer panic, solo None.
    assert!(LegoBundle::from_json_str("no soy json").is_none());
    assert!(LegoBundle::from_json_str("{}").is_none());
}

#[test]
fn bundle_mismatched_links_rejected() {
    let precompute = proof_with_link_d(g1("111", "222"), &["5", "6"]);
    // link_d distinto: una precompute de otra sesion/seed no enlaza.
    let residual = proof_with_link_d(g1("999", "888"), &["100", "200"]);

    let bundle = LegoBundle {
        precompute,
        residual,
    };
    assert!(
        !bundle.links_match(),
        "link_d distinto -> el bundle NO enlaza (rechazo del pool)"
    );
}
