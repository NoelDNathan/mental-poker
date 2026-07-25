//! Vuelca la VERIFYING KEY que hay DENTRO de un `*_pk.bin` LegoGroth16, en la
//! misma codificacion EVM que usa `export_onchain` del POC
//! (zk-bench/native-provers/legogroth16-poc).
//!
//! Para que existe: el setup LegoGroth16 se regenera en cada corrida del POC, y
//! el verifier Solidity lleva su vk HARDCODEADA. Si alguien regenera el verifier
//! y no propaga el `precompute_pk.bin` al frontend (o al reves), el navegador
//! prueba con un setup y la cadena verifica con otro: `verify()` devuelve false
//! SIEMPRE, la proof es irreprochable y el mensaje de error no dice nada util.
//! No habia forma de comprobarlo porque la vk vivia enterrada en un binario
//! arkworks de 18 MB.
//!
//! Uso:
//!   cargo run --release --bin dump-vk -- <ruta/al/pk.bin>
//!
//! Salida: JSON por stdout con `groth16_vk` y `link_vk`, comparable campo a
//! campo contra las constantes del `.sol` desplegado. Lo consume
//! `zk-bench/scripts/check-verifier-matches-pk.mjs`.

use ark_bn254::{Bn254 as E, G1Affine as Bn254G1, G2Affine as Bn254G2};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalDeserialize;
use legogroth16::ProvingKeyWithLink;
use serde_json::{json, Value};

fn neg1(p: &Bn254G1) -> Bn254G1 {
    (-p.into_group()).into_affine()
}

fn neg2(p: &Bn254G2) -> Bn254G2 {
    (-p.into_group()).into_affine()
}

fn g1_json(p: &Bn254G1) -> Value {
    let (x, y) = p.xy().map(|(x, y)| (x.to_string(), y.to_string())).unwrap_or_else(|| {
        ("0".to_string(), "0".to_string())
    });
    json!({ "x": x, "y": y })
}

fn g2_json(p: &Bn254G2) -> Value {
    match p.xy() {
        Some((x, y)) => json!({
            "x_c1": x.c1.to_string(),
            "x_c0": x.c0.to_string(),
            "y_c1": y.c1.to_string(),
            "y_c0": y.c0.to_string(),
        }),
        None => json!({ "x_c1": "0", "x_c0": "0", "y_c1": "0", "y_c0": "0" }),
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("uso: dump-vk <ruta/al/pk.bin>");
        std::process::exit(2);
    });

    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("no se pudo leer {path}: {e}");
        std::process::exit(2);
    });

    // MISMO metodo que usa el cliente en produccion (lego_prover::load_pk):
    // uncompressed_unchecked. Si el fichero no es una ProvingKeyWithLink esto
    // falla aqui, que es lo que queremos (fail-closed, no un vk basura).
    let pk = ProvingKeyWithLink::<E>::deserialize_uncompressed_unchecked(&bytes[..])
        .unwrap_or_else(|e| {
            eprintln!("{path} no deserializa como ProvingKeyWithLink: {e:?}");
            std::process::exit(1);
        });

    let gvk = &pk.vk.groth16_vk;
    let lvk = &pk.vk.link_vk;
    let ic: Vec<Value> = gvk.gamma_abc_g1.iter().map(g1_json).collect();

    let out = json!({
        "source": path,
        "bytes": bytes.len(),
        "num_ic": ic.len(),
        "groth16_vk": {
            "alpha_neg": g1_json(&neg1(&gvk.alpha_g1)),
            "beta": g2_json(&gvk.beta_g2),
            "gamma_neg": g2_json(&neg2(&gvk.gamma_g2)),
            "delta_neg": g2_json(&neg2(&gvk.delta_g2)),
            "ic": ic,
        },
        "link_vk": {
            "c0": g2_json(&lvk.c[0]),
            "c1": g2_json(&lvk.c[1]),
            "a_neg": g2_json(&neg2(&lvk.a)),
        },
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
