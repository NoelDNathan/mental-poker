//! Representacion serde de una proof cp_link en DECIMALES, la frontera con el
//! `wasm_client` (ark 0.5) y el frontend. Mismo encoding de puntos que los
//! exports on-chain del lab: G1 = (x, y); G2 en orden EIP-197 (parte imaginaria
//! primero). `pubs` son los public inputs del circuito en decimal.

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use serde::{Deserialize, Serialize};

use legogroth16::ProofWithLink;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct G1Json {
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct G2Json {
    pub x_c1: String,
    pub x_c0: String,
    pub y_c1: String,
    pub y_c0: String,
}

/// Una proof cp_link completa lista para serializar/transportar. `a,c,d,link_d,
/// link_pi` son G1; `b` es G2; `pubs` los public inputs del circuito.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegoProofJson {
    pub a: G1Json,
    pub b: G2Json,
    pub c: G1Json,
    pub d: G1Json,
    pub link_d: G1Json,
    pub link_pi: G1Json,
    pub pubs: Vec<String>,
}

fn g1_json(p: &G1Affine) -> G1Json {
    let (x, y) = p.xy().expect("punto G1 no es identidad");
    G1Json {
        x: x.to_string(),
        y: y.to_string(),
    }
}

fn g2_json(p: &G2Affine) -> G2Json {
    let (x, y) = p.xy().expect("punto G2 no es identidad");
    G2Json {
        x_c1: x.c1.to_string(),
        x_c0: x.c0.to_string(),
        y_c1: y.c1.to_string(),
        y_c0: y.c0.to_string(),
    }
}

impl LegoProofJson {
    /// Construye el JSON a partir de la proof arkworks y los public inputs ya en
    /// decimal (los del circuito, incluidos alpha/beta para el shuffle).
    pub fn from_proof(proof: &ProofWithLink<Bn254>, pubs: &[String]) -> Self {
        LegoProofJson {
            a: g1_json(&proof.groth16_proof.a),
            b: g2_json(&proof.groth16_proof.b),
            c: g1_json(&proof.groth16_proof.c),
            d: g1_json(&proof.groth16_proof.d),
            link_d: g1_json(&proof.link_d),
            link_pi: g1_json(&proof.link_pi),
            pubs: pubs.to_vec(),
        }
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("serialize LegoProofJson")
    }

    pub fn from_json_str(s: &str) -> Self {
        serde_json::from_str(s).expect("deserialize LegoProofJson")
    }
}
