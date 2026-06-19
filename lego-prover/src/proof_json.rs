//! Representacion serde de una proof cp_link en DECIMALES, la frontera con el
//! `wasm_client` (ark 0.5) y el frontend. Mismo encoding de puntos que los
//! exports on-chain del lab: G1 = (x, y); G2 en orden EIP-197 (parte imaginaria
//! primero). `pubs` son los public inputs del circuito en decimal.

use core::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use serde::{Deserialize, Serialize};

use legogroth16::{Proof, ProofWithLink};

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

    /// Inversa de `from_proof`: reconstruye la `ProofWithLink` arkworks desde los
    /// decimales. Devuelve `None` si algun campo no parsea (entrada de un peer
    /// potencialmente malicioso: NO debe hacer panic, solo fallar la verificacion).
    pub fn to_proof(&self) -> Option<ProofWithLink<Bn254>> {
        Some(ProofWithLink {
            groth16_proof: Proof {
                a: g1_from(&self.a)?,
                b: g2_from(&self.b)?,
                c: g1_from(&self.c)?,
                d: g1_from(&self.d)?,
            },
            link_d: g1_from(&self.link_d)?,
            link_pi: g1_from(&self.link_pi)?,
        })
    }

    /// Los public inputs del circuito (sin el `1` inicial) parseados a `Fr`.
    /// `None` si alguno no es un decimal valido.
    pub fn public_inputs(&self) -> Option<Vec<Fr>> {
        self.pubs.iter().map(|s| Fr::from_str(s).ok()).collect()
    }
}

fn g1_from(j: &G1Json) -> Option<G1Affine> {
    let x = Fq::from_str(&j.x).ok()?;
    let y = Fq::from_str(&j.y).ok()?;
    Some(G1Affine::new_unchecked(x, y))
}

fn g2_from(j: &G2Json) -> Option<G2Affine> {
    // EIP-197: parte imaginaria primero en el JSON; ark Fq2 = {c0 real, c1 imag}.
    let x = Fq2::new(Fq::from_str(&j.x_c0).ok()?, Fq::from_str(&j.x_c1).ok()?);
    let y = Fq2::new(Fq::from_str(&j.y_c0).ok()?, Fq::from_str(&j.y_c1).ok()?);
    Some(G2Affine::new_unchecked(x, y))
}
