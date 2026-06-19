//! Metadatos de los tres circuitos lego del protocolo. Todos comprometen las
//! mismas `COMMIT_WITNESS_COUNT` (208) senales r'_G || r'_H justo despues de
//! sus publics, con los mismos generadores NUMS y blinding `link_v`: por eso
//! sus `link_d` coinciden (el enlace cp_link).

/// Descripcion de un circuito lego.
pub struct LegoCircuit {
    /// Id del circuito (carpeta de artefactos en el lab).
    pub id: &'static str,
    /// Longitud de `gamma_abc` = 1 + numero de public signals. Los committed
    /// witnesses empiezan en `wires[num_public]`.
    pub num_public: usize,
    /// El shuffle deriva alpha/beta por Fiat-Shamir (permutacion); el reshuffle
    /// y el precompute no (remask posicional).
    pub needs_fs: bool,
}

/// Residual del barajado: `shuffling_multiset_lego`. 422 publics (420 + alpha +
/// beta), con Fiat-Shamir.
pub const SHUFFLE: LegoCircuit = LegoCircuit {
    id: "shuffling_multiset_lego",
    num_public: 423,
    needs_fs: true,
};

/// Residual de la cancelacion/reshuffle: `card_cancellation_lego`. 536 publics,
/// sin Fiat-Shamir.
pub const RESHUFFLE: LegoCircuit = LegoCircuit {
    id: "card_cancellation_lego",
    num_public: 537,
    needs_fs: false,
};

/// Re-randomizacion de background compartida: `rerandomization_precompute_52_lego`.
/// 4 publics; se prueba fuera del camino critico (su PK es grande, ~20 MB, por
/// eso se carga bajo demanda y no se embebe).
pub const PRECOMPUTE: LegoCircuit = LegoCircuit {
    id: "rerandomization_precompute_52_lego",
    num_public: 5,
    needs_fs: false,
};
