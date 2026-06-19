//! Gate nativo de la capa 3.4b para el RESHUFFLE/cancellation: round-trip
//! `remask_for_reshuffle_lego` (prover) -> `verify_reshuffle_remask_lego`
//! (verifier P2P) con datos de juego REALES (babyjubjub).
//!
//! El circuito `card_cancellation_lego` solo impone DOS restricciones duras:
//!   1. `pk_computed === pk` con `BabyPbk(sk)` (base BASE8 de babyjubjub) → exige
//!      `pk = sk·BASE8`. Como `prime_subgroup_generator()` de este babyjubjub ES
//!      BASE8, el keypair de `player_keygen` (pk = sk·generator) lo satisface.
//!   2. `r_prime_G[i] + r_prime_H[i] === r_prime[i]·(G+H)` → lo cumple el prover
//!      al precomputar r'·G y r'·H.
//! Las comprobaciones de `m`/cartas del jugador NO imponen igualdad dura (solo
//! condicionan los outputs Ca_out/Cb_out), así que un mazo válido cualquiera
//! produce una proof válida. Por eso el round-trip SÍ es reproducible nativo.
//!
//! La PK del reshuffle (~4.7 MB) hace el prove lento: `#[ignore]`, se corre con
//! `cargo +stable-x86_64-pc-windows-msvc test -p barnett-smart-card-protocol \
//!   --release --test lego_reshuffle -- --ignored`.

use ark_ec::AffineCurve;
use ark_std::UniformRand;
use babyjubjub::{EdwardsAffine, EdwardsProjective, Fr as BjFr};
use barnett_smart_card_protocol::discrete_log_cards::{self, Card, MaskedCard};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use proof_essentials::utils::rand::sample_vector;
use rand::thread_rng;

type CardProtocol<'a> = discrete_log_cards::DLCards<'a, EdwardsProjective>;

#[test]
#[ignore]
fn remask_for_reshuffle_lego_real_deck_round_trip() {
    let rng = &mut thread_rng();
    let m = 2;
    let n = 26;
    let deck_size = m * n;

    let generator = EdwardsAffine::prime_subgroup_generator();
    let pp = CardProtocol::setup(rng, generator, m, n).expect("setup");

    // Keypair del jugador: pk = sk·generator = sk·BASE8 (satisface BabyPbk).
    let (pk, sk) = CardProtocol::player_keygen(rng, &pp).expect("keygen");
    // shared_key (H): con un solo jugador, la clave agregada es su pk.
    let shared_key = pk;

    // Mazo de entrada (52 cartas enmascaradas) y las 52 cartas en claro (m_list).
    let deck: Vec<MaskedCard<EdwardsProjective>> = sample_vector(rng, deck_size);
    let m_list: Vec<Card<EdwardsProjective>> = sample_vector(rng, deck_size);

    // Las 2 cartas del jugador: dos cartas del mazo.
    let player_cards_opt: Vec<Option<MaskedCard<EdwardsProjective>>> =
        vec![Some(deck[0]), Some(deck[1])];
    let player_cards: Vec<MaskedCard<EdwardsProjective>> = vec![deck[0], deck[1]];

    // Factores de remask r' (escalares), como en el cliente.
    let r_prime: Vec<BjFr> = (0..deck_size).map(|_| BjFr::rand(rng)).collect();

    let out = CardProtocol::remask_for_reshuffle_lego(
        &r_prime,
        &pp,
        &shared_key,
        &deck,
        &player_cards_opt,
        &sk,
        &pk,
        &m_list,
        /* link_v_seed */ 0xBEEF,
    )
    .expect("remask_for_reshuffle_lego");

    assert!(
        out.verified,
        "la proof lego del reshuffle debe auto-verificar con un mazo real"
    );
    assert_eq!(
        out.proof.pubs.len(),
        536,
        "numero de public inputs del circuito reshuffle lego"
    );

    // Lado VERIFIER/peer (3.4b): verifica el bundle, comprueba pk/H/G/cartas/m/Ca/Cb
    // contra el estado y reconstruye el mazo resultante.
    let reshuffled = CardProtocol::verify_reshuffle_remask_lego(
        &pp,
        &shared_key,
        &deck,
        &player_cards,
        &pk,
        &m_list,
        &out.proof,
    )
    .expect("verify_reshuffle_remask_lego debe aceptar el bundle valido");
    assert_eq!(reshuffled.len(), deck_size, "mazo resultante de 52 cartas");

    // Tamper: un public manipulado debe hacer fallar la verificacion del peer.
    let mut bad = out.proof.clone();
    bad.pubs[0] = "123".to_string();
    assert!(
        CardProtocol::verify_reshuffle_remask_lego(
            &pp,
            &shared_key,
            &deck,
            &player_cards,
            &pk,
            &m_list,
            &bad,
        )
        .is_err(),
        "un bundle manipulado debe rechazarse"
    );
}
