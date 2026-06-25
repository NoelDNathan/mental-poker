//! Gate nativo de la capa 3.4b: `shuffle_and_remask2_lego` con datos de juego
//! REALES (babyjubjub, el mismo curve del cliente) — no el `input.json` del lab.
//!
//! Construye un mazo de 52 cartas, una permutacion y los `r'` como en el flujo
//! real, llama al nuevo metodo (que arma el `input.json` del circuito
//! `shuffling_multiset_lego` y delega en `zk_reshuffle::lego` -> doble pasada FS
//! + prove cp_link) y exige que la proof se auto-verifique. Esto valida que el
//! MAPEO game-state -> input del circuito es correcto (orden de campos,
//! permutacion aplicada, formato de coordenadas), que es lo que 3.4b anade sobre
//! la tuberia ya probada en 3.3.

use ark_ec::AffineCurve;
use ark_std::UniformRand;
use babyjubjub::{EdwardsAffine, EdwardsProjective, Fr as BjFr};
use barnett_smart_card_protocol::discrete_log_cards::{self, MaskedCard};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use rand::thread_rng;

type CardProtocol<'a> = discrete_log_cards::DLCards<'a, EdwardsProjective>;

#[test]
fn shuffle_and_remask2_lego_real_deck_verifies() {
    let rng = &mut thread_rng();
    // 52 cartas (m*n = 2*26), como el deck del juego.
    let m = 2;
    let n = 26;
    let deck_size = m * n;

    let generator = EdwardsAffine::prime_subgroup_generator();
    let pp = CardProtocol::setup(rng, generator, m, n).expect("setup");

    // shared_key: con un solo jugador, la clave agregada es su pk (suma de 1).
    let (shared_key, _sk) = CardProtocol::player_keygen(rng, &pp).expect("keygen");

    // Mazo de entrada: 52 cartas enmascaradas validas (puntos on-curve).
    let deck: Vec<MaskedCard<EdwardsProjective>> = sample_vector(rng, deck_size);

    // Permutacion secreta y factores de remask r' (escalares), como en el cliente.
    let permutation = Permutation::new(rng, deck_size);
    let r_prime: Vec<BjFr> = (0..deck_size).map(|_| BjFr::rand(rng)).collect();

    // #1: link_v = 32 bytes (ancho completo). #5: domain_sep liga la proof a un
    // contexto (chain/partida/...); prover y verifier deben usar EL MISMO.
    let link_v: [u8; 32] = [
        0xee, 0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 7,
    ];
    let domain_sep = zk_reshuffle::lego::fs_domain_separator(31337, b"game-abc", 0, 0);

    let out = CardProtocol::shuffle_and_remask2_lego(
        &permutation,
        &r_prime,
        &pp,
        &shared_key,
        &deck,
        &link_v,
        &domain_sep,
    )
    .expect("shuffle_and_remask2_lego");

    assert!(
        out.verified,
        "la proof lego del shuffle debe auto-verificar con un mazo real"
    );

    // El shuffle lego expone 422 publics (420 que preceden a los challenges +
    // alpha + beta). Ver SHUFFLE_NUM_PUBLIC/SHUFFLE_FS_PUBLICS en zk_reshuffle::lego.
    assert_eq!(
        out.proof.pubs.len(),
        422,
        "numero de public inputs del circuito shuffle lego"
    );

    // Lado VERIFIER/peer (3.4b paso 2): verifica el bundle con EL MISMO domain_sep
    // y reconstruye el mazo resultante desde Ca_out/Cb_out (lo que hara el receive
    // handler).
    let shuffled =
        CardProtocol::verify_shuffle_remask2_lego(&pp, &shared_key, &deck, &out.proof, &domain_sep)
            .expect("verify_shuffle_remask2_lego debe aceptar el bundle valido");
    assert_eq!(shuffled.len(), deck_size, "mazo resultante de 52 cartas");

    // #5 (anti-replay): el MISMO bundle con un domain_sep de OTRO contexto (otra
    // partida) debe RECHAZARSE — alpha/beta re-derivados no cuadran.
    let other_ctx = zk_reshuffle::lego::fs_domain_separator(31337, b"OTRA-partida", 0, 0);
    assert!(
        CardProtocol::verify_shuffle_remask2_lego(&pp, &shared_key, &deck, &out.proof, &other_ctx)
            .is_err(),
        "una proof valida NO debe verificar bajo otro domain_sep (replay entre contextos)"
    );

    // Tamper: un public manipulado debe hacer fallar la verificacion del peer.
    let mut bad = out.proof.clone();
    bad.pubs[0] = "123".to_string();
    assert!(
        CardProtocol::verify_shuffle_remask2_lego(&pp, &shared_key, &deck, &bad, &domain_sep)
            .is_err(),
        "un bundle manipulado debe rechazarse"
    );
}
