//! Vuelca el mazo canonico a JSON (coordenadas decimales, formato del
//! contrato). Uso:
//!   cargo run -p texas-holdem --example dump_canonical_deck > canonical-deck.json
//!
//! El JSON resultante es la fuente de verdad compartida con smartcontracts/
//! (deploy + tests de Hardhat siembran cardMapping con el) y con el frontend.
//! Si cambia la semilla o la derivacion, hay que regenerarlo Y redesplegar:
//! el test `canonical_deck_golden_pin` de la lib avisa de cualquier deriva.

use texas_holdem::{card_coords_decimal, generate_canonical_deck, CANONICAL_DECK_SEED};

const NUM_OF_CARDS: usize = 52;

fn main() {
    let deck = generate_canonical_deck(NUM_OF_CARDS);
    let seed_ascii = core::str::from_utf8(&CANONICAL_DECK_SEED).expect("seed is ASCII");

    println!("{{");
    println!("  \"seed\": \"{}\",", seed_ascii);
    println!("  \"cards\": [");
    for (i, card) in deck.iter().enumerate() {
        let (x, y) = card_coords_decimal(card);
        let comma = if i + 1 < deck.len() { "," } else { "" };
        println!("    {{ \"x\": \"{}\", \"y\": \"{}\" }}{}", x, y, comma);
    }
    println!("  ]");
    println!("}}");
}
