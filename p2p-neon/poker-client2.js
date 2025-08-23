const { poker_client_async, send_line } = require(".");

const player_id = process.argv[2];
if (!player_id) {
  console.error("Usage: node poker-client.js <player_id>");
  process.exit(1);
}

console.log("player_id", player_id);
// Estado JS
let community_cards = [null, null, null, null, null];
let private_cards = [null, null];

function verifyPublicKey(public_key, r, s) {
  console.log("Javascript: Verify public key");
  console.log("JS Public key:", public_key);
  console.log("JS Proof:", r, s);
  console.log("................. end javascript ......................");
}

function verifyShuffling(public, proof) {
    console.log("Javascript: Shuffling");
    // console.log("JS Public info:", public);
    // console.log("JS Proof:", proof);
    console.log("................. end javascript ......................");
}


// @param G Base point G
// @param H Base point H
// @param S0 S0 = xG
// @param S1 S1 = xH
// @param A Commitment A = rP
// @param B Commitment B = rR
// @param r Response r

// G_card1.upcast::<JsValue>(),
// G_card2.upcast::<JsValue>(),
// H.upcast::<JsValue>(),
// statement1_card1.upcast::<JsValue>(),
// statement1_card2.upcast::<JsValue>(),
// statement2.upcast::<JsValue>(),
// A_card1.upcast::<JsValue>(),
// B_card1.upcast::<JsValue>(),
// r_card1.upcast::<JsValue>(),
// A_card2.upcast::<JsValue>(),
// B_card2.upcast::<JsValue>(),
// r_card2.upcast::<JsValue>(),

function verifyRevealToken(
  G_card1, 
  G_card2, 
  H, 
  statement1_card1, 
  statement1_card2, 
  statement2, 
  A_card1, 
  B_card1, 
  A_card2, 
  B_card2, 
  r_card1, 
  r_card2){
  console.log("Javascript: Verifing Token");
  // console.log("G", G)
  // console.log("H", H)
  // console.log("xG", xG)
  // console.log("xH", xH)
  // console.log("A", A)
  // console.log("B", B)
  // console.log("r", r)
}

function revealCommunityCard(pos, card) {
  console.log("Javascript: Reveal community card");
  community_cards[pos] = card;
  console.log(`JS → Community[${pos}] = ${card}`);
  console.log("................. end javascript ......................");
}

function revealPrivateCard(pos, card) {
  console.log("Javascript: Reveal private card");
  private_cards[pos] = card;
  console.log(`JS → Private[${pos}]   = ${card}`);
  console.log("................. end javascript ......................");
}

// Arrancamos la tarea Rust
poker_client_async(
  player_id,
  verifyPublicKey,
  verifyShuffling,
  verifyRevealToken,
  revealCommunityCard,
  revealPrivateCard
);

console.log(
  "Presiona:\n" +
    " [s] → primer mensaje (PublicKeyInfo)\n" +
    " [f] → flop\n" +
    " [t] → turn\n" +
    " [r] → river\n" +
    " [q] → salir"
);

process.stdin.setRawMode(true);
process.stdin.resume();
process.stdin.setEncoding("utf8");

process.stdin.on("data", (key) => {
  switch (key) {
    case "s":
      console.log("JS → send_line('start')");
      send_line("start");
      break;
    case "f":
      console.log("JS → send_line('flop')");
      send_line("flop");
      break;
    case "t":
      console.log("JS → send_line('turn')");
      send_line("turn");
      break;
    case "r":
      console.log("JS → send_line('river')");
      send_line("river");
      break;
    case "q":
      console.log("JS → send_line('exit')");
      send_line("exit");
      process.exit(0);
      break;
    default:
      console.log(`JS → Tecla desconocida: ${key}`);
  }
});
