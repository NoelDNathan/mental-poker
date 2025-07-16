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

function revealCommunityCard(pos, card) {
  community_cards[pos] = card;
  console.log(`JS → Community[${pos}] = ${card}`);
}

function revealPrivateCard(pos, card) {
  private_cards[pos] = card;
  console.log(`JS → Private[${pos}]   = ${card}`);
}

// Arrancamos la tarea Rust
poker_client_async(player_id, revealCommunityCard, revealPrivateCard);

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
