const { poker_client_async } = require(".");

community_cards = [null, null, null, null, null];

player_cards = [null, null];

function revealCommunityCard(pos, card) {
  console.log("Javascript: Reveal community card");
  community_cards[pos] = card;
  console.log("Carta:", card, "en posición:", pos);
}

function revealPrivateCard(pos, card) {
  console.log("Javascript: Reveal private card");
  private_cards[pos] = card;
  console.log("Carta:", card, "en posición:", pos);
}

function setPublicKey(public_key) {
  console.log("Javascript: Set public key");
  console.log("Public key:", public_key);
}

function setEncryptedCards(encrypted_cards) {
  console.log("Encrypted cards:", encrypted_cards);
}


// Configurar la entrada de teclado para detectar 'q'
process.stdin.setRawMode(true);
process.stdin.resume();
process.stdin.setEncoding("utf8");

poker_client_async(setPublicKey, revealCommunityCard, revealPrivateCard);

// let intervalId = null;

// // Evento para manejar la entrada de teclado
process.stdin.on("data", (key) => {
  // Si se pulsa 'q', detener el intervalo y salir
  if (key === "q") {
    if (intervalId) {
      clearInterval(intervalId);
    }
    console.log("Saliendo...");
    process.exit();
  }

  if (key === "c") {
    console.log("Mostrando cartas comunitarias cada 3 segundos. Presiona 'q' para salir.");
    intervalId = setInterval(() => {
      console.log("Cartas comunitarias actuales:", community_cards);
    }, 3000);
  }

  if (key === "p") {
    console.log("Mostrando cartas privadas cada 3 segundos. Presiona 'q' para salir.");
    intervalId = setInterval(() => {
      console.log("Cartas privadas actuales:", private_cards);
    }, 3000);
  }

  if (key === "p") {
    console.log("Mostrando cartas privadas cada 3 segundos. Presiona 'q' para salir.");
    intervalId = setInterval(() => {
      console.log("Cartas privadas actuales:", private_cards);
    }, 3000);
  }
});
// // Iniciar el intervalo para mostrar las cartas comunitarias cada 3 segundos
// console.log('Mostrando cartas comunitarias cada 3 segundos. Presiona "q" para salir.');
// intervalId = setInterval(() => {
//   console.log("Cartas comunitarias actuales:", community_cards);
// }, 3000);
