const { poker_client_async, send_line } = require(".");
// const BlockchainApiClass = require("../../frontend/src/bridge/BlockchaiApi"); // Comentado por ahora

async function loadBlockchainApi() {
  try {
    const pokerContractInfo = require("../../smartcontracts/contracts-config.json");
    // const pokerContractInfo = await import("../../smartcontracts/contracts-config.json");
    const module = require("../../frontend/compiled/bridge/BlockchaiApi.js");

    console.log("pokerContractInfo", pokerContractInfo);

    const pokerContractAddress = pokerContractInfo.poker_diamond;
    const tokenContractAddress = pokerContractInfo.gameToken;
    const instance = new module.default(pokerContractAddress, tokenContractAddress, "account");
    console.log("BlockchainApiClass", instance);
    return instance;
  } catch (error) {
    console.warn("Could not load BlockchainAPI:", error.message);
    return null;
  }
}

async function poker_client(player_id, setCommunityCard, setPrivateCards, useTerminal) {
  if (!player_id) {
    console.error("Player id is required");
    return;
  }
  const BlockchainApi = await loadBlockchainApi();
  console.log("BlockchainApiClass", BlockchainApi);


  function verifyPublicKey(public_key, r, s) {
    console.log("Javascript: Verify public key");
    console.log("JS Public key:", public_key);
    console.log("JS Proof:", r, s);
    console.log("................. end javascript ......................");
    BlockchainApiClass.newPlayer(105, public_key, r, s);
  }

  function verifyShuffling(pubSignals, proof) {
    console.log("Javascript: Shuffling");
    // console.log("JS Public info:", pubSignals);
    // console.log("JS Proof:", proof);
    console.log("................. end javascript ......................");
    BlockchainApiClass.shufflingCards(proof[0], proof[1], proof[2], pubSignals);
  }
  function verifyReshuffling(pubSignals, proof) {
    console.log("Javascript: Reshuffling");
    console.log("................. end javascript ......................");
    BlockchainApiClass.reshufflingCards(proof[0], proof[1], proof[2], pubSignals);
  }

  // @param G Base point G
  // @param H Base point H
  // @param S0 S0 = xG
  // @param S1 S1 = xH
  // @param A Commitment A = rP
  // @param B Commitment B = rR
  // @param r Response r

  function verifyRevealToken(
    receiverChair,
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
    r_card2
  ) {
    console.log("Javascript: Verifing Token");
    // console.log("G", G)
    // console.log("H", H)
    // console.log("xG", xG)
    // console.log("xH", xH)
    // console.log("A", A)
    // console.log("B", B)
    // console.log("r", r)

    const tokens = [statement1_card1, statement1_card2];
    const A = [A_card1, A_card2];
    const B = [B_card1, B_card2];
    const r = [r_card1, r_card2];
    BlockchainApiClass.sendRevealPlayerCardTokens(receiverChair, tokens, A, B, r);
  }

  function revealCommunityCard(pos, card) {
    console.log("Javascript: Reveal community card");
    // community_cards[pos] = card;
    console.log(`JS → Community[${pos}] = ${card}`);
    console.log("................. end javascript ......................");
    // setCommunityCard(pos, card);
  }

  function revealPrivateCard(pos, card) {
    console.log("Javascript: Reveal private card");
    // private_cards[pos] = card;
    console.log(`JS → Private[${pos}]   = ${card}`);
    console.log("................. end javascript ......................");
    // setPrivateCards(pos, card);
  }

  console.log("Javascript: Starting poker client");
  // Arrancamos la tarea Rust
  poker_client_async(
    player_id,
    verifyPublicKey,
    verifyShuffling,
    verifyRevealToken,
    revealCommunityCard,
    revealPrivateCard
  );

  function start() {
    console.log("JS → send_line('start')");
    send_line("start");
  }
  function flop() {
    console.log("JS → send_line('flop')");
    send_line("flop");
  }
  function turn() {
    console.log("JS → send_line('turn')");
    send_line("turn");
  }
  function river() {
    console.log("JS → send_line('river')");
    send_line("river");
  }
  function exit() {
    console.log("JS → send_line('exit')");
    send_line("exit");
  }

  if (useTerminal) {
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
      console.log("JS → Tecla: ", key);
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
  } else {
    return {
      start,
      flop,
      turn,
      river,
      exit,
    };
  }
}

const player_id = process.argv[2];

poker_client(
  player_id,
  () => {},
  () => {},
  true
);
// Cambiar de export a module.exports
module.exports = { poker_client };
