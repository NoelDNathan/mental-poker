pragma circom 2.1.9;

// Centralized compile-time constants for V3 circuits.
//
// Circom 2.2.x does not support a `global` keyword, so we expose constants via
// functions which can be used in `var` assignments and template parameters.

// ---------------------------------------------------------------------------
// Rank mapping (two=0 .. ace=12)
// ---------------------------------------------------------------------------
function rankTwo() { return 0; }
function rankThree() { return 1; }
function rankFour() { return 2; }
function rankFive() { return 3; }
function rankSix() { return 4; }
function rankSeven() { return 5; }
function rankEight() { return 6; }
function rankNine() { return 7; }
function rankTen() { return 8; }
function rankJack() { return 9; }
function rankQueen() { return 10; }
function rankKing() { return 11; }
function rankAce() { return 12; }

// ---------------------------------------------------------------------------
// Suits mapping (clubs=0, diamonds=1, hearts=2, spades=3)
// ---------------------------------------------------------------------------
function suitClubs() { return 0; }
function suitDiamonds() { return 1; }
function suitHearts() { return 2; }
function suitSpades() { return 3; }

// ---------------------------------------------------------------------------
// Rank base powers (13^k) for score encoding
// ---------------------------------------------------------------------------
function rankBase1() { return 1; }        // 13^0
function rankBase2() { return 13; }       // 13^1
function rankBase3() { return 169; }      // 13^2
function rankBase4() { return 2197; }     // 13^3
function rankBase5() { return 28561; }    // 13^4
function rankBase6() { return 371293; }   // 13^5
function rankBase7() { return 4826809; }  // 13^6

// ---------------------------------------------------------------------------
// Category offsets (must dominate any within-category score)
// ---------------------------------------------------------------------------
function straightFlushOffset() { return 80000000; }
function pokerOffset() { return 70000000; }
function fullHouseOffset() { return 60000000; }
function flushOffset() { return 50000000; }
function straightOffset() { return 40000000; }
function trioOffset() { return 30000000; }
function doublePairsOffset() { return 20000000; }
function pairsOffset() { return 10000000; }
function highCardsOffset() { return 0; }
