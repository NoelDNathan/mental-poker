const ace = 12;
const king = 11;
const queen = 10;
const jack = 9;
const ten = 8;
const nine = 7;
const eight = 6;
const seven = 5;
const six = 4;
const five = 3;
const four = 2;
const three = 1;
const two = 0;


const spades = 0;
const hearts = 1;
const diamonds = 2;
const clubs = 3;

const rankBase1 = 1;      // 13^1
const rankBase2 = 13;     // 13^2
const rankBase3 = 169;    // 13^3
const rankBase4 = 2197;   // 13^4
const rankBase5 = 28561;  // 13^5
const rankBase6 = 371293; // 13^6
const rankBase7 = 62748517; // 13^7


const STRAIGHT_FLUSH_OFFSET = 80000000
const FOUR_OF_A_KIND_OFFSET = 70000000
const FULL_HOUSE_OFFSET = 60000000
const FLUSH_OFFSET = 50000000
const STRAIGHT_OFFSET = 40000000
const THREE_OF_A_KIND_OFFSET = 30000000
const TWO_PAIR_OFFSET = 20000000
const ONE_PAIR_OFFSET = 10000000
const HIGH_CARD_OFFSET = 0

const RANKS = {
    ace,
    king,
    queen,
    jack,
    ten,
    nine,
    eight,
    seven,
    six,
    five,
    four,
    three,
    two,
}

const SUITS = {
    spades,
    hearts,
    diamonds,
    clubs,
}

const BASES = {
    1: rankBase1,
    2: rankBase2,
    3: rankBase3,
    4: rankBase4,
    5: rankBase5,
    6: rankBase6,
    7: rankBase7,
}

const allspades = [SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades, SUITS.spades]
const allhearts = [SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts, SUITS.hearts]
const alldiamonds = [SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds, SUITS.diamonds]
const allclubs = [SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs, SUITS.clubs]
const allstraighs = [
    [RANKS.ace, RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten], // score : 10
    [RANKS.king, RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine], // score : 9
    [RANKS.queen, RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight], // score : 8
    [RANKS.jack, RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven], // score : 7
    [RANKS.ten, RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six], // score : 6
    [RANKS.nine, RANKS.eight, RANKS.seven, RANKS.six, RANKS.five], // score : 5
    [RANKS.eight, RANKS.seven, RANKS.six, RANKS.five, RANKS.four], // score : 4
    [RANKS.seven, RANKS.six, RANKS.five, RANKS.four, RANKS.three], // score : 3
    [RANKS.six, RANKS.five, RANKS.four, RANKS.three, RANKS.two], // score : 2
    [RANKS.ace, RANKS.five, RANKS.four, RANKS.three, RANKS.two] // score : 1
];


module.exports = {
    allspades,
    allhearts,
    alldiamonds,
    allclubs,
    allstraighs,
    BASES,
    RANKS,
    SUITS,
    STRAIGHT_FLUSH_OFFSET,
    FOUR_OF_A_KIND_OFFSET,
    FULL_HOUSE_OFFSET,
    FLUSH_OFFSET,
    STRAIGHT_OFFSET,
    THREE_OF_A_KIND_OFFSET,
    TWO_PAIR_OFFSET,
    ONE_PAIR_OFFSET,
    HIGH_CARD_OFFSET,
};
