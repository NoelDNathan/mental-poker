
const { 
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
    spades,
    hearts,
    diamonds,
    clubs } = require("./constant");


const POKER = [{
        name: "4 aces",
        cardsRank: [ace, ace, ace, ace, king, queen, jack],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, spades, spades]
    },
    {
        name: "4k q j 3",
        cardsRank: [king, king, king, king, queen, jack, three],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, spades, spades]
    },
    {
        name: "a 4k q 3",
        cardsRank: [ace, king, king, king, king, queen, three],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, spades, spades]
    },
    {
        name: "a a 4k 3",
        cardsRank: [ace, ace, king, king, king, king, three],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, spades, spades]
    },
    {
        name: "a a a 4k",
        cardsRank: [ace, ace, ace, king, king, king, king],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 4q",
        cardsRank: [ace, ace, ace, queen, queen, queen, queen],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 4j",
        cardsRank: [ace, ace, ace, jack, jack, jack, jack],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 10x4",
        cardsRank: [ace, ace, ace, ten, ten, ten, ten],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 9x4",
        cardsRank: [ace, ace, ace, nine, nine, nine, nine],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 8x4",
        cardsRank: [ace, ace, ace, eight, eight, eight, eight],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 7x4",
        cardsRank: [ace, ace, ace, seven, seven, seven, seven],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 6x4",
        cardsRank: [ace, ace, ace, six, six, six, six],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 5x4",
        cardsRank: [ace, ace, ace, five, five, five, five],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 4x4",
        cardsRank: [ace, ace, ace, four, four, four, four],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 3x4",
        cardsRank: [ace, ace, ace, three, three, three, three],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a a a 2x4",
        cardsRank: [ace, ace, ace, two, two, two, two],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
    {
        name: "a k j j j j 5",
        cardsRank: [ace, king, jack, jack, jack, jack, two],
        cardsSuit: [spades, hearts, clubs, diamonds, spades, hearts, clubs]
    },
];

    
    
    





