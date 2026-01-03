import random
import sys

sys.setrecursionlimit(2000)

RANKS = ['two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'jack', 'queen', 'king', 'ace']
SUITS = ['spades', 'hearts', 'diamonds', 'clubs']

RANK_MAP = {r: i for i, r in enumerate(RANKS)}

def get_rank_val(r_name):
    return RANK_MAP[r_name]

def sort_hand(hand):
    return sorted(hand, key=lambda x: get_rank_val(x[0]), reverse=True)

def fmt_hand(hand, name, idx):
    sorted_h = sort_hand(hand)
    ranks = [x[0] for x in sorted_h]
    suits = [x[1] for x in sorted_h]
    
    return f'''    {{
        name: "{name}",
        index: {idx},  
        cardsRank: [{', '.join(ranks)}],
        cardsSuit: [{', '.join(suits)}]
    }},'''

def gen_straight_flush():
    suit = random.choice(SUITS)
    start_vals = list(range(0, 9))
    sv = random.choice(start_vals)
    ranks_idx = [sv, sv+1, sv+2, sv+3, sv+4]
    hand = [(RANKS[r], suit) for r in ranks_idx]
    
    tries = 0
    while len(hand) < 7 and tries < 100:
        tries += 1
        r = random.choice(RANKS)
        s = random.choice(SUITS)
        if (r,s) not in hand:
            if s != suit:
               hand.append((r,s))
            else:
               rv = get_rank_val(r)
               if rv != sv-1 and rv != sv+5:
                   hand.append((r,s))
    return hand

def gen_quads():
    r1 = random.choice(RANKS)

    # Las 4 cartas del mismo rango
    hand = [(r1, s) for s in SUITS]

    # Kickers con rangos distintos al del quad
    rem_ranks = [r for r in RANKS if r != r1]
    kickers = random.sample(rem_ranks, 3)

    for r in kickers:
        hand.append((r, random.choice(SUITS)))

    # Evitar flush accidental
    from collections import Counter
    sc = Counter([x[1] for x in hand])
    for s, c in sc.items():
        if c >= 5:
            return gen_quads()

    # Evitar straight accidental
    run_ranks = sorted(set(get_rank_val(x[0]) for x in hand))
    cons = 1
    max_cons = 1
    for i in range(1, len(run_ranks)):
        if run_ranks[i] == run_ranks[i-1] + 1:
            cons += 1
        else:
            cons = 1
        max_cons = max(max_cons, cons)

    if max_cons >= 5:
        return gen_quads()

    return hand

def gen_full_house():
    r1 = random.choice(RANKS)
    remaining_ranks = [r for r in RANKS if r != r1]
    r2 = random.choice(remaining_ranks)
    
    s1 = random.sample(SUITS, 3)
    hand = [(r1, s) for s in s1]
    
    s2 = random.sample(SUITS, 2)
    hand += [(r2, s) for s in s2]
    
    tries = 0
    while len(hand) < 7 and tries < 100:
        tries += 1
        r = random.choice(RANKS)
        if r != r1 and r != r2:
            s = random.choice(SUITS)
            if (r,s) not in hand:
                hand.append((r,s))
    return hand

def gen_flush():
    suit = random.choice(SUITS)
    attempts = 0
    while True:
        attempts += 1
        if attempts > 1000: return gen_flush()
        r_indices = random.sample(range(13), 5)
        r_indices.sort()
        is_cons = all(r_indices[i] == r_indices[i-1]+1 for i in range(1,5))
        is_wheel = (r_indices == [0,1,2,3,12])
        if not is_cons and not is_wheel:
            break
            
    hand = [(RANKS[i], suit) for i in r_indices]
    
    tries = 0
    while len(hand) < 7 and tries < 100:
        tries += 1
        r = random.choice(RANKS)
        s = random.choice(SUITS)
        if s != suit:
            hand.append((r,s))
    return hand

def gen_straight():
    start_vals = list(range(0, 9))
    sv = random.choice(start_vals)
    ranks_idx = [sv, sv+1, sv+2, sv+3, sv+4]
    
    hand = []
    while True:
        suits = [random.choice(SUITS) for _ in range(5)]
        if len(set(suits)) > 1:
            break
    
    for i in range(5):
        hand.append((RANKS[ranks_idx[i]], suits[i]))
        
    tries = 0
    while len(hand) < 7 and tries < 100:
        tries += 1
        r = random.choice(RANKS)
        s = random.choice(SUITS)
        if (r,s) not in hand:
            r_val = get_rank_val(r)
            if r_val == sv-1 or r_val == sv+5:
                continue
            current_suits = [x[1] for x in hand] + [s]
            from collections import Counter
            sc = Counter(current_suits)
            if sc[s] >= 5:
                continue
            hand.append((r,s))
    return hand

def gen_trips():
    r1 = random.choice(RANKS)
    s1 = random.sample(SUITS, 3)
    hand = [(r1, s) for s in s1]
    
    rem_ranks = [r for r in RANKS if r != r1]
    others = random.sample(rem_ranks, 4)
    
    for r in others:
        s = random.choice(SUITS)
        hand.append((r,s))
        
    from collections import Counter
    sc = Counter([x[1] for x in hand])
    for s, c in sc.items():
        if c >= 5:
            return gen_trips()
    return hand

def gen_double_pair():
    r1, r2 = random.sample(RANKS, 2)
    s1 = random.sample(SUITS, 2)
    s2 = random.sample(SUITS, 2)
    hand = [(r1, s) for s in s1] + [(r2, s) for s in s2]
    
    rem = [r for r in RANKS if r!=r1 and r!=r2]
    others = random.sample(rem, 3)
    for r in others:
        hand.append((r, random.choice(SUITS)))
        
    from collections import Counter
    sc = Counter([x[1] for x in hand])
    for s, c in sc.items():
        if c >= 5:
            return gen_double_pair()
    return hand

def gen_pair():
    r1 = random.choice(RANKS)
    s1 = random.sample(SUITS, 2)
    hand = [(r1, s) for s in s1]
    rem = [r for r in RANKS if r!=r1]
    others = random.sample(rem, 5)
    for r in others:
        hand.append((r, random.choice(SUITS)))
        
    from collections import Counter
    sc = Counter([x[1] for x in hand])
    for s, c in sc.items():
        if c >= 5: return gen_pair()
        
    run_ranks = [get_rank_val(x[0]) for x in hand]
    run_ranks.sort()
    cons = 1
    max_cons = 1
    for i in range(1, 7):
        if run_ranks[i] == run_ranks[i-1] + 1:
            cons += 1
        elif run_ranks[i] != run_ranks[i-1]:
            cons = 1
        max_cons = max(max_cons, cons)
    if max_cons >= 5: return gen_pair()
    
    return hand

def gen_high_card():
    while True:
        ranks_idx = random.sample(range(13), 7)
        ranks_idx.sort()
        cons = 1
        max_cons = 1
        for i in range(1, 7):
            if ranks_idx[i] == ranks_idx[i-1] + 1:
                cons += 1
            else:
                cons = 1
            max_cons = max(max_cons, cons)
        if max_cons >= 5: continue
        
        hand = []
        suit_counts = {s:0 for s in SUITS}
        valid_hand = True
        for idx in ranks_idx:
            avail = [s for s in SUITS if suit_counts[s] < 4]
            if not avail:
                valid_hand = False
                break
            s = random.choice(avail)
            suit_counts[s] += 1
            hand.append((RANKS[idx], s))
        if valid_hand:
            return hand

cats = [
    ('straight_flush', gen_straight_flush),
    ("poker", gen_quads),
    ('full_house', gen_full_house),
    ('flush', gen_flush),
    ('straight', gen_straight),
    ('trips', gen_trips),
    ('double_pair', gen_double_pair),
    ('pair', gen_pair),
    ('high_card', gen_high_card)
]

n = 51

print('''const { 
    ace, king, queen, jack, ten, nine, eight, seven, six, five, four, three, two, 
    spades, hearts, diamonds, clubs 
} = require("./constant");''')

for name, gen_func in cats:
    print("const " + name.upper() + " = [")
    for i in range(1, n):
        try:
            h = gen_func()
            print(fmt_hand(h, name, i))
        except Exception:
            pass
    print('];')
    
print('module.exports = { STRAIGHT_FLUSH, POKER, FULL_HOUSE, FLUSH, STRAIGHT, TRIPS, DOUBLE_PAIR, PAIR, HIGH_CARD };')

# python generate_hand.py > generated_hand.ts