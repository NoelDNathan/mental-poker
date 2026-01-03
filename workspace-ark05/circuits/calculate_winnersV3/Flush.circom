pragma circom 2.1.9;
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "SelectorUnchecked.circom";

template Flush(maxNumBits) {
    signal input cardsRank[7];
    signal input cardsSuit[7];
    signal output scoreOut;
    signal output isSuit[4][7];  // Output bidimensional para isSuit

    // Arrays bidimensionales: [suit][index]
    // suit: 0=spades, 1=hearts, 2=diamonds, 3=clubs
    signal count[4][8];
    signal scores[4][8];
    
    component isSuitComponents[4][7];
    component hasFlush[4];
    component lessThan5[4][2];
    component selectors[4][8];

    // Inicializar contadores y scores
    for (var suit = 0; suit < 4; suit++) {
        count[suit][0] <== 0;
        scores[suit][0] <== 0;
    }

    // Bucle principal: procesar cada carta
    for (var i = 1; i < 8; i++) {
        var i_card = i - 1;
        
        // Verificar si cada carta pertenece a cada palo
        for (var suit = 0; suit < 4; suit++) {
            isSuitComponents[suit][i_card] = IsEqual();
            isSuitComponents[suit][i_card].in <== [cardsSuit[i_card], suit];
            
            // Asignar el output del componente a la señal de salida
            isSuit[suit][i_card] <== isSuitComponents[suit][i_card].out;
            
            // Actualizar contador
            count[suit][i] <== count[suit][i-1] + isSuit[suit][i_card];
        }

        // Para las últimas 2 cartas (i > 5), aplicar lógica de selección
        if (i > 5) {
            var index = i - 6;
            
            for (var suit = 0; suit < 4; suit++) {
                // Verificar si count < 5
                lessThan5[suit][index] = LessThan(maxNumBits);
                lessThan5[suit][index].in <== [count[suit][i], 6];
                
                // Selector: solo actualizar score si es del palo Y count < 5
                selectors[suit][i] = SelectorUnchecked();
                selectors[suit][i].condition <== isSuit[suit][i_card] * lessThan5[suit][index].out;
                selectors[suit][i].true <== (scores[suit][i-1] * 13 + cardsRank[i_card] + 1) * isSuit[suit][i_card];
                selectors[suit][i].false <== scores[suit][i-1];
                scores[suit][i] <== selectors[suit][i].out;
            }
        } else {
            // Para las primeras 5 cartas, acumular normalmente
            for (var suit = 0; suit < 4; suit++) {
                selectors[suit][i] = SelectorUnchecked();
                selectors[suit][i].condition <== isSuit[suit][i_card];
                selectors[suit][i].true <== (scores[suit][i-1] * 13 + cardsRank[i_card] + 1);
                selectors[suit][i].false <== scores[suit][i-1];
                scores[suit][i] <== selectors[suit][i].out;
            }
        }
    }

    // Verificar si cada palo tiene flush (>= 5 cartas)
    for (var suit = 0; suit < 4; suit++) {
        hasFlush[suit] = GreaterThan(maxNumBits);
        hasFlush[suit].in <== [count[suit][7], 4];  // >= 5 significa > 4
    }

    // Calcular score final para cada palo
    signal suitScores[4];
    for (var suit = 0; suit < 4; suit++) {
        suitScores[suit] <== scores[suit][7] * hasFlush[suit].out;
    }

    // Sumar todos los scores
    scoreOut <== suitScores[0] + suitScores[1] + suitScores[2] + suitScores[3];
}

