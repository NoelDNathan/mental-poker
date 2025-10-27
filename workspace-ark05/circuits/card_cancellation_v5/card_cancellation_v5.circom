pragma circom 2.1.6;

include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/escalarmul.circom";
include "circomlib/circuits/comparators.circom";


template EscalarMulN(n) {
    signal input  k;
    signal input  base[2];
    signal output out[2];

    // Convertir k a binario
    component kBits = Num2Bits(n);
    kBits.in <== k; // Conectar el escalar al convertidor de bits


    // Instancia de la multiplicación escalar   
    component mul = EscalarMulAny(n);

    // Conectar los bits de k a la entrada de EscalarMul
    for (var i = 0; i < n; i++) {
        kBits.out[i] ==> mul.e[i];
    }

    // Conectar el punto base
    base[0] ==> mul.p[0];
    base[1] ==> mul.p[1];

    // Capturar el resultado
    mul.out[0] ==> out[0];
    mul.out[1] ==> out[1];
}
template BabyEqual() {
    signal input x1;
    signal input y1;
    signal input x2;
    signal input y2;
    signal isZeroX;
    signal isZeroY;
    signal output isEqual;

    isZeroX <== IsZero()(x1 - x2);
    isZeroY <== IsZero()(y1 - y2);
     
    isEqual <== isZeroX * isZeroY;

}


// Resta dos puntos en la curva elíptica
template BabySub() {
    signal input x1;
    signal input y1;
    signal input x2;
    signal input y2;
    signal output xout;
    signal output yout;


    component adder = BabyAdd();
    adder.x1 <== x1;
    adder.y1 <== y1;
    adder.x2 <== -x2;
    adder.y2 <== y2;

    adder.xout ==> xout;
    adder.yout ==> yout;
}



template CardCancellation() {
    signal input sk;      
    signal input r_prime[52];
    signal input pk[2];    
    signal input H[2]; // aggregated public key    
    signal input G[2];
    signal input r_prime_G[104]; // precomputed
    signal input r_prime_H[104]; // precomputed
    signal input Ca1_player[2];    
    signal input Cb1_player[2];    
    signal input Ca2_player[2];    
    signal input Cb2_player[2];    
    signal input m[104];  
    signal input Ca[104]; // 52 cartas    
    signal input Cb[104]; // 52 cartas   
    signal output pk_computed[2];   
    signal output Ca_out[104];
    signal output Cb_out[104];    

    //// Verificar que pk es correcto
    component pkVerifier = BabyPbk();
    pkVerifier.in <== sk;

    pk_computed[0] <== pkVerifier.Ax;
    pk_computed[1] <== pkVerifier.Ay;
    pk_computed[0] === pk[0];
    pk_computed[1] === pk[1];
    
    // Calcular sk * Ca
    component skCa1 = EscalarMulN(256);
    skCa1.k <== sk;
    skCa1.base <== Ca1_player;

    component skCa2 = EscalarMulN(256);
    skCa2.k <== sk;
    skCa2.base <== Ca2_player;

    // Calcular m_player = Cb_player - sk * Ca_player
    component computed_m1 = BabyAdd();
    computed_m1.x1 <== Cb1_player[0];
    computed_m1.y1 <== Cb1_player[1];
    computed_m1.x2 <== -skCa1.out[0];
    computed_m1.y2 <== skCa1.out[1];

    component computed_m2 = BabyAdd();
    computed_m2.x1 <== Cb2_player[0];
    computed_m2.y1 <== Cb2_player[1];
    computed_m2.x2 <== -skCa2.out[0];
    computed_m2.y2 <== skCa2.out[1];

    component addHG = BabyAdd();
    addHG.x1 <== H[0];
    addHG.y1 <== H[1];
    addHG.x2 <== G[0];
    addHG.y2 <== G[1];


    //G + H
    component pointEqual1[52];
    component pointEqual2[52];
    component addCa[52];
    component addCb[52];
    component subCb[52];

    component mul_r_prime_GH[52];

    signal isEqual[52];
    signal m_x[52];
    signal m_y[52];
    
    component addprecomputed[52];
    component isEqualPrecomputed[52];

    for(var i = 0; i < 52; i++){
        var index = i*2;
        var indexplus = index + 1;

        addprecomputed[i] = BabyAdd();
        pointEqual1[i] = BabyEqual();
        pointEqual2[i] = BabyEqual();
        isEqualPrecomputed[i] = BabyEqual();
        addCa[i] = BabyAdd();
        addCb[i] = BabyAdd();
        subCb[i] = BabySub();
        mul_r_prime_GH[i] = EscalarMulN(100);

        // r'G + r'H
        addprecomputed[i].x1 <== r_prime_G[index];
        addprecomputed[i].y1 <== r_prime_G[indexplus];
        addprecomputed[i].x2 <== r_prime_H[index];
        addprecomputed[i].y2 <== r_prime_H[indexplus];

        // r' * (G + H)
        mul_r_prime_GH[i].k <== r_prime[i];
        mul_r_prime_GH[i].base <== [addHG.xout, addHG.yout];

        
        // check equality
        isEqualPrecomputed[i].x1 <== addprecomputed[i].xout;
        isEqualPrecomputed[i].y1 <== addprecomputed[i].yout;
        isEqualPrecomputed[i].x2 <== mul_r_prime_GH[i].out[0];
        isEqualPrecomputed[i].y2 <== mul_r_prime_GH[i].out[1];

        isEqualPrecomputed[i].isEqual === 1;

        // Verificar si m es igual a las cartas del jugador
        pointEqual1[i].x1 <== computed_m1.xout;
        pointEqual1[i].y1 <== computed_m1.yout;
        pointEqual1[i].x2 <== m[index];
        pointEqual1[i].y2 <== m[indexplus];

        pointEqual2[i].x1 <== computed_m2.xout;
        pointEqual2[i].y1 <== computed_m2.yout;
        pointEqual2[i].x2 <== m[index];
        pointEqual2[i].y2 <== m[indexplus];

        // isEqual1 or isEqual2
        isEqual[i] <== pointEqual1[i].isEqual + pointEqual2[i].isEqual - (pointEqual1[i].isEqual * pointEqual2[i].isEqual);

        // Calcular Ca_out = Ca + r'G
        addCa[i].x1 <== Ca[index];
        addCa[i].y1 <== Ca[indexplus];
        addCa[i].x2 <== r_prime_G[index];
        addCa[i].y2 <== r_prime_G[indexplus];

        Ca_out[index] <== addCa[i].xout;
        Ca_out[indexplus] <== addCa[i].yout;
    
        // Calcular Cb_temp = Cb + r'H
        addCb[i].x1 <== Cb[index];
        addCb[i].y1 <== Cb[indexplus];
        addCb[i].x2 <== r_prime_H[index];
        addCb[i].y2 <== r_prime_H[indexplus];

        // Si m == computed_m, restamos m de Cb_out
        // identity element is [0, 1], that's why we sum isEqual to m_y

        m_x[i] <== m[index] * isEqual[i];
        m_y[i] <== m[indexplus] * isEqual[i] + (1 - isEqual[i]); 

        subCb[i].x1 <== addCb[i].xout;
        subCb[i].y1 <== addCb[i].yout;
        subCb[i].x2 <== m_x[i];
        subCb[i].y2 <== m_y[i];
        
        Cb_out[index] <== subCb[i].xout;
        Cb_out[indexplus] <== subCb[i].yout;
    }
}


component main {public [pk, G, H, Ca1_player, Cb1_player, Ca2_player, Cb2_player, m, Ca, Cb]} = CardCancellation();
