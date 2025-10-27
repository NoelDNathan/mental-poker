pragma circom 2.1.6;

include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/escalarmul.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

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


template AssertDistinct(n) {
  signal input in[n];
  var acc = 0;
  for (var i = 0; i < n-1; i++){
    for (var j = i+1; j < n; j++){
      var eq = IsEqual()([in[i], in[j]]);
      acc += 1 - eq;
    }
  }

  acc === n * (n - 1) / 2;
}


template IsInRange(maxNumBits) {
  signal input MIN;
  signal input num;
  signal input MAX;
  signal output out;

  component isLessThan = LessEqThan(maxNumBits);
  isLessThan.in <== [num, MAX];
  component isGreaterThan = GreaterThan(maxNumBits);
  isGreaterThan.in <== [num, MIN];

  component isInRange = AND();
  isInRange.a <== isLessThan.out;
  isInRange.b <== isGreaterThan.out;
  
  out <== isInRange.out;

}

template PermutationByIndex(n) {
    signal input Ca[n*2];
    signal input Cb[n*2];
    signal input sel[n]; // valores 0..n-1
    signal output CaOut[n*2];
    signal output CbOut[n*2];

    component eq[n][n];
    signal productsCaX[n][n];
    signal productsCaY[n][n];
    signal productsCbX[n][n];
    signal productsCbY[n][n];
    signal sumsCaX[n][n+1];
    signal sumsCaY[n][n+1];
    signal sumsCbX[n][n+1];
    signal sumsCbY[n][n+1];

    for (var i = 0; i < n; i++) {
        sumsCaX[i][0] <== 0;
        sumsCaY[i][0] <== 0;
        sumsCbX[i][0] <== 0;
        sumsCbY[i][0] <== 0;
        for (var j = 0; j < n; j++) {
            eq[i][j] = IsEqual();
            eq[i][j].in[0] <== sel[i];
            eq[i][j].in[1] <== j;

            productsCaX[i][j] <== Ca[j*2]   * eq[i][j].out;
            productsCaY[i][j] <== Ca[j*2+1] * eq[i][j].out;
            productsCbX[i][j] <== Cb[j*2]   * eq[i][j].out;
            productsCbY[i][j] <== Cb[j*2+1] * eq[i][j].out;

            sumsCaX[i][j+1] <== sumsCaX[i][j] + productsCaX[i][j];
            sumsCaY[i][j+1] <== sumsCaY[i][j] + productsCaY[i][j];
            sumsCbX[i][j+1] <== sumsCbX[i][j] + productsCbX[i][j];
            sumsCbY[i][j+1] <== sumsCbY[i][j] + productsCbY[i][j];
        }
        CaOut[i*2]   <== sumsCaX[i][n];
        CaOut[i*2+1] <== sumsCaY[i][n];
        CbOut[i*2]   <== sumsCbX[i][n];
        CbOut[i*2+1] <== sumsCbY[i][n];
    }
}


template Shuffling() {
    signal input r_prime[52];
    signal input permutations[52];
    signal input H[2]; // aggregated public key    
    signal input G[2];
    signal input r_prime_G[104];
    signal input r_prime_H[104];
    signal input Ca[104]; // 52 cartas    
    signal input Cb[104]; // 52 cartas   
    

    
    signal output Ca_out[104];
    signal output Cb_out[104];    
    
    
    //G + H
    component addHG = BabyAdd();
    addHG.x1 <== H[0];
    addHG.y1 <== H[1];
    addHG.x2 <== G[0];
    addHG.y2 <== G[1];

    component addCa[52];
    component addCb[52];
    component mul_r_prime_GH[52];
    component addprecomputed[52];
    component isEqualPrecomputed[52];
    

    // Verificar rango de permutations
    component inRange[52];
    for (var i = 0; i < 52; i++) {
        inRange[i] = IsInRange(6);
        inRange[i].MIN <== -1;
        inRange[i].MAX <== 52;
        inRange[i].num <== permutations[i];
        inRange[i].out === 1;
    }

    // Verificar que no se repiten
    component assertDistinct = AssertDistinct(52);
    assertDistinct.in <== permutations;

    for(var i = 0; i < 52; i++){
        var index = i*2;
        var indexplus = index + 1;

        addprecomputed[i] = BabyAdd();
        isEqualPrecomputed[i] = BabyEqual();
        addCa[i] = BabyAdd();
        addCb[i] = BabyAdd();
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

        // Calcular Ca_out = Ca + r'G
        addCa[i].x1 <== Ca[index];
        addCa[i].y1 <== Ca[indexplus];
        addCa[i].x2 <== r_prime_G[index];
        addCa[i].y2 <== r_prime_G[indexplus];
    
        // Calcular Cb_temp = Cb + r'H
        addCb[i].x1 <== Cb[index];
        addCb[i].y1 <== Cb[indexplus];
        addCb[i].x2 <== r_prime_H[index];
        addCb[i].y2 <== r_prime_H[indexplus];

    }

    // Ahora que todos los puntos están calculados, prepara los arrays para la permutación
    signal permInCa[104];
    signal permInCb[104];
    for (var i = 0; i < 52; i++) {
        var idx = i * 2;
        permInCa[idx]   <== addCa[i].xout;
        permInCa[idx+1] <== addCa[i].yout;
        permInCb[idx]   <== addCb[i].xout;
        permInCb[idx+1] <== addCb[i].yout;
    }

    // Instancia y conecta la permutación
    component permutation = PermutationByIndex(52);
    permutation.Ca <== permInCa;
    permutation.Cb <== permInCb;
    permutation.sel <== permutations;

    Ca_out <== permutation.CaOut;
    Cb_out <== permutation.CbOut;
}


component main {public [G, H, Ca, Cb]} = Shuffling();
