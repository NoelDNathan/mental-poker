
const { 
    hello,
    executeCallback
} = require(".");

console.log(hello())

executeCallback(function(arg) {
    console.log("Callback ejecutado con:", arg);
    return "Resultado del callback";
  });
  
// Pasar una función con argumento
patata = executeCallback(
function(message) { 
    console.log(message); 
    return 42; 
}, 
"¡Hola desde JavaScript!"
);

console.log(patata)