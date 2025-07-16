// Importamos el módulo nativo construido con Neon
const addon = require('.'); // reemplaza con el path correcto

// Definimos la función callback que recibirá mensajes desde Rust
function handleMessage(msg) {
    console.log('Mensaje recibido desde Rust:', msg);
}

// Llamamos a la función exportada `startLoop` pasando nuestro callback
addon.startLoop(handleMessage);

// El programa seguirá corriendo, recibiendo mensajes cada segundo.
console.log('Esperando mensajes desde Rust...');
