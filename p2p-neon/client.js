const WebSocket = require("ws");

const {  
    player_pk, 
   
} = require(".");
const ws = new WebSocket("ws://localhost:8080");

ws.on("open", () => {
  console.log("Conectado al servidor WebSocket");
});

ws.on("message", (message) => {
  const data = JSON.parse(message);
  console.log("Mensaje recibido del servidor:", data);
});


