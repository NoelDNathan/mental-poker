// Spike 2.0: el nucleo en su origen; solo el debe poder llamar al nativo.
const TABLE = "http://table.localhost";
const rep = {
  origin: location.origin,
  crossOriginIsolated: self.crossOriginIsolated,
  tauriInternals: typeof window.__TAURI_INTERNALS__,
};
try {
  new SharedArrayBuffer(8);
  rep.sharedArrayBuffer = "ok";
} catch (e) {
  rep.sharedArrayBuffer = "error " + e.message;
}
async function run(port) {
  try {
    rep.ipc = "ACEPTADO " + (await window.__TAURI_INTERNALS__.invoke("spike_ping"));
  } catch (e) {
    rep.ipc = "rechazado: " + String((e && e.message) || e);
  }
  try {
    const r = await fetch("http://prover.localhost/ping", { method: "POST" });
    rep.prover = "status " + r.status + " " + (await r.text());
  } catch (e) {
    rep.prover = "error: " + e.message;
  }
  port.postMessage(rep);
}
window.addEventListener("message", (ev) => {
  if (ev.origin !== TABLE || !ev.ports[0]) return;
  run(ev.ports[0]);
});
parent.postMessage({ type: "hello" }, TABLE);
