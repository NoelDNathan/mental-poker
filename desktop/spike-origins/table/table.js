// Spike 2.0: la mesa embebe el nucleo de otro origen y comprueba el aislamiento.
const ENGINE = "http://engine.localhost";
const out = {};
const log = (k, v) => {
  out[k] = v;
  document.getElementById("r").textContent = JSON.stringify(out, null, 1);
  window.__spike = out;
};
log("table.origin", location.origin);
log("table.crossOriginIsolated", self.crossOriginIsolated);
log("table.tauriInternals", typeof window.__TAURI_INTERNALS__);
(async () => {
  try {
    log("table.ipc", "ACEPTADO " + (await window.__TAURI_INTERNALS__.invoke("spike_ping")));
  } catch (e) {
    log("table.ipc", "rechazado: " + String((e && e.message) || e));
  }
})();
(async () => {
  try {
    log("table.coreCmd", "ACEPTADO " + (await window.__TAURI_INTERNALS__.invoke("plugin:app|version")));
  } catch (e) {
    log("table.coreCmd", "rechazado: " + String((e && e.message) || e));
  }
})();
fetch("http://prover.localhost/ping", { method: "POST" })
  .then(async (r) => log("table.prover", "status " + r.status + " " + (await r.text())))
  .catch((e) => log("table.prover", "error: " + e.message));

const frame = document.createElement("iframe");
frame.allow = "cross-origin-isolated";
frame.src = ENGINE + "/engine.html";
frame.width = "600";
frame.height = "200";
window.addEventListener("message", (ev) => {
  if (ev.source !== frame.contentWindow) return;
  log("table.hello.origin", ev.origin);
  if (ev.origin !== ENGINE) return;
  const ch = new MessageChannel();
  ch.port1.onmessage = (m) => log("engine.report", m.data);
  frame.contentWindow.postMessage({ type: "connect" }, ENGINE, [ch.port2]);
});
document.body.append(frame);
setTimeout(() => {
  try {
    void frame.contentWindow.document.body;
    log("table.engineDom", "ACCESIBLE");
  } catch {
    log("table.engineDom", "bloqueado");
  }
}, 3000);
