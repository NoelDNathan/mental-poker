window.addEventListener("load", async () => {
  try {
    await import("./pkg");
    console.log("WebRTC Sequential Demo loaded successfully!");
  } catch (err) {
    console.error("Failed to load WASM module:", err);
  }
});
