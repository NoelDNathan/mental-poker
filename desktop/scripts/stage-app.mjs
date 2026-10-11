#!/usr/bin/env node
/**
 * Fase 2 / 2.4: reune la carpeta de app de escritorio que sirven los
 * protocolos `table` y `engine` (src-tauri/src/serve) y que se empaqueta junto
 * al .exe como `app/`:
 *
 *   <out>/table/                 export estatico de la mesa (con csp.txt)
 *   <out>/engine/                build del nucleo (engine.html + assets/)
 *   <out>/public/                solo lo que el nucleo necesita: wasm y precompute/vhyb
 *   <out>/public/release-manifest.json y <out>/table/release-manifest.json
 *   <out>/desktop-config.json    {"engineConnect": [...]} para la CSP del nucleo
 *
 * Los ficheros grandes se enlazan (hard link) si se puede, para no duplicar
 * cientos de MB en disco; si no, se copian. Nunca se siguen enlaces simbolicos
 * dentro de los directorios copiados (salvo las raices pedidas).
 *
 * Uso:
 *   node desktop/scripts/stage-app.mjs --fe <frontend-production> \
 *     --table <export de la mesa> --engine <engine-dist> --out <dir> \
 *     --connect "ws://127.0.0.1:2794 http://127.0.0.1:8545" [--version 1]
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, linkSync, lstatSync, mkdirSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

/** Lo que el nucleo pide a su origen (engine/server.mjs PUBLIC_PREFIXES). */
const PUBLIC_DIRS = ["pkg-rayon-native-20261006", "precompute/vhyb"];

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0) return process.argv[i + 1];
  if (def === undefined) throw new Error(`falta --${name}`);
  return def;
}

let linked = 0;
let copied = 0;
let bytes = 0;

function placeFile(src, dst) {
  try {
    linkSync(src, dst);
    linked++;
  } catch {
    copyFileSync(src, dst);
    copied++;
  }
  bytes += statSync(src).size;
}

/** Copia `src` (se resuelve si es un enlace) a `dst`, sin seguir enlaces de dentro. */
function copyTree(src, dst) {
  const root = realpathSync(src);
  mkdirSync(dst, { recursive: true });
  for (const name of readdirSync(root)) {
    const from = join(root, name);
    const st = lstatSync(from);
    if (st.isSymbolicLink()) {
      console.warn(`  [aviso] enlace omitido: ${from}`);
    } else if (st.isDirectory()) {
      copyTree(from, join(dst, name));
    } else if (st.isFile()) {
      placeFile(from, join(dst, name));
    }
  }
}

const fe = resolve(arg("fe"));
const table = resolve(arg("table"));
const engine = resolve(arg("engine"));
const out = resolve(arg("out"));
const connect = arg("connect").split(/\s+/).filter(Boolean);
const version = arg("version", "1");

for (const [n, p] of [["mesa", join(table, "index.html")], ["nucleo", join(engine, "engine.html")], ["csp de la mesa", join(table, "csp.txt")]]) {
  if (!existsSync(p)) throw new Error(`no existe ${n}: ${p}`);
}

rmSync(out, { recursive: true, force: true });
console.log(`[stage] ${out}`);
copyTree(table, join(out, "table"));
copyTree(engine, join(out, "engine"));
for (const d of PUBLIC_DIRS) copyTree(join(fe, "public", d), join(out, "public", d));

// Manifiesto de ESTA build (los hashes del nucleo de escritorio, no los del lab web).
const manifest = join(out, "public", "release-manifest.json");
execFileSync(process.execPath, [join(fe, "scripts", "release-manifest.mjs"), "--version", version, "--engine-dist", engine, "--out", manifest], {
  stdio: "inherit",
});
copyFileSync(manifest, join(out, "table", "release-manifest.json"));
// El webview pide /favicon.ico por su cuenta; sin el, un 404 en cada carga.
copyFileSync(new URL("../src-tauri/icons/icon.ico", import.meta.url), join(out, "table", "favicon.ico"));

writeFileSync(join(out, "desktop-config.json"), JSON.stringify({ engineConnect: connect }, null, 2) + "\n");
console.log(`[stage] ${linked} enlazados, ${copied} copiados, ${(bytes / 1e6).toFixed(1)} MB`);
