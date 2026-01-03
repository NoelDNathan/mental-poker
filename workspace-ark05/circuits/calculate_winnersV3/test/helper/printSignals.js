

const printSignals = (circuit, witness, options = {}) => {
  const {
    only = null,        // array de nombres o prefijos
    hideZero = false,   // no mostrar signals con valor 0
    sort = true         // ordenar alfabéticamente
  } = options;

  let entries = Object.entries(circuit.symbols);

  if (sort) {
    entries.sort(([a], [b]) => a.localeCompare(b));
  }

  for (const [name, info] of entries) {
    if (only) {
      const match = only.some(prefix => name.startsWith(prefix));
      if (!match) continue;
    }

    const value = witness[info.varIdx];

    if (hideZero && value === 0n) continue;
    if (value === undefined) continue;

    console.log(`${name} = ${value.toString()}`);
  }
}

module.exports = { printSignals };