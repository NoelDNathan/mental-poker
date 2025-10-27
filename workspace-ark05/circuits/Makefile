BUILD_CIRCUIT = ../circom-witnesscalc/target/release/build-circuit.exe

build:
	mkdir -p build

.PRECIOUS: build/%.graph build/%.r1cs
build/%.graph build/%.r1cs: %.circom $(BUILD_CIRCUIT) build
	$(BUILD_CIRCUIT) --r1cs build/$*.r1cs $< build/$*.graph

# En tu Makefile
build-shuffling:
	$(BUILD_CIRCUIT) --r1cs build/shuffling.r1cs shuffling/shuffling.circom build/shuffling.graph --O0

build-reshuffling:
	$(BUILD_CIRCUIT) --r1cs build/reshuffling.r1cs card_cancellation_v5/card_cancellation_v5.circom build/reshuffling.graph --O0


ARK_CWC_SETUP = ../ark-circom-witnesscalc/target/release/ark_cwc_setup.exe

.PRECIOUS: build/%.ark-pkey build/%.ark-vk build/%.ark-vk-json
build/%.ark-pkey build/%.ark-vk: build/%.r1cs
	$(ARK_CWC_SETUP) $< build/$*.ark-pkey build/$*.ark-vk build/$*.ark-vk-json