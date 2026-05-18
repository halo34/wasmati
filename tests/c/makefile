# wasmati/tests/c/makefile
EMCC=emcc
WASM_FILES=$(patsubst %.c,%.wasm,$(wildcard *.c))

CFLAGS=-O0 \
  -sERROR_ON_UNDEFINED_SYMBOLS=0 \
  -sSTANDALONE_WASM=1 \
  -Wl,--no-entry \
  -Wl,--export-all \
  -mno-reference-types \
  -mno-bulk-memory \
  -mno-sign-ext \
  -mno-nontrapping-fptoint
  # -sEXPORTED_FUNCTIONS='["_write_to_web"]'

.PHONY: all clean

all: $(WASM_FILES)

%.wasm: %.c
	$(EMCC) $< -o $@ $(CFLAGS)

clean:
	rm -f $(WASM_FILES)
