# wasmati/tests/c/makefile
EMCC=emcc
WASM_FILES=$(patsubst %.c,%.wasm,$(wildcard *.c))

CFLAGS=-O0 \
  -g \
  -fno-inline \
  -sERROR_ON_UNDEFINED_SYMBOLS=0 \
  -sSTANDALONE_WASM=1 \
  -Wl,--no-entry \
  -mno-reference-types \
  -mno-bulk-memory \
  -mno-sign-ext \
  -mno-nontrapping-fptoint
  # -sEXPORTED_FUNCTIONS='["_write_to_web"]'

# Export only the test entrypoints we care about for each file.
EXPORT_FLAGS_insecureArgs=-Wl,--export=callInsecureArgs
EXPORT_FLAGS_mem_leak=-Wl,--export=foo
EXPORT_FLAGS_poc=-Wl,--export=write_to_web
EXPORT_FLAGS_printf=-Wl,--export=logMessage -Wl,--export=logMessageVuln
EXPORT_FLAGS_sink=-Wl,--export=foo
EXPORT_FLAGS_trunc=-Wl,--export=foo
EXPORT_FLAGS_uaf=-Wl,--export=foo
EXPORT_FLAGS_unreach=-Wl,--export=unreach

# Per-test compile overrides.
EXTRA_CFLAGS_uaf=-O1

.PHONY: all clean

all: $(WASM_FILES)

%.wasm: %.c
	$(EMCC) $< -o $@ $(CFLAGS) $(EXTRA_CFLAGS_$*) $(EXPORT_FLAGS_$*)

clean:
	rm -f $(WASM_FILES)
