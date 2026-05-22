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

EXPORT_FLAGS_insecureArgs=-Wl,--export=callInsecureArgs
EXPORT_FLAGS_mem_leak=-Wl,--export=foo
EXPORT_FLAGS_poc=-Wl,--export=write_to_web
EXPORT_FLAGS_printf=-Wl,--export=logMessage -Wl,--export=logMessageVuln
EXPORT_FLAGS_save_validation=-Wl,--export=safe_printf -Wl,--export=vuln_printf -Wl,--export=safe_fprintf -Wl,--export=vuln_fprintf
EXPORT_FLAGS_sink=-Wl,--export=foo
EXPORT_FLAGS_test=-Wl,--export=main
EXPORT_FLAGS_trunc=-Wl,--export=foo
EXPORT_FLAGS_uaf=-Wl,--export=foo
EXPORT_FLAGS_unreach=-Wl,--export=unreach
EXPORT_FLAGS_dangorousFunction=-Wl,--export=main
EXTRA_CFLAGS_uaf=-O1

.PHONY: all clean

all: $(WASM_FILES)

%.wasm: %.c
	$(EMCC) $< -o $@ $(CFLAGS) $(EXTRA_CFLAGS_$*) $(EXPORT_FLAGS_$*)

clean:
	rm -f $(WASM_FILES)
