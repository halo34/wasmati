#include <stdio.h>
#include <emscripten.h>

// Safe: fixed format string, user-controlled data only as an argument.
void EMSCRIPTEN_KEEPALIVE safe_printf(char* message) {
    printf("%s", message);
}

// Vulnerable: user input is used directly as format string.
void EMSCRIPTEN_KEEPALIVE vuln_printf(char* message) {
    printf(message);
}

// Safe: fixed format string in fprintf.
void EMSCRIPTEN_KEEPALIVE safe_fprintf(char* message) {
    fprintf(stderr, "%s", message);
}

// Vulnerable: user input is used directly as format string in fprintf.
void EMSCRIPTEN_KEEPALIVE vuln_fprintf(char* message) {
    fprintf(stderr, message);
}
