#include <emscripten.h>
#include <stdio.h>
#include <string.h>

static char g_arr[20];

char* write_to_web(char* in) {
    strcpy(g_arr, in);
    printf("%s\n", g_arr);
    return "Done";
}
