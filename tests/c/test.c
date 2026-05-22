#include <stdio.h>
#include <string.h>

int main(void) {
    char input[128];
    if (!fgets(input, sizeof(input), stdin)) return 1;

    printf(input);  
    return 0;
}