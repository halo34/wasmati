#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    
    fgets(buffer, 100, stdin);
    return 0;
}
