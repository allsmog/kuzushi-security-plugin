#include <string.h>
#include <stdio.h>

void parse(char *input) {
    char buf[16];
    strcpy(buf, input);
    printf("%s\n", buf);
}
