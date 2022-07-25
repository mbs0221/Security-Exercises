#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    char *s = NULL;
    s = getenv(argv[1]);
    printf("&%s = %p = %s\n", argv[1], s, s); /* display comspec parameter */
    return 0;
}