#include <stdio.h>

int main(int argc, char *argv[])
{
	union w {
		int a;
		char b;
	} c;

	c.a = 1;
	
	printf("This cpu is %s\n", c.b == 1 ? "little-endian" : "big-endian");
}
