#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"


int max(int a, int b) {
    int result;
    if (a > result) {
        result = a;
    }
    if (b > result) {
        result = b;
    }
    return result;
}

int main() {
    if (max(0, 100) != 100) {
        printf("BUG 1\n");
    }
    if (max(10, 0) != 10) {
        printf("BUG 2\n");
    }
    return 0;
}