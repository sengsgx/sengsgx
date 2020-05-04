#include <stdio.h>
#include <sys/time.h>

int main(int argc, char *argv[]) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("%ld\n", tv.tv_sec * 1000000 + tv.tv_usec);
    return 0;
}
