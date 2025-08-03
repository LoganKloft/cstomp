#include <stdio.h>
#include <uv.h>

int main()
{
    printf("Hello World\n");
    fflush(stdout);

    uv_loop_t loop;
    int result = uv_loop_init(&loop);
    printf("libuv init result: %d\n", result);
    fflush(stdout);

    uv_loop_close(&loop);
    printf("Done\n");
    fflush(stdout);
    return 0;
}