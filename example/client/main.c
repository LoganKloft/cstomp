#include <stdint.h>

#include "cstomp/cstomp.h"

int main(int argc, char **argv)
{

    const char *host = "127.0.0.1";
    uint16_t port = 61613;

    const char *username = "admin";
    const char *password = "admin";

    const char *topic = "/topic/example";

    cstomp_connection_t *connection = cstomp_connection();
    cstomp_connect(connection, host, port, username, password);

    cstomp_connection_free(connection);
    return 0;
}