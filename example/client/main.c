#include <stdint.h>
#include <stdio.h>

#include "cstomp/cstomp.h"

// Global connection for cleanup
cstomp_connection_t *g_connection = NULL;

// Connection callback - called when connected to broker
void on_connect(void *ctx)
{
    printf("Connected to STOMP broker!\n");

    // Now we can send a test message
    const char *topic = "/topic/example";
    const char *message = "Hello from cstomp client!";

    printf("Sending message to %s: %s\n", topic, message);
    cstomp_send(g_connection, topic, message, strlen(message));
}

// Read callback - called when we receive data from broker
void on_read(void *ctx, char *buffer, size_t nread)
{
    if (nread > 0)
    {
        printf("Received %zu bytes: ", nread);
        // Print the received frame (should be CONNECTED frame)
        for (size_t i = 0; i < nread; i++)
        {
            if (buffer[i] == '\0')
            {
                printf("[NULL]");
            }
            else if (buffer[i] == '\n')
            {
                printf("[LF]");
            }
            else if (buffer[i] == '\r')
            {
                printf("[CR]");
            }
            else
            {
                printf("%c", buffer[i]);
            }
        }
        printf("\n");
    }
    else if (nread == 0)
    {
        printf("Connection closed by broker\n");
    }
    else
    {
        printf("Read error\n");
    }
}

// Write callback - called when our message has been sent
void on_write(void *ctx)
{
    printf("Message sent successfully!\n");
}

int main(int argc, char **argv)
{
    char host[] = "127.0.0.1"; // Remove const for compatibility
    uint16_t port = 61613;

    char username[] = "admin"; // Remove const for compatibility
    char password[] = "admin"; // Remove const for compatibility

    printf("Creating STOMP connection to %s:%d\n", host, port);

    cstomp_connection_t *connection = cstomp_connection();
    if (!connection)
    {
        fprintf(stderr, "Failed to create connection\n");
        return 1;
    }

    g_connection = connection; // Store globally for callbacks

    // Set up callbacks BEFORE connecting
    cstomp_set_connect_callback(connection, NULL, on_connect);
    cstomp_set_read_callback(connection, NULL, on_read);
    cstomp_set_write_callback(connection, NULL, on_write);

    printf("Connecting...\n");

    // Connect and run event loop (this blocks until connection closes)
    int result = cstomp_connect(connection, host, port, username, password);

    printf("Event loop finished with result: %d\n", result);

    // Clean up
    cstomp_connection_free(connection);
    return 0;
}