#ifndef CSTOMP_LIBRARY
#define CSTOMP_LIBRARY

#include <string.h>
#include <stdlib.h>

#include <utf8proc.h>
#include <uv.h>

#define CSTOMP_COMMAND_CONNECT "CONNECT"
#define CSTOMP_COMMAND_CONNECTED "CONNECTED"
#define CSTOMP_COMMAND_ERROR "ERROR"
#define CSTOMP_COMMAND_SEND "SEND"
#define CSTOMP_COMMAND_SUBSCRIBE "SUBSCRIBE"
#define CSTOMP_COMMAND_UNSUBSCRIBE "UNSUBSCRIBE"
#define CSTOMP_COMMAND_BEGIN "BEGIN"
#define CSTOMP_COMMAND_COMMIT "COMMIT"
#define CSTOMP_COMMAND_ABORT "ABORT"
#define CSTOMP_COMMAND_ACK "ACK"
#define CSTOMP_COMMAND_NACK "NACK"
#define CSTOMP_COMMAND_DISCONNECT "DISCONNECT"

#define CSTOMP_HOST_MAX_LENGTH 256
#define CSTOMP_CONNECTION_VERSION "1.1"
#define CSTOMP_CONNECTION_VERSION_MAX_LENGTH 128

typedef enum
{
    kCStompCommandConnect,
    kCStompCommandConnected,
    kCStompCommandError,
    kCStompCommandSend,
    kCStompCommandSubscribe,
    kCStompCommandUsubscribe,
    kCStompCommandBegin,
    kCStompCommandCommit,
    kCStompCommandAbort,
    kCStompCommandAck,
    kCStompCommandNack,
    kCStompCommandDisconnect,
    kCStompCommandReceipt,
    kCStompCommandMessage
} CStompCommand;

typedef struct
{
    char buffer[8196];
    size_t frame_size;
} cstomp_frame_t;

typedef struct
{
    uv_tcp_t socket;
    char host[CSTOMP_HOST_MAX_LENGTH];
    char version[CSTOMP_CONNECTION_VERSION_MAX_LENGTH];
    uint16_t port;
    struct sockaddr_in destination;
    uv_loop_t *loop;
    uv_connect_t *connect;

    void (*on_connect)(void *ctx);
    void *on_connect_ctx;
    void (*on_read)(void *ctx, char *buffer, size_t nread);
    void *on_read_ctx;
    void (*on_write)(void *ctx);
    void *on_write_ctx;
} cstomp_connection_t;

// context passed to cstomp_on_write
typedef struct
{
    void *buffer;
    void *size;
    cstomp_connect_t *connection;
} cstomp_write_t;

void cstomp_set_connect_callback(cstomp_connection_t *connection, void *ctx, void (*on_connect)(void *ctx))
{
    if (connection == NULL)
    {
        return;
    }

    connection->on_connect = on_connect;
    connection->on_connect_ctx = ctx;
}

void cstomp_set_read_callback(cstomp_connection_t *connection, void *ctx, void (*on_read)(void *ctx, char *buffer, size_t nread))
{
    if (connection == NULL)
    {
        return;
    }

    connection->on_read = on_read;
    connection->on_read_ctx = ctx;
}

void cstomp_set_write_callback(cstomp_connection_t *connection, void *ctx, void (*on_write)(void *ctx))
{
    if (connection == NULL)
    {
        return;
    }

    connection->on_write = on_write;
    connection->on_write_ctx = ctx;
}

void cstomp_alloc_callback(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)calloc(suggested_size, 1);

    if (buf->base == NULL)
    {
        buf->len = 0;
    }
    else
    {
        buf->len = suggested_size;
    }
}

void cstomp_on_connect(uv_connect_t *req, int status)
{
    if (status < 0)
    {
        fprintf(stderr, "Connection error %d\n", uv_strerror(status));
        return;
    }

    cstomp_connection_t *connection = (cstomp_connection_t *)req->handle->data;
    connection->on_connect(connection->on_connect_ctx);

    uv_read_start((uv_stream_t *)&connection->socket, cstomp_alloc_callback, cstomp_on_read);

    cstomp_frame_t *frame = (cstomp_frame_t *)calloc(sizeof(cstomp_frame_t), 1);
    cstomp_add_command(frame, CSTOMP_COMMAND_CONNECT);
    cstomp_add_header(frame, "accept-version", connection->version);
    cstomp_add_header(frame, "host", connection->host);

    cstomp_send_frame(connection, frame);
}

void cstomp_on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    if (nread < 0 && nread != UV_EOF)
    {
        fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    }

    cstomp_connection_t *connection = (cstomp_connection_t *)client->handle->data;
    connection->on_read(connection->on_read_ctx, buf->base, nread);

    if (buf->base)
    {
        free(buf->base);
    }
}

void cstomp_on_write(uv_write_t *req, in status)
{
    if (status)
    {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }

    cstomp_write_t *write_ctx = (cstomp_write_t *)req->handle->data;
    cstomp_connection_t *connection = write_ctx->connection;
    connection->on_write(connection->on_write_ctx);

    free(write_ctx->buffer);
    free(write_ctx);
    free(req);
}

static inline cstomp_connection_t *cstomp_connection()
{
    cstomp_connection_t *connection = (cstomp_connection_t *)calloc(1, sizeof(cstomp_connection_t));
    if (connection == NULL)
    {
        return NULL;
    }

    connection->frame = (cstomp_frame_t *)calloc(1, sizeof(cstomp_frame_t));
    if (connection->frame == NULL)
    {
        free(connection);
        return NULL;
    }

    connection->connect = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));
    if (connection->connection == NULL)
    {
        free(connection);
        free(connection->frame);
        return NULL;
    }

    connection->loop = (uv_loop_t *)calloc(1, sizeof(uv_loop_t));
    if (connection->loop == NULL)
    {
        free(connection);
        free(connection->frame);
        free(conection->connect);
    }
    uv_loop_init(connection->loop);

    uv_tcp_init(connection->loop, &connection->socket);

    strcpy(connection->version, CSTOMP_CONNECTION_VERSION);

    return connection;
}

static inline int cstomp_connection_free(cstomp_connection_t *connection)
{
    uv_loop_close(connection->loop);
    free(connection->loop);
    free(connection->connect);
    free(connection->frame);
    free(connection);
    return 0;
}

static inline int cstomp_connect(cstomp_connection_t *connection, char *destination_ip, uint16_t destination_port)
{
    strcpy(connection->host, destination_ip);
    connection->port = destination_port;
    up_ip4_addr(connection->host, connection->port, &connection->destination);
    uv_tcp_connect(connection->connect, &connection->socket, (const struct sockaddr *)&connection->destination, cstomp_on_connect);
    uv_run(connection->loop, UV_RUN_DEFAULT);
}

static inline int cstomp_add_command(cstomp_frame_t *frame, const char *command)
{
    char *command_start = frame->buffer;
    char *command_terminator = "\\n";
    char *header_terminator = "\\n";

    if (strcmp(command, CSTOMP_COMMAND_CONNECT) == 0 || strcmp(command, CSTOMP_COMMAND_CONNECTED))
    { // CONNECT and CONNECTED frames don't escape newlines
        command_terminator = "\n";
        header_terminator = "\n";
    }

    strcpy(command_start, command);
    command_start += strlen(command);
    strcpy(command_start, command_terminator);
    command_start += strlen(command_terminator);
    strcpy(command_start, header_terminator);
    command_start += strlen(header_terminator);
    command_start[0] = '\0';
    command_start += 1;
    frame->frame_size = abs(command_start - frame->buffer);

    return 0;
}

// Precondition: a command must be present
// Precondition: 0 or more headers may be present
// Precondition: an empty body must be present
// Postcondition: original command remains unedited
// Postcondition: original headers remain unedited
// Postcondition: new header added
// Postcondition: empty body at end of frame
static inline int cstomp_add_header(cstomp_frame_t *frame, const char *key, const char *value)
{
    char *command_start = frame->buffer;
    char *key_value_delimiter = "\\c";
    char *header_terminator = "\\n\\n";
    char *header_block_terminator = "\\n";

    // if command is CONNECT or CONNECTED then we don't escape '\n' and ':'
    if (strncmp(command_start, CSTOMP_COMMAND_CONNECT, strlen(CSTOMP_COMMAND_CONNECT)) == 0 || strncmp(command_start, CSTOMP_COMMAND_CONNECTED, strlen(CSTOMP_COMMAND_CONNECTED)))
    {
        key_value_delimiter = ":";
        header_terminator = "\n\n";
        header_block_terminator = "\n";
    }

    char *header_start = frame->buffer + frame->frame_size - 1;
    int header_exists = 0;
    if (strncmp(header_start - strlen(header_terminator), header_terminator, strlen(header_terminator)) == 0)
    {
        header_exists = 1;
    }

    if (header_exists)
    {
        header_start -= strlen(header_block_terminator);
    }

    strcpy(header_start, key);
    header_start += strlen(key);
    strcpy(header_start, key_value_delimiter);
    header_start += strlen(key_value_delimiter);
    strcpy(header_start, value);
    header_start += strlen(value);
    strcpy(header_start, header_terminator);
    header_start += strlen(header_terminator);
    header_start[0] = '\0';
    header_start += 1;
    frame->frame_size = abs(header_start - frame->buffer);

    return 0;
}

static inline int cstomp_add_body(cstomp_frame_t *frame, const char *body, size_t body_size)
{
    char *body_start = frame->buffer + frame->frame_size - 1;
    memcpy(body_start, body, body_size);
    body_start += body_size;
    body_start[0] = '\0';
    body_start += 1;
    frame->frame_size = abs(body_start - frame->buffer);
    return 0;
}

static inline int cstomp_send_frame(cstomp_connection_t *connection, cstomp_frame_t *frame)
{
    cstomp_write_t *write_ctx = (cstomp_write_t *)calloc(sizeof(cstomp_write_t), 1);
    write_ctx->buffer = (void *)frame->buffer;
    write_ctx->size = frame->frame_size;

    uv_write_t *req = (uv_write_t *)calloc(sizeof(uv_write_t), 1);
    uv_buf_t buf = uv_buf_init(write_ctx->buffer, write_ctx->size);
    uv_write(req, (uv_stream_t *)&connection->socket, &buf, 1, cstomp_on_write);
}

static inline int cstomp_send_message(cstom_connection_t *connection, const char *message, size_t message_size)
{
}

#endif // CSTOMP_HEADER_ONLY_LIBRARY