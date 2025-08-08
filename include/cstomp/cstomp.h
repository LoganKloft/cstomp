#ifndef CSTOMP_LIBRARY
#define CSTOMP_LIBRARY

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
#define CSTOMP_USERNAME_MAX_LENGTH 128
#define CSTOMP_PASSWORD_MAX_LENGTH 128

#define CSTOMP_FRAME_TERMINATOR "\0"
#define CSTOMP_HEADER_DELIMITER ":"
#define CSTOMP_LINE_TERMINATOR "\n"
#define CSTOMP_HEADER_BLOCK_TERMINATOR "\n\n"

#define CSTOMP_FRAME_BUFFER_MAX_SIZE 8192

typedef enum
{
    CSTOMP_OK = 0,
    CSTOMP_ERROR_NULL_POINTER = -1,
    CSTOMP_ERROR_BUFFER_OVERFLOW = -2,
    CSTOMP_ERROR_MEMORY_ALLOCATION = -3,
    CSTOMP_ERROR_NETWORK = -4,
    CSTOMP_ERROR_INVALID_FRAME = -5
} cstomp_error_t;

typedef struct
{
    char buffer[CSTOMP_FRAME_BUFFER_MAX_SIZE];
    size_t frame_size;
} cstomp_frame_t;

typedef struct
{
    uv_tcp_t socket;
    char host[CSTOMP_HOST_MAX_LENGTH];
    char version[CSTOMP_CONNECTION_VERSION_MAX_LENGTH];
    char username[CSTOMP_USERNAME_MAX_LENGTH];
    char password[CSTOMP_PASSWORD_MAX_LENGTH];
    uint16_t port;
    struct sockaddr_in destination;
    uv_loop_t *loop;
    uv_connect_t *connect;

    void (*on_connect)(void *ctx);
    void *on_connect_ctx;
    void (*on_read)(void *ctx, char *buffer, size_t nread);
    void *on_read_ctx;
    void (*on_write)(void *ctx, char *buffer, size_t nwrote);
    void *on_write_ctx;
} cstomp_connection_t;

// context passed to cstomp_on_write
typedef struct
{
    cstomp_frame_t *frame;
    cstomp_connection_t *connection;
} cstomp_write_t;

static inline int cstomp_set_connect_callback(cstomp_connection_t *connection, void *ctx, void (*on_connect)(void *ctx))
{
    if (!connection)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    // if specify ctx, must also specify an on_connect method to pass ctx to
    if (ctx && !on_connect)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    connection->on_connect = on_connect;
    connection->on_connect_ctx = ctx;

    return CSTOMP_OK;
}

static inline int cstomp_set_read_callback(cstomp_connection_t *connection, void *ctx, void (*on_read)(void *ctx, char *buffer, size_t nread))
{
    if (!connection)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    // if specify ctx, must also specify an on_read method to pass ctx to
    if (ctx && !on_read)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    connection->on_read = on_read;
    connection->on_read_ctx = ctx;

    return CSTOMP_OK;
}

static inline int cstomp_set_write_callback(cstomp_connection_t *connection, void *ctx, void (*on_write)(void *ctx, char *buffer, size_t nwrote))
{
    if (!connection)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    // if specify ctx, must also specify an on_write method to pass ctx to
    if (ctx && !on_write)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    connection->on_write = on_write;
    connection->on_write_ctx = ctx;

    return CSTOMP_OK;
}

void cstomp_alloc_callback(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)calloc(1, suggested_size);

    if (!buf->base)
    {
        buf->len = 0;
        fprintf(stderr, "Memory allocation failed in alloc callback\n");
    }
    else
    {
        buf->len = (unsigned long)suggested_size;
    }
}

static inline int cstomp_get_body(cstomp_frame_t *frame, char **body, size_t *body_size)
{
    if (!frame || !body || !body_size)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    *body = NULL;
    *body_size = 0;

    // Look for the header block terminator "\n\n"
    size_t terminator_len = strlen(CSTOMP_HEADER_BLOCK_TERMINATOR);

    char *body_start = NULL;
    for (size_t i = 0; i <= frame->frame_size - terminator_len; i++)
    {
        if (memcmp(frame->buffer + i, CSTOMP_HEADER_BLOCK_TERMINATOR, terminator_len) == 0)
        {
            body_start = frame->buffer + i + terminator_len;
            break;
        }
    }

    if (!body_start)
    {
        return CSTOMP_ERROR_INVALID_FRAME;
    }

    // Find the null terminator that ends the STOMP frame
    char *null_terminator = memchr(body_start, '\0', frame->buffer + frame->frame_size - body_start);
    if (!null_terminator)
    {
        return CSTOMP_ERROR_INVALID_FRAME;
    }

    *body_size = null_terminator - body_start;
    *body = body_start;

    return CSTOMP_OK;
}

void cstomp_on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    if (!client)
    {
        goto cstomp_on_read_cleanup;
    }

    if (nread < 0 && nread != UV_EOF)
    {
        fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
    }

    uv_handle_t *handle = (uv_handle_t *)client;
    if (!handle->data)
    {
        goto cstomp_on_read_cleanup;
    }

    cstomp_connection_t *connection = (cstomp_connection_t *)handle->data;

    if (buf && buf->base)
    {
        if (connection->on_connect && strncmp(buf->base, CSTOMP_COMMAND_CONNECTED, strlen(CSTOMP_COMMAND_CONNECTED)) == 0)
        {
            connection->on_connect(connection->on_connect_ctx);
        }

        if (connection->on_read)
        {
            connection->on_read(connection->on_read_ctx, buf->base, nread);
        }
    }

cstomp_on_read_cleanup:
    if (buf && buf->base)
    {
        free(buf->base);
    }
}

void cstomp_on_write(uv_write_t *req, int status)
{
    if (!req)
    {
        return;
    }

    if (status)
    {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }

    if (!req->data)
    {
        goto cstomp_on_write_cleanup;
    }
    cstomp_write_t *write_ctx = (cstomp_write_t *)req->data;

    if (!write_ctx->connection)
    {
        goto cstomp_on_write_cleanup;
    }
    cstomp_connection_t *connection = write_ctx->connection;

    if (!write_ctx->frame)
    {
        goto cstomp_on_write_cleanup;
    }

    char *buffer = 0;
    size_t nwrote = 0;
    if (!cstomp_get_body(write_ctx->frame, &buffer, &nwrote))
    {
        goto cstomp_on_write_cleanup;
    }

    if (connection->on_write)
    {
        connection->on_write(connection->on_write_ctx, buffer, nwrote);
    }

cstomp_on_write_cleanup:
    free(write_ctx->frame);
    free(write_ctx);
    free(req);
}

static inline cstomp_connection_t *cstomp_connection()
{
    cstomp_connection_t *connection = (cstomp_connection_t *)calloc(1, sizeof(cstomp_connection_t));
    if (!connection)
    {
        return NULL;
    }

    connection->connect = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));
    if (!connection->connect)
    {
        free(connection);
        return NULL;
    }

    connection->loop = (uv_loop_t *)calloc(1, sizeof(uv_loop_t));
    if (!connection->loop)
    {
        free(connection->connect);
        free(connection);
        return NULL;
    }

    int ret = uv_loop_init(connection->loop);
    if (ret != 0)
    {
        free(connection->loop);
        free(connection->connect);
        free(connection);
        return NULL;
    }

    ret = uv_tcp_init(connection->loop, &connection->socket);
    if (ret != 0)
    {
        free(connection->loop);
        free(connection->connect);
        free(connection);
        return NULL;
    }

    strcpy_s(connection->version, CSTOMP_CONNECTION_VERSION_MAX_LENGTH, CSTOMP_CONNECTION_VERSION);

    return connection;
}

static inline int cstomp_add_command(cstomp_frame_t *frame, const char *command)
{
    if (!frame || !command)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    size_t command_len = strlen(command);
    size_t required_space = command_len + 2; // +2 for \n and \0

    if (frame->frame_size + required_space >= CSTOMP_FRAME_BUFFER_MAX_SIZE)
    {
        return CSTOMP_ERROR_BUFFER_OVERFLOW;
    }

    char *command_start = frame->buffer;

    strcpy_s(command_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (command_start - frame->buffer), command);
    command_start += strlen(command);
    strcpy_s(command_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (command_start - frame->buffer), CSTOMP_LINE_TERMINATOR);
    command_start += strlen(CSTOMP_LINE_TERMINATOR);
    strcpy_s(command_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (command_start - frame->buffer), CSTOMP_FRAME_TERMINATOR);
    command_start += 1;
    frame->frame_size = command_start - frame->buffer;

    return CSTOMP_OK;
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
    if (!frame || !key || !value)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    if (strlen(key) == 0 || strlen(value) == 0)
    {
        return CSTOMP_ERROR_INVALID_FRAME;
    }

    char *header_start = frame->buffer + frame->frame_size - 1;
    int header_exists = 0;
    if (strncmp(header_start - strlen(CSTOMP_HEADER_BLOCK_TERMINATOR), CSTOMP_HEADER_BLOCK_TERMINATOR, strlen(CSTOMP_HEADER_BLOCK_TERMINATOR)) == 0)
    {
        header_exists = 1;
    }

    if (header_exists)
    {
        header_start -= strlen(CSTOMP_LINE_TERMINATOR);
    }

    size_t space_needed = strlen(key) + strlen(CSTOMP_HEADER_DELIMITER) + strlen(value) + strlen(CSTOMP_HEADER_BLOCK_TERMINATOR) + 1;
    size_t space_used = header_start - frame->buffer;
    if (space_used + space_needed > CSTOMP_FRAME_BUFFER_MAX_SIZE)
    {
        return CSTOMP_ERROR_BUFFER_OVERFLOW;
    }

    strcpy_s(header_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (header_start - frame->buffer), key);
    header_start += strlen(key);
    strcpy_s(header_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (header_start - frame->buffer), CSTOMP_HEADER_DELIMITER);
    header_start += strlen(CSTOMP_HEADER_DELIMITER);
    strcpy_s(header_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (header_start - frame->buffer), value);
    header_start += strlen(value);
    strcpy_s(header_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (header_start - frame->buffer), CSTOMP_HEADER_BLOCK_TERMINATOR);
    header_start += strlen(CSTOMP_HEADER_BLOCK_TERMINATOR);
    strcpy_s(header_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (header_start - frame->buffer), CSTOMP_FRAME_TERMINATOR);
    header_start += 1;
    frame->frame_size = header_start - frame->buffer;

    return CSTOMP_OK;
}

static inline int cstomp_add_body(cstomp_frame_t *frame, const char *body, size_t body_size)
{
    if (!frame || !body)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    if (frame->frame_size + body_size >= CSTOMP_FRAME_BUFFER_MAX_SIZE)
    {
        return CSTOMP_ERROR_BUFFER_OVERFLOW;
    }

    char *body_start = frame->buffer + frame->frame_size - 1;
    memcpy(body_start, body, body_size);
    body_start += body_size;
    strcpy_s(body_start, CSTOMP_FRAME_BUFFER_MAX_SIZE - (body_start - frame->buffer), CSTOMP_FRAME_TERMINATOR);
    body_start += 1;
    frame->frame_size = body_start - frame->buffer;
    return CSTOMP_OK;
}

static inline int cstomp_send_frame(cstomp_connection_t *connection, cstomp_frame_t *frame)
{
    if (!connection || !frame)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    if (frame->frame_size == 0 || frame->frame_size > CSTOMP_FRAME_BUFFER_MAX_SIZE)
    {
        return CSTOMP_ERROR_INVALID_FRAME;
    }

    if (!uv_is_writable((uv_stream_t *)&connection->socket))
    {
        return CSTOMP_ERROR_NETWORK;
    }

    cstomp_write_t *write_ctx = (cstomp_write_t *)calloc(sizeof(cstomp_write_t), 1);
    if (!write_ctx)
    {
        return CSTOMP_ERROR_MEMORY_ALLOCATION;
    }
    write_ctx->frame = frame;
    write_ctx->connection = connection;

    uv_write_t *req = (uv_write_t *)calloc(sizeof(uv_write_t), 1);
    if (!req)
    {
        free(write_ctx);
        return CSTOMP_ERROR_MEMORY_ALLOCATION;
    }
    req->data = write_ctx;
    uv_buf_t buf = uv_buf_init(write_ctx->frame->buffer, (unsigned int)write_ctx->frame->frame_size);
    if (!buf.base || buf.len == 0)
    {
        free(write_ctx);
        free(req);
        return CSTOMP_ERROR_INVALID_FRAME;
    }

    int result = uv_write(req, (uv_stream_t *)&connection->socket, &buf, 1, cstomp_on_write);
    if (result)
    {
        // uv_write failed immediately - cleanup and return error
        free(write_ctx);
        free(req);
        return CSTOMP_ERROR_NETWORK;
    }

    return CSTOMP_OK;
}

void cstomp_on_connect(uv_connect_t *req, int status)
{
    if (!req || status < 0)
    {
        fprintf(stderr, "Connection error %s\n", uv_strerror(status));
        return;
    }

    cstomp_connection_t *connection = (cstomp_connection_t *)req->handle->data;
    int read_start_result = uv_read_start((uv_stream_t *)&connection->socket, cstomp_alloc_callback, cstomp_on_read);
    if (read_start_result)
    {
        fprintf(stderr, "Failed to start reading: %s\n", uv_err_name(read_start_result));
        return;
    }

    cstomp_frame_t *frame = (cstomp_frame_t *)calloc(sizeof(cstomp_frame_t), 1);
    cstomp_add_command(frame, CSTOMP_COMMAND_CONNECT);
    cstomp_add_header(frame, "accept-version", connection->version);
    cstomp_add_header(frame, "host", connection->host);
    cstomp_add_header(frame, "login", connection->username);
    cstomp_add_header(frame, "passcode", connection->password);
    cstomp_send_frame(connection, frame);
}

static inline int cstomp_connection_free(cstomp_connection_t *connection)
{
    if (!connection)
    {
        return CSTOMP_OK;
    }

    uv_loop_close(connection->loop);
    free(connection->loop);
    free(connection->connect);
    free(connection);
    return CSTOMP_OK;
}

static inline int cstomp_connect(cstomp_connection_t *connection, const char *destination_ip, const uint16_t destination_port, const char *username, const char *password)
{
    if (!connection || !destination_ip)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    if ((username && !password) || (!username && password))
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    strcpy_s(connection->host, CSTOMP_HOST_MAX_LENGTH, destination_ip);
    strcpy_s(connection->username, CSTOMP_USERNAME_MAX_LENGTH, username);
    strcpy_s(connection->password, CSTOMP_PASSWORD_MAX_LENGTH, password);
    connection->port = destination_port;

    uv_ip4_addr(connection->host, connection->port, &connection->destination);
    connection->socket.data = connection;

    uv_tcp_connect(connection->connect, &connection->socket, (const struct sockaddr *)&connection->destination, cstomp_on_connect);

    uv_run(connection->loop, UV_RUN_DEFAULT);
    return CSTOMP_OK;
}

static inline int cstomp_send(cstomp_connection_t *connection, const char *destination, const char *message, size_t message_size)
{
    if (!connection || !destination || !message)
    {
        return CSTOMP_ERROR_NULL_POINTER;
    }

    char message_size_string[CSTOMP_FRAME_BUFFER_MAX_SIZE];
    snprintf(message_size_string, CSTOMP_FRAME_BUFFER_MAX_SIZE, "%zu", message_size);

    cstomp_frame_t *frame = (cstomp_frame_t *)calloc(sizeof(cstomp_frame_t), 1);
    cstomp_add_command(frame, CSTOMP_COMMAND_SEND);
    cstomp_add_header(frame, "destination", destination);
    cstomp_add_header(frame, "content-length", message_size_string);
    cstomp_add_body(frame, message, message_size);
    cstomp_send_frame(connection, frame);
    return CSTOMP_OK;
}

#endif // CSTOMP_HEADER_ONLY_LIBRARY