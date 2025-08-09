/**
 * @file cstomp.h
 * @brief STOMP (Simple Text Oriented Messaging Protocol) client library
 * @author Logan Kloft
 * @version 1.0
 * @date 2025
 *
 * A lightweight C library for connecting to and communicating with STOMP message brokers.
 * This library provides asynchronous I/O operations using libuv and supports STOMP protocol
 * version 1.1 features including connect and send.
 */
#ifndef CSTOMP_LIBRARY
#define CSTOMP_LIBRARY

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <utf8proc.h>
#include <uv.h>

/** @defgroup stomp_commands STOMP Protocol Commands
 *  @brief Standard STOMP protocol command strings
 *  @{
 */
#define CSTOMP_COMMAND_CONNECT "CONNECT"         /**< Client connection request command */
#define CSTOMP_COMMAND_CONNECTED "CONNECTED"     /**< Server connection acknowledgment */
#define CSTOMP_COMMAND_ERROR "ERROR"             /**< Server error response */
#define CSTOMP_COMMAND_SEND "SEND"               /**< Send message to destination */
#define CSTOMP_COMMAND_SUBSCRIBE "SUBSCRIBE"     /**< Subscribe to destination */
#define CSTOMP_COMMAND_UNSUBSCRIBE "UNSUBSCRIBE" /**< Unsubscribe from destination */
#define CSTOMP_COMMAND_BEGIN "BEGIN"             /**< Begin transaction */
#define CSTOMP_COMMAND_COMMIT "COMMIT"           /**< Commit transaction */
#define CSTOMP_COMMAND_ABORT "ABORT"             /**< Abort transaction */
#define CSTOMP_COMMAND_ACK "ACK"                 /**< Acknowledge message */
#define CSTOMP_COMMAND_NACK "NACK"               /**< Negative acknowledge message */
#define CSTOMP_COMMAND_DISCONNECT "DISCONNECT"   /**< Disconnect from server */
/** @} */

/** @defgroup config_limits Configuration Limits and Constants
 *  @brief Maximum sizes and protocol constants
 *  @{
 */
#define CSTOMP_HOST_MAX_LENGTH 256               /**< Maximum hostname length */
#define CSTOMP_CONNECTION_VERSION "1.1"          /**< Supported STOMP protocol version */
#define CSTOMP_CONNECTION_VERSION_MAX_LENGTH 128 /**< Maximum version string length */
#define CSTOMP_USERNAME_MAX_LENGTH 128           /**< Maximum username length */
#define CSTOMP_PASSWORD_MAX_LENGTH 128           /**< Maximum password length */
/** @} */

/** @defgroup protocol_delimiters STOMP Protocol Delimiters
 *  @brief Special characters and strings used in STOMP protocol
 *  @{
 */
#define CSTOMP_FRAME_TERMINATOR "\0"          /**< Null byte frame terminator */
#define CSTOMP_HEADER_DELIMITER ":"           /**< Header key-value delimiter */
#define CSTOMP_LINE_TERMINATOR "\n"           /**< Line terminator */
#define CSTOMP_HEADER_BLOCK_TERMINATOR "\n\n" /**< Header block terminator */
/** @} */

/** @defgroup buffer_limits Buffer Size Limits
 *  @brief Maximum buffer sizes for frames and data
 *  @{
 */
#define CSTOMP_FRAME_BUFFER_MAX_SIZE 8192 /**< Maximum STOMP frame size in bytes */
/** @} */

/**
 * @brief Error codes returned by CSTOMP functions
 *
 * All CSTOMP functions return one of these error codes to indicate
 * success or the type of failure that occurred.
 */
typedef enum
{
    CSTOMP_OK = 0,                       /**< Operation completed successfully */
    CSTOMP_ERROR_NULL_POINTER = -1,      /**< Null pointer passed as argument */
    CSTOMP_ERROR_BUFFER_OVERFLOW = -2,   /**< Buffer would overflow */
    CSTOMP_ERROR_MEMORY_ALLOCATION = -3, /**< Memory allocation failed */
    CSTOMP_ERROR_NETWORK = -4,           /**< Network operation failed */
    CSTOMP_ERROR_INVALID_FRAME = -5      /**< Invalid STOMP frame format */
} cstomp_error_t;

/**
 * @brief STOMP protocol frame structure
 *
 * Represents a complete STOMP frame including command, headers, and body.
 * The frame is stored as a contiguous buffer with proper STOMP formatting.
 */
typedef struct
{
    char buffer[CSTOMP_FRAME_BUFFER_MAX_SIZE]; /**< Frame data buffer */
    size_t frame_size;                         /**< Current size of frame data */
} cstomp_frame_t;

/**
 * @brief STOMP connection context
 *
 * Contains all state and configuration needed for a STOMP connection,
 * including network socket, authentication credentials, and callback handlers.
 */
typedef struct
{
    uv_tcp_t socket;                                    /**< TCP socket handle */
    char host[CSTOMP_HOST_MAX_LENGTH];                  /**< Server hostname or IP */
    char version[CSTOMP_CONNECTION_VERSION_MAX_LENGTH]; /**< STOMP protocol version */
    char username[CSTOMP_USERNAME_MAX_LENGTH];          /**< Authentication username */
    char password[CSTOMP_PASSWORD_MAX_LENGTH];          /**< Authentication password */
    uint16_t port;                                      /**< Server port number */
    struct sockaddr_in destination;                     /**< Server socket address */
    uv_loop_t *loop;                                    /**< Event loop handle */
    uv_connect_t *connect;                              /**< Connection request handle */

    void (*on_connect)(void *ctx);                            /**< Connection established callback */
    void *on_connect_ctx;                                     /**< Context for connection callback */
    void (*on_read)(void *ctx, char *buffer, size_t nread);   /**< Data received callback */
    void *on_read_ctx;                                        /**< Context for read callback */
    void (*on_write)(void *ctx, char *buffer, size_t nwrote); /**< Data sent callback */
    void *on_write_ctx;                                       /**< Context for write callback */
} cstomp_connection_t;

/**
 * @brief Context passed to write completion callback
 *
 * Contains references to the frame that was sent and the connection
 * it was sent on, used by the write completion handler.
 */
typedef struct
{
    cstomp_frame_t *frame;           /**< Frame that was sent */
    cstomp_connection_t *connection; /**< Connection frame was sent on */
} cstomp_write_t;

/**
 * @brief Set connection established callback
 *
 * Registers a callback function to be called when the STOMP connection
 * is successfully established and the server sends a CONNECTED frame.
 *
 * @param connection Pointer to connection structure
 * @param ctx User context to pass to callback (can be NULL)
 * @param on_connect Callback function to call on connection (required if ctx is not NULL)
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note If ctx is provided, on_connect must also be provided
 */
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

/**
 * @brief Set data received callback
 *
 * Registers a callback function to be called whenever data is received
 * from the STOMP server on this connection.
 *
 * @param connection Pointer to connection structure
 * @param ctx User context to pass to callback (can be NULL)
 * @param on_read Callback function to call when data is received (required if ctx is not NULL)
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note If ctx is provided, on_read must also be provided
 */
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

/**
 * @brief Set data sent callback
 *
 * Registers a callback function to be called when data has been successfully
 * sent to the STOMP server.
 *
 * @param connection Pointer to connection structure
 * @param ctx User context to pass to callback (can be NULL)
 * @param on_write Callback function to call when data is sent (required if ctx is not NULL)
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note If ctx is provided, on_write must also be provided
 */
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

/**
 * @brief Memory allocation callback for libuv
 *
 * This function is called by libuv when it needs to allocate a buffer
 * for incoming data. It allocates the requested amount of memory and
 * initializes it to zero.
 *
 * @param handle The handle that needs the buffer
 * @param suggested_size Suggested buffer size from libuv
 * @param buf Output buffer structure to fill
 *
 * @note This function prints an error message to stderr if allocation fails
 */
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

/**
 * @brief Extract body from STOMP frame
 *
 * Parses a STOMP frame to locate and extract the message body portion.
 * The body is the content that appears after the header block terminator
 * and before the frame terminator.
 *
 * @param frame Pointer to frame structure to parse
 * @param body Output pointer to body data (will point into frame buffer)
 * @param body_size Output size of body data in bytes
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note The returned body pointer points directly into the frame buffer
 */
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

/**
 * @brief Callback for data received from server
 *
 * This function is called by libuv when data is received from the STOMP server.
 * It handles connection acknowledgment detection and forwards data to user callbacks.
 *
 * @param client The stream that received data
 * @param nread Number of bytes read (negative on error)
 * @param buf Buffer containing received data
 *
 * @note This function automatically detects CONNECTED frames and triggers connection callbacks
 * @note Buffer memory is automatically freed after processing
 */
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

/**
 * @brief Callback for data sent to server
 *
 * This function is called by libuv when a write operation completes.
 * It extracts the message body and forwards it to user write callbacks,
 * then cleans up allocated resources.
 *
 * @param req The write request that completed
 * @param status Write operation status (0 on success, negative on error)
 *
 * @note This function automatically frees frame and request memory
 * @note Error messages are printed to stderr on write failures
 */
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

/**
 * @brief Create a new STOMP connection
 *
 * Allocates and initializes a new STOMP connection structure with default values.
 * Sets up the libuv event loop and TCP socket for network operations.
 *
 * @return Pointer to new connection structure, or NULL on allocation failure
 *
 * @note The returned connection must be freed with cstomp_connection_free()
 * @note The connection is not yet connected to a server
 */
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

/**
 * @brief Add command to STOMP frame
 *
 * Adds a STOMP protocol command to the beginning of a frame buffer.
 * This must be the first operation when building a new frame.
 *
 * @param frame Pointer to frame structure to modify
 * @param command STOMP command string (e.g., "CONNECT", "SEND")
 * @return CSTOMP_OK on success, error code on failure
 *
 * @pre Frame buffer must be empty or this will overwrite existing content
 * @post Frame will contain command followed by line terminator and frame terminator
 */
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

/**
 * @brief Add header to STOMP frame
 *
 * Adds a key-value header pair to a STOMP frame. Headers must be added
 * after the command and before the body.
 *
 * @param frame Pointer to frame structure to modify
 * @param key Header key name (must not be empty)
 * @param value Header value (must not be empty)
 * @return CSTOMP_OK on success, error code on failure
 *
 * @pre A command must already be present in the frame
 * @pre Frame must have an empty body (will be preserved)
 * @post New header will be added while preserving existing headers and command
 * @post Empty body will remain at the end of the frame
 */
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

/**
 * @brief Add body to STOMP frame
 *
 * Adds message body content to a STOMP frame. This should be the final
 * step when building a frame, after command and headers are added.
 *
 * @param frame Pointer to frame structure to modify
 * @param body Pointer to body data
 * @param body_size Size of body data in bytes
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note Body data can contain binary content. If body data contains null bytes, then a content-length header should be added before the body.
 * @note The frame terminator will be added after the body content
 */
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

/**
 * @brief Send STOMP frame to server
 *
 * Transmits a complete STOMP frame to the connected server. The frame
 * must be properly formatted with command, headers, and body.
 *
 * @param connection Pointer to active connection
 * @param frame Pointer to frame to send (will be freed after sending)
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note The frame pointer will be freed automatically after sending
 * @note Connection must be established before calling this function
 * @note This function is asynchronous; use write callbacks to detect completion
 */
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

/**
 * @brief Callback for connection establishment
 *
 * This function is called by libuv when the TCP connection to the STOMP
 * server is established. It starts reading from the socket and sends
 * the initial CONNECT frame with authentication credentials.
 *
 * @param req The connection request that completed
 * @param status Connection status (0 on success, negative on error)
 *
 * @note This function automatically sends a CONNECT frame with stored credentials
 * @note Error messages are printed to stderr on connection failures
 */
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

/**
 * @brief Free STOMP connection resources
 *
 * Properly cleans up and frees all resources associated with a STOMP connection,
 * including the event loop, socket handles, and connection structure itself.
 *
 * @param connection Pointer to connection to free (can be NULL)
 * @return CSTOMP_OK always
 *
 * @note This function is safe to call with NULL pointer
 * @note Connection should be disconnected before calling this function
 */
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

/**
 * @brief Connect to STOMP server
 *
 * Establishes a TCP connection to the specified STOMP server and begins
 * the STOMP protocol handshake. This function starts the event loop and
 * will block until the connection is closed.
 *
 * @param connection Pointer to initialized connection structure
 * @param destination_ip Server IP address or hostname
 * @param destination_port Server port number
 * @param username Authentication username (can be NULL for anonymous)
 * @param password Authentication password (can be NULL for anonymous)
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note Both username and password must be provided together or both must be NULL
 * @note This function blocks until the connection is closed
 * @note Connection callbacks will be triggered during execution
 */
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

/**
 * @brief Send message to destination
 *
 * Sends a message to the specified destination on the STOMP server.
 * The message will be delivered to any subscribers of that destination.
 *
 * @param connection Pointer to active connection
 * @param destination Destination name (e.g., "/queue/test", "/topic/news")
 * @param message Pointer to message content
 * @param message_size Size of message content in bytes
 * @return CSTOMP_OK on success, error code on failure
 *
 * @note Connection must be established before sending messages
 * @note Message content can include binary data and null bytes
 * @note Content-length header will be automatically added
 */
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