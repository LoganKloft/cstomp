#ifndef CSTOMP_HEADER_ONLY_LIBRARY
#define CSTOMP_HEADER_ONLY_LIBRARY

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
    uv_tcp_t *socket;
    uv_connect_t *connect;
    cstomp_frame_t *frame;
} cstomp_connection_t;

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

    return connection;
}

static inline int cstomp_connection_free(cstomp_connection_t *connection)
{
    free(connection->frame);
    free(connection);
    return 0;
}

static inline int cstomp_connect(cstomp_connection_t *connection)
{
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
}

static inline int cstomp_send_message(cstom_connection_t *connection, const char *message, size_t message_size)
{
}

#endif // CSTOMP_HEADER_ONLY_LIBRARY