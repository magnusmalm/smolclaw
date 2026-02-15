/*
 * smolclaw - CLI channel
 * Interactive command-line channel using readline or simple fgets fallback.
 */

#include "channels/cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "constants.h"
#include "logger.h"
#include "util/str.h"

typedef struct {
    int stop_requested;
} cli_data_t;

static int cli_start(sc_channel_t *self)
{
    self->running = 1;
    SC_LOG_INFO("cli", "CLI channel started");
    return 0;
}

static int cli_stop(sc_channel_t *self)
{
    self->running = 0;
    cli_data_t *d = self->data;
    if (d) d->stop_requested = 1;
    SC_LOG_INFO("cli", "CLI channel stopped");
    return 0;
}

static int cli_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    (void)self;
    if (!msg || !msg->content) return -1;

    printf("\n%s %s\n\n", SC_LOGO, msg->content);
    fflush(stdout);
    return 0;
}

static int cli_is_running(sc_channel_t *self)
{
    return self ? self->running : 0;
}

static void cli_destroy(sc_channel_t *self)
{
    sc_channel_base_free(self);
}

/* Read a line from the user (blocking) */
static char *cli_readline(void)
{
#ifdef HAVE_READLINE
    char *line = readline("You: ");
    if (line && *line) {
        add_history(line);
    }
    return line;
#else
    printf("You: ");
    fflush(stdout);

    char buf[4096];
    if (!fgets(buf, sizeof(buf), stdin)) return NULL;

    /* Remove trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    return sc_strdup(buf);
#endif
}

/* Run the interactive CLI loop (blocking).
 * Reads input, publishes to bus, and relies on bus outbound handler for output. */
void sc_channel_cli_run(sc_channel_t *ch)
{
    if (!ch) return;
    cli_data_t *d = ch->data;

    printf("%s Interactive mode (type 'exit' to quit)\n\n", SC_LOGO);

    while (ch->running) {
        char *line = cli_readline();
        if (!line) {
            /* EOF */
            printf("\nGoodbye!\n");
            break;
        }

        /* Trim */
        char *trimmed = sc_trim(line);
        free(line);

        if (!trimmed || trimmed[0] == '\0') {
            free(trimmed);
            continue;
        }

        if (strcmp(trimmed, "exit") == 0 || strcmp(trimmed, "quit") == 0) {
            free(trimmed);
            printf("Goodbye!\n");
            break;
        }

        if (d && d->stop_requested) {
            free(trimmed);
            break;
        }

        /* Publish to bus */
        sc_channel_handle_message(ch, "cli_user", "direct", trimmed);
        free(trimmed);
    }
}

int sc_cli_confirm_tool(const char *tool, const char *args, void *ctx)
{
    (void)ctx;
    /* Truncate args for display */
    char preview[201];
    if (args && args[0]) {
        size_t len = strlen(args);
        if (len > 200) {
            memcpy(preview, args, 200);
            preview[200] = '\0';
        } else {
            memcpy(preview, args, len + 1);
        }
    } else {
        preview[0] = '\0';
    }

    fprintf(stderr, "\n[CONFIRM] Tool: %s\n", tool);
    if (preview[0])
        fprintf(stderr, "  Args: %s\n", preview);
    fprintf(stderr, "  Allow? (y/N): ");
    fflush(stderr);

    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin))
        return 0;

    return (buf[0] == 'y' || buf[0] == 'Y');
}

sc_channel_t *sc_channel_cli_new(sc_bus_t *bus)
{
    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    cli_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(ch); return NULL; }

    ch->name = SC_CHANNEL_CLI;
    ch->start = cli_start;
    ch->stop = cli_stop;
    ch->send = cli_send;
    ch->is_running = cli_is_running;
    ch->destroy = cli_destroy;
    ch->bus = bus;
    ch->allow_list = NULL;
    ch->allow_list_count = 0;
    ch->running = 0;
    ch->data = d;

    return ch;
}
