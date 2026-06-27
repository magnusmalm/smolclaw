/*
 * smolclaw - port diagnostics tests (task 2.7)
 */

#include "test_main.h"
#include "util/port_diag.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Bind+listen on an ephemeral 127.0.0.1 port; return fd and set *out_port. */
static int open_listener(int *out_port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  /* ephemeral */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    if (listen(fd, 1) != 0) { close(fd); return -1; }

    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) { close(fd); return -1; }
    *out_port = ntohs(addr.sin_port);
    return fd;
}

static void test_finds_listening_process(void)
{
    int port = 0;
    int fd = open_listener(&port);
    ASSERT(fd >= 0, "should open a listener");
    ASSERT(port > 0, "should learn the ephemeral port");

    char *holder = sc_port_holder(port);
    ASSERT_NOT_NULL(holder);  /* this test process owns the socket */

    char want[32];
    snprintf(want, sizeof(want), "(pid %d)", (int)getpid());
    ASSERT(strstr(holder, want) != NULL, "holder names this process's pid");
    free(holder);

    close(fd);
}

static void test_no_holder_when_free(void)
{
    int port = 0;
    int fd = open_listener(&port);
    ASSERT(fd >= 0, "open listener");
    close(fd);  /* release the port */

    /* The listening socket is gone, so nothing should be reported. */
    char *holder = sc_port_holder(port);
    ASSERT_NULL(holder);
}

static void test_invalid_port_guard(void)
{
    ASSERT_NULL(sc_port_holder(0));
    ASSERT_NULL(sc_port_holder(-1));
}

int main(void)
{
    printf("test_port_diag\n");

    RUN_TEST(test_finds_listening_process);
    RUN_TEST(test_no_holder_when_free);
    RUN_TEST(test_invalid_port_guard);

    TEST_REPORT();
}
