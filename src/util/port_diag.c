#include "util/port_diag.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/str.h"

#define TCP_LISTEN 0x0A

/* Scan one /proc/net/tcp-style file for a LISTEN socket on `port`, returning
 * its inode (0 if none). `ipv6` selects the wider local-address column. */
static unsigned long listen_inode_in(const char *path, int port, int ipv6)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[512];
    /* Skip the header line. */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }

    unsigned long inode = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned lport = 0, st = 0;
        unsigned long ino = 0;
        int n;
        if (ipv6) {
            n = sscanf(line,
                " %*d: %*64[0-9A-Fa-f]:%x %*64[0-9A-Fa-f]:%*x %x"
                " %*x:%*x %*x:%*x %*x %*u %*u %lu",
                &lport, &st, &ino);
        } else {
            n = sscanf(line,
                " %*d: %*x:%x %*x:%*x %x"
                " %*x:%*x %*x:%*x %*x %*u %*u %lu",
                &lport, &st, &ino);
        }
        if (n == 3 && st == TCP_LISTEN && (int)lport == port) {
            inode = ino;
            break;
        }
    }

    fclose(f);
    return inode;
}

static int is_all_digits(const char *s)
{
    if (!*s) return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

/* Read /proc/<pid>/comm into `out` (newline-stripped). Returns 0 on success. */
static int read_comm(const char *pid, char *out, size_t outsz)
{
    char path[300];  /* "/proc/" + up to 255-byte name + "/comm" */
    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)outsz, f)) { fclose(f); return -1; }
    fclose(f);
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
    return 0;
}

/* Find the PID owning a socket with `inode`. Returns a malloc'd
 * "comm (pid N)" string, or NULL. */
static char *pid_for_inode(unsigned long inode)
{
    char target[64];
    snprintf(target, sizeof(target), "socket:[%lu]", inode);

    DIR *proc = opendir("/proc");
    if (!proc) return NULL;

    char *result = NULL;
    struct dirent *pe;
    while ((pe = readdir(proc)) != NULL) {
        if (!is_all_digits(pe->d_name)) continue;

        char fdpath[300];
        snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", pe->d_name);
        DIR *fdd = opendir(fdpath);
        if (!fdd) continue;  /* likely EACCES for other users */

        struct dirent *fe;
        while ((fe = readdir(fdd)) != NULL) {
            char linkpath[600];
            int wn = snprintf(linkpath, sizeof(linkpath), "%s/%s",
                              fdpath, fe->d_name);
            if (wn < 0 || (size_t)wn >= sizeof(linkpath)) continue;

            char buf[96];
            ssize_t r = readlink(linkpath, buf, sizeof(buf) - 1);
            if (r < 0) continue;
            buf[r] = '\0';
            if (strcmp(buf, target) != 0) continue;

            char comm[64] = "?";
            read_comm(pe->d_name, comm, sizeof(comm));
            sc_strbuf_t sb;
            sc_strbuf_init(&sb);
            sc_strbuf_appendf(&sb, "%s (pid %s)", comm, pe->d_name);
            result = sc_strbuf_finish(&sb);
            break;
        }
        closedir(fdd);
        if (result) break;
    }

    closedir(proc);
    return result;
}

char *sc_port_holder(int port)
{
    if (port <= 0) return NULL;

    unsigned long inode = listen_inode_in("/proc/net/tcp", port, 0);
    if (!inode)
        inode = listen_inode_in("/proc/net/tcp6", port, 1);
    if (!inode) return NULL;

    return pid_for_inode(inode);
}
