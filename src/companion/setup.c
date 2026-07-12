/*
 * companion/setup.c — QR setup code generation for Android companion pairing.
 */

#include "companion/setup.h"
#include "config.h"
#include "util/str.h"
#include "qrcodegen.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int is_unreserved(unsigned char c)
{
    return (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~');
}

char *sc_companion_uri_encode(const char *s)
{
    if (!s) return NULL;
    size_t cap = strlen(s) * 3 + 1;
    char *out = malloc(cap);
    if (!out) return NULL;
    char *p = out;
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        if (is_unreserved(*c))
            *p++ = (char)*c;
        else
            p += snprintf(p, (size_t)(out + cap - p), "%%%02X", *c);
    }
    *p = '\0';
    return out;
}

char *sc_companion_build_connect_uri(const char *origin, const char *token)
{
    if (!origin || !origin[0] || !token || !token[0]) return NULL;
    char *enc_url = sc_companion_uri_encode(origin);
    char *enc_tok = sc_companion_uri_encode(token);
    if (!enc_url || !enc_tok) {
        free(enc_url);
        free(enc_tok);
        return NULL;
    }
    size_t n = strlen("smolclaw://v1/connect?url=") + strlen(enc_url)
             + strlen("&token=") + strlen(enc_tok) + 1;
    char *uri = malloc(n);
    if (uri)
        snprintf(uri, n, "smolclaw://v1/connect?url=%s&token=%s",
                 enc_url, enc_tok);
    free(enc_url);
    free(enc_tok);
    return uri;
}

char *sc_companion_origin_from_web(const sc_web_config_t *web,
                                      const char *override_url)
{
    if (override_url && override_url[0])
        return sc_strdup(override_url);
    if (!web) return NULL;

    const char *scheme = (web->tls_cert && web->tls_cert[0] &&
                          web->tls_key && web->tls_key[0]) ? "https" : "http";
    const char *host = web->bind_addr && web->bind_addr[0]
                       ? web->bind_addr : "127.0.0.1";
    if (strcmp(host, "0.0.0.0") == 0)
        host = "127.0.0.1";
    int port = web->port > 0 ? web->port : 8080;
    int default_port = (strcmp(scheme, "https") == 0) ? 443 : 80;
    char *origin = malloc(256);
    if (!origin) return NULL;
    if (port == default_port)
        snprintf(origin, 256, "%s://%s", scheme, host);
    else
        snprintf(origin, 256, "%s://%s:%d", scheme, host, port);
    return origin;
}

static int host_is_private(const char *origin)
{
    if (!origin) return 0;
    const char *p = strstr(origin, "://");
    if (!p) return 0;
    p += 3;
    if (strncmp(p, "127.", 4) == 0 || strncmp(p, "localhost", 9) == 0)
        return 1;
    if (strncmp(p, "10.", 3) == 0) return 1;
    if (strncmp(p, "192.168.", 8) == 0) return 1;
    if (strncmp(p, "172.", 4) == 0) {
        int o2 = atoi(p + 4);
        if (o2 >= 16 && o2 <= 31) return 1;
    }
    if (strstr(p, ".local")) return 1;
    return 0;
}

int sc_companion_origin_tls_ok(const char *origin)
{
    if (!origin) return 0;
    if (strncmp(origin, "https://", 8) == 0) return 1;
    if (strncmp(origin, "http://", 7) == 0 && host_is_private(origin))
        return 1;
    return 0;
}

void sc_companion_print_qr_ascii(const char *text)
{
    if (!text || !text[0]) return;

    uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
    uint8_t temp[qrcodegen_BUFFER_LEN_MAX];
    if (!qrcodegen_encodeText(text, temp, qrcode, qrcodegen_Ecc_MEDIUM,
                              qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                              qrcodegen_Mask_AUTO, true))
        return;

    int size = qrcodegen_getSize(qrcode);
    /* Two QR rows per terminal row using half blocks (plan §13.1 D2). */
    for (int y = 0; y < size; y += 2) {
        fputs("  ", stdout);
        for (int x = 0; x < size; x++) {
            int top = qrcodegen_getModule(qrcode, x, y);
            int bot = (y + 1 < size) ? qrcodegen_getModule(qrcode, x, y + 1) : 0;
            /* UTF-8 block chars are multi-byte: must be string literals.
             * fputc('▀') truncates to one garbage byte (and clang rejects it). */
            if (top && bot) fputs("█", stdout);
            else if (top) fputs("▀", stdout);
            else if (bot) fputs("▄", stdout);
            else fputc(' ', stdout);
        }
        fputc('\n', stdout);
    }
}

int sc_companion_cmd_qr(int argc, char **argv)
{
    const char *override_url = NULL;
    int force = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) force = 1;
        else if (strcmp(argv[i], "--url") == 0 && i + 1 < argc)
            override_url = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: smolclaw companion qr [--url ORIGIN] [--force]\n");
            return 0;
        }
    }

    char *path = sc_config_get_path();
    sc_config_t *cfg = sc_config_load(path);
    if (!cfg) {
        fprintf(stderr, "Failed to load config from %s\n", path);
        free(path);
        return 1;
    }
    if (!cfg->web.bearer_token || !cfg->web.bearer_token[0]) {
        fprintf(stderr, "channels.web.bearer_token is required\n");
        free(path);
        sc_config_free(cfg);
        return 1;
    }

    char *origin = sc_companion_origin_from_web(&cfg->web, override_url);
    char *uri = sc_companion_build_connect_uri(origin, cfg->web.bearer_token);
    if (!origin || !uri) {
        fprintf(stderr, "Failed to build connect URI\n");
        free(origin);
        free(uri);
        free(path);
        sc_config_free(cfg);
        return 1;
    }

    if (!sc_companion_origin_tls_ok(origin))
        fprintf(stderr, "Warning: origin is not HTTPS and not a private LAN host; "
                "use --url with https:// for remote pairing\n");

    if (!isatty(STDOUT_FILENO) && !force) {
        fprintf(stderr, "Refusing to print token to non-TTY stdout (use --force)\n");
        free(origin);
        free(uri);
        free(path);
        sc_config_free(cfg);
        return 1;
    }

    printf("%s\n\n", uri);
    sc_companion_print_qr_ascii(uri);
    printf("\nOrigin: %s\n", origin);

    free(origin);
    free(uri);
    free(path);
    sc_config_free(cfg);
    return 0;
}