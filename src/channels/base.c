/*
 * smolclaw - channel base
 * Common channel logic: allow list checking, message handling.
 */

#include "channels/base.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "logger.h"
#include "util/str.h"

void sc_channel_init_security(sc_channel_t *ch, const char *dm_policy,
                               char **allow_from, int allow_from_count,
                               const char *channel_name)
{
    if (!ch) return;

    pthread_mutex_init(&ch->security_mutex, NULL);

    /* Copy allow list */
    if (allow_from_count > 0 && allow_from) {
        ch->allow_list_count = allow_from_count;
        ch->allow_list = calloc((size_t)allow_from_count, sizeof(char *));
        if (ch->allow_list) {
            for (int i = 0; i < allow_from_count; i++)
                ch->allow_list[i] = sc_strdup(allow_from[i]);
        }
    }

    /* DM policy + pairing store */
    ch->dm_policy = sc_dm_policy_from_str(dm_policy);
    if (ch->dm_policy == SC_DM_POLICY_PAIRING) {
        char *dir = sc_expand_home("~/.smolclaw/pairing");
        ch->pairing_store = sc_pairing_store_new(channel_name, dir);
        free(dir);
    }
}

int sc_channel_is_allowed(sc_channel_t *ch, const char *sender_id)
{
    if (!ch || !sender_id) return 0;

    pthread_mutex_lock(&ch->security_mutex);

    /* Empty allow list: open policy allows all, others deny */
    if (ch->allow_list_count == 0 || !ch->allow_list) {
        int result = (ch->dm_policy == SC_DM_POLICY_OPEN) ? 1 : 0;
        pthread_mutex_unlock(&ch->security_mutex);
        return result;
    }

    /* Extract parts from compound senderID like "123456|username" */
    const char *id_part = sender_id;
    const char *user_part = NULL;
    char *id_buf = NULL;

    const char *pipe = strchr(sender_id, '|');
    if (pipe) {
        size_t id_len = pipe - sender_id;
        id_buf = malloc(id_len + 1);
        if (id_buf) {
            memcpy(id_buf, sender_id, id_len);
            id_buf[id_len] = '\0';
            id_part = id_buf;
        }
        user_part = pipe + 1;
    }

    int allowed = 0;
    for (int i = 0; i < ch->allow_list_count && !allowed; i++) {
        const char *entry = ch->allow_list[i];
        if (!entry) continue;

        /* Strip leading @ */
        const char *trimmed = entry;
        if (trimmed[0] == '@') trimmed++;

        /* Parse allowed entry for "id|username" format */
        const char *allowed_id = trimmed;
        const char *allowed_user = NULL;
        char *aid_buf = NULL;

        const char *apipe = strchr(trimmed, '|');
        if (apipe) {
            size_t alen = apipe - trimmed;
            aid_buf = malloc(alen + 1);
            if (aid_buf) {
                memcpy(aid_buf, trimmed, alen);
                aid_buf[alen] = '\0';
                allowed_id = aid_buf;
            }
            allowed_user = apipe + 1;
        }

        /* Match: full sender_id == entry */
        if (strcmp(sender_id, entry) == 0) { allowed = 1; }
        /* Match: id_part == entry */
        else if (strcmp(id_part, entry) == 0) { allowed = 1; }
        /* Match: sender_id == trimmed */
        else if (strcmp(sender_id, trimmed) == 0) { allowed = 1; }
        /* Match: id_part == trimmed */
        else if (strcmp(id_part, trimmed) == 0) { allowed = 1; }
        /* Match: id_part == allowed_id */
        else if (strcmp(id_part, allowed_id) == 0) { allowed = 1; }
        /* Match: allowed_user set and sender_id == allowed_user */
        else if (allowed_user && strcmp(sender_id, allowed_user) == 0) { allowed = 1; }
        /* Match: user_part matches */
        else if (user_part) {
            if (strcmp(user_part, entry) == 0) { allowed = 1; }
            else if (strcmp(user_part, trimmed) == 0) { allowed = 1; }
            else if (allowed_user && strcmp(user_part, allowed_user) == 0) { allowed = 1; }
        }

        free(aid_buf);
    }

    pthread_mutex_unlock(&ch->security_mutex);
    free(id_buf);
    return allowed;
}

void sc_channel_handle_message(sc_channel_t *ch, const char *sender_id,
                                const char *chat_id, const char *content)
{
    if (!ch || !ch->bus) return;

    /* Reject sender_id with multiple pipes (prevents compound ID parsing bypass) */
    if (sender_id) {
        const char *p1 = strchr(sender_id, '|');
        if (p1 && strchr(p1 + 1, '|')) {
            SC_LOG_WARN("channel", "Rejected sender_id with multiple pipes");
            return;
        }
    }

    if (!sc_channel_is_allowed(ch, sender_id)) {
        /* Pairing mode: send challenge code to unknown sender */
        if (ch->dm_policy == SC_DM_POLICY_PAIRING && ch->pairing_store) {
            const char *code = sc_pairing_store_challenge(ch->pairing_store, sender_id);
            if (code) {
                sc_strbuf_t reply;
                sc_strbuf_init(&reply);
                sc_strbuf_appendf(&reply,
                    "Access requires pairing. Your code: %s\n"
                    "Ask the owner to run: smolclaw pairing approve %s %s",
                    code, ch->name, code);
                char *text = sc_strbuf_finish(&reply);

                sc_outbound_msg_t *out = sc_outbound_msg_new(
                    ch->name, chat_id ? chat_id : "0", text);
                free(text);
                if (out && ch->send) {
                    ch->send(ch, out);
                }
                sc_outbound_msg_free(out);
            }
            SC_LOG_DEBUG("channel", "Pairing challenge sent to sender=%s", sender_id);
        } else {
            SC_LOG_DEBUG("channel", "Message rejected by allowlist: sender=%s",
                         sender_id ? sender_id : "(null)");
        }
        return;
    }

    /* Rate limiting */
    pthread_mutex_lock(&ch->security_mutex);
    sc_rate_limiter_t *rl = ch->rate_limiter;
    pthread_mutex_unlock(&ch->security_mutex);
    if (rl) {
        sc_strbuf_t rk;
        sc_strbuf_init(&rk);
        sc_strbuf_appendf(&rk, "%s:%s", ch->name, chat_id ? chat_id : "unknown");
        char *rate_key = sc_strbuf_finish(&rk);
        int allowed = sc_rate_limiter_check(rl, rate_key);
        free(rate_key);
        if (!allowed) {
            SC_LOG_WARN("channel", "Rate limited: %s:%s from %s",
                        ch->name, chat_id ? chat_id : "unknown",
                        sender_id ? sender_id : "(null)");
            return;
        }
    }

    /* Build session key: channel:chat_id */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s:%s", ch->name, chat_id ? chat_id : "unknown");
    char *session_key = sc_strbuf_finish(&sb);

    sc_inbound_msg_t *msg = sc_inbound_msg_new(
        ch->name, sender_id, chat_id, content, session_key);
    free(session_key);

    if (msg) {
        sc_bus_publish_inbound(ch->bus, msg);
    }
}

void sc_channel_base_free(sc_channel_t *ch)
{
    if (!ch) return;
    pthread_mutex_destroy(&ch->security_mutex);
    free(ch->announce_message);
    if (ch->allow_list) {
        for (int i = 0; i < ch->allow_list_count; i++) {
            free(ch->allow_list[i]);
        }
        free(ch->allow_list);
    }
    sc_pairing_store_free(ch->pairing_store);
    sc_rate_limiter_free(ch->rate_limiter);
    /* ch->data is owned and freed by channel-specific destroy() */
    free(ch);
}
