/*
 * smolclaw - channel manager
 * Manages multiple communication channels, dispatches outbound messages.
 */

#include "channels/manager.h"

#include <stdlib.h>
#include <string.h>

#include "util/str.h"

#include "sc_features.h"
#include "sc_version.h"
#include "constants.h"
#include "logger.h"
#include "rate_limit.h"

#if SC_ENABLE_TELEGRAM
#include "channels/telegram.h"
#endif
#if SC_ENABLE_DISCORD
#include "channels/discord.h"
#endif
#if SC_ENABLE_IRC
#include "channels/irc.h"
#endif
#if SC_ENABLE_SLACK
#include "channels/slack.h"
#endif
#if SC_ENABLE_WEB
#include "channels/web.h"
#endif
#if SC_ENABLE_X
#include "channels/x.h"
#endif
#if SC_ENABLE_VOICE
#include "voice/transcriber.h"
#endif

#if SC_STRICT_SECURITY
/* Strict mode: refuse to start channels with inadequate security config.
 * Returns 1 if the channel should be quarantined (not started). */
static int quarantine_check(const char *name, const char *dm_policy,
                             int allow_from_count)
{
    /* Channels with explicit non-open policy are fine */
    if (dm_policy && strcmp(dm_policy, "open") != 0)
        return 0;

    /* Open policy but has an allow_from list = effectively allowlist */
    if (allow_from_count > 0)
        return 0;

    SC_LOG_ERROR("channels", "QUARANTINE: %s channel has open DM policy and no allow_from list. "
                 "In strict security mode, configure dm_policy or allow_from to enable this channel.",
                 name);
    return 1;
}
#endif

/* Add a channel to the manager array, set up rate limiter and DM policy warning.
 * Returns 0 on success, -1 on failure (channel is destroyed on failure). */
static int manager_add_channel(sc_channel_manager_t *mgr, sc_channel_t *ch,
                                const char *dm_policy, int rate_limit)
{
    sc_channel_t **new_arr = sc_safe_realloc(mgr->channels,
        (size_t)(mgr->count + 1) * sizeof(sc_channel_t *));
    if (!new_arr) {
        SC_LOG_ERROR("channels", "OOM adding %s channel", ch->name);
        ch->destroy(ch);
        return -1;
    }
    mgr->channels = new_arr;
    if (rate_limit > 0)
        ch->rate_limiter = sc_rate_limiter_new(rate_limit);
    mgr->channels[mgr->count++] = ch;
    if (dm_policy && strcmp(dm_policy, "open") == 0)
        SC_LOG_WARN("channels", "%s DM policy is 'open' — all users can message the bot",
                    ch->name);
    SC_LOG_INFO("channels", "%s channel enabled", ch->name);
    return 0;
}

sc_channel_manager_t *sc_channel_manager_new(sc_config_t *cfg, sc_bus_t *bus)
{
    sc_channel_manager_t *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    mgr->bus = bus;
    mgr->config = cfg;
    mgr->channels = NULL;
    mgr->count = 0;

    int rl = cfg->rate_limit_per_minute;

#if SC_ENABLE_TELEGRAM
    if (cfg->telegram.enabled && cfg->telegram.token && cfg->telegram.token[0]) {
#if SC_STRICT_SECURITY
        if (!quarantine_check("Telegram", cfg->telegram.dm_policy,
                              cfg->telegram.allow_from_count)) {
#endif
        SC_LOG_INFO("channels", "Initializing Telegram channel");
        sc_channel_t *tg = sc_channel_telegram_new(&cfg->telegram, bus);
        if (tg)
            manager_add_channel(mgr, tg, cfg->telegram.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Telegram channel");
#if SC_STRICT_SECURITY
        }
#endif
    }
#endif

#if SC_ENABLE_DISCORD
    if (cfg->discord.enabled && cfg->discord.token && cfg->discord.token[0]) {
#if SC_STRICT_SECURITY
        if (!quarantine_check("Discord", cfg->discord.dm_policy,
                              cfg->discord.allow_from_count)) {
#endif
        SC_LOG_INFO("channels", "Initializing Discord channel");
        sc_channel_t *dc = sc_channel_discord_new(&cfg->discord, bus);
        if (dc)
            manager_add_channel(mgr, dc, cfg->discord.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Discord channel");
#if SC_STRICT_SECURITY
        }
#endif
    }
#endif

#if SC_ENABLE_IRC
    if (cfg->irc.enabled && cfg->irc.hostname && cfg->irc.hostname[0]) {
#if SC_STRICT_SECURITY
        if (!quarantine_check("IRC", cfg->irc.dm_policy,
                              cfg->irc.allow_from_count)) {
#endif
        SC_LOG_INFO("channels", "Initializing IRC channel");
        sc_channel_t *irc = sc_channel_irc_new(&cfg->irc, bus);
        if (irc)
            manager_add_channel(mgr, irc, cfg->irc.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize IRC channel");
#if SC_STRICT_SECURITY
        }
#endif
    }
#endif

#if SC_ENABLE_SLACK
    if (cfg->slack.enabled && cfg->slack.bot_token && cfg->slack.bot_token[0]
        && cfg->slack.app_token && cfg->slack.app_token[0]) {
#if SC_STRICT_SECURITY
        if (!quarantine_check("Slack", cfg->slack.dm_policy,
                              cfg->slack.allow_from_count)) {
#endif
        SC_LOG_INFO("channels", "Initializing Slack channel");
        sc_channel_t *sl = sc_channel_slack_new(&cfg->slack, bus);
        if (sl)
            manager_add_channel(mgr, sl, cfg->slack.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Slack channel");
#if SC_STRICT_SECURITY
        }
#endif
    }
#endif

#if SC_ENABLE_WEB
    if (cfg->web.enabled) {
        if (!cfg->web.bearer_token || !cfg->web.bearer_token[0]) {
            SC_LOG_ERROR("channels", "Web channel requires a bearer_token for API authentication. "
                         "Set web.bearer_token in config or SMOLCLAW_WEB_BEARER_TOKEN env var.");
        } else {
#if SC_STRICT_SECURITY
            const char *waddr = cfg->web.bind_addr;
            int web_loopback = !waddr || !waddr[0] ||
                               strcmp(waddr, "127.0.0.1") == 0 ||
                               strcmp(waddr, "::1") == 0 ||
                               strcmp(waddr, "localhost") == 0;
            if (!web_loopback) {
                SC_LOG_ERROR("channels", "QUARANTINE: Web channel bind_addr is '%s' (non-loopback). "
                             "In strict security mode, bind to 127.0.0.1 and use a reverse proxy.",
                             waddr);
            } else if (!quarantine_check("Web", cfg->web.dm_policy,
                                         cfg->web.allow_from_count)) {
#endif
            SC_LOG_INFO("channels", "Initializing Web channel");
            sc_channel_t *web = sc_channel_web_new(&cfg->web, bus);
            if (web)
                manager_add_channel(mgr, web, cfg->web.dm_policy, rl);
            else
                SC_LOG_ERROR("channels", "Failed to initialize Web channel");
#if SC_STRICT_SECURITY
            }
#endif
        }
    }
#endif

#if SC_ENABLE_X
    if (cfg->x.enabled && cfg->x.consumer_key && cfg->x.consumer_key[0]
        && cfg->x.access_token && cfg->x.access_token[0]) {
#if SC_STRICT_SECURITY
        if (!quarantine_check("X", cfg->x.dm_policy,
                              cfg->x.allow_from_count)) {
#endif
        SC_LOG_INFO("channels", "Initializing X channel");
        sc_channel_t *xch = sc_channel_x_new(&cfg->x, bus);
        if (xch)
            manager_add_channel(mgr, xch, cfg->x.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize X channel");
#if SC_STRICT_SECURITY
        }
#endif
    }
#endif

#if SC_ENABLE_VOICE
    if (cfg->groq.api_key && cfg->groq.api_key[0]) {
        mgr->transcriber = sc_transcriber_new(cfg->groq.api_key, cfg->groq.api_base);
        if (mgr->transcriber) {
            SC_LOG_INFO("channels", "Voice transcription enabled (Groq Whisper)");
            for (int i = 0; i < mgr->count; i++)
                mgr->channels[i]->transcriber = mgr->transcriber;
        }
    }
#endif

    /* Build announce message if enabled */
    if (cfg->announce_on_join && mgr->count > 0) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "smolclaw %s", SC_VERSION_FULL);

        /* Compile-time feature list */
        const char *features[] = {
#if SC_ENABLE_VOICE
            "voice",
#endif
#if SC_ENABLE_MCP
            "mcp",
#endif
#if SC_ENABLE_GIT
            "git",
#endif
#if SC_ENABLE_WEB_TOOLS
            "web-tools",
#endif
#if SC_ENABLE_STREAMING
            "streaming",
#endif
#if SC_ENABLE_MEMORY_SEARCH
            "memory-search",
#endif
#if SC_ENABLE_VAULT
            "vault",
#endif
            NULL  /* sentinel — avoids zero-size array in minimal builds */
        };
        int nfeat = (int)(sizeof(features) / sizeof(features[0])) - 1;
        if (nfeat > 0) {
            sc_strbuf_append(&sb, " [");
            for (int i = 0; i < nfeat; i++) {
                if (i > 0) sc_strbuf_append(&sb, ", ");
                sc_strbuf_append(&sb, features[i]);
            }
            sc_strbuf_append(&sb, "]");
        }

        char *msg = sc_strbuf_finish(&sb);
        for (int i = 0; i < mgr->count; i++)
            mgr->channels[i]->announce_message = sc_strdup(msg);
        free(msg);
    }

    SC_LOG_INFO("channels", "Channel initialization completed: %d channels", mgr->count);
    return mgr;
}

void sc_channel_manager_free(sc_channel_manager_t *mgr)
{
    if (!mgr) return;

    for (int i = 0; i < mgr->count; i++) {
        if (mgr->channels[i] && mgr->channels[i]->destroy) {
            mgr->channels[i]->destroy(mgr->channels[i]);
        }
    }
    free(mgr->channels);
#if SC_ENABLE_VOICE
    sc_transcriber_free(mgr->transcriber);
#endif
    free(mgr);
}

int sc_channel_manager_start_all(sc_channel_manager_t *mgr)
{
    if (!mgr) return -1;

    if (mgr->count == 0) {
        SC_LOG_WARN("channels", "No channels enabled");
        return 0;
    }

    SC_LOG_INFO("channels", "Starting all channels");

    for (int i = 0; i < mgr->count; i++) {
        sc_channel_t *ch = mgr->channels[i];
        if (ch && ch->start) {
            SC_LOG_INFO("channels", "Starting channel: %s", ch->name);
            int ret = ch->start(ch);
            if (ret != 0) {
                SC_LOG_ERROR("channels", "Failed to start channel: %s", ch->name);
            }
        }
    }

    SC_LOG_INFO("channels", "All channels started");
    return 0;
}

void sc_channel_manager_stop_all(sc_channel_manager_t *mgr)
{
    if (!mgr) return;

    SC_LOG_INFO("channels", "Stopping all channels");

    for (int i = 0; i < mgr->count; i++) {
        sc_channel_t *ch = mgr->channels[i];
        if (ch && ch->stop) {
            SC_LOG_INFO("channels", "Stopping channel: %s", ch->name);
            ch->stop(ch);
        }
    }

    SC_LOG_INFO("channels", "All channels stopped");
}

sc_channel_t *sc_channel_manager_get(sc_channel_manager_t *mgr, const char *name)
{
    if (!mgr || !name) return NULL;

    for (int i = 0; i < mgr->count; i++) {
        if (mgr->channels[i] && mgr->channels[i]->name &&
            strcmp(mgr->channels[i]->name, name) == 0) {
            return mgr->channels[i];
        }
    }
    return NULL;
}

int sc_channel_manager_send(sc_channel_manager_t *mgr, const char *channel,
                            const char *chat_id, const char *content)
{
    if (!mgr || !channel) return -1;

    /* Skip internal channels silently */
    if (sc_is_internal_channel(channel)) return 0;

    sc_channel_t *ch = sc_channel_manager_get(mgr, channel);
    if (!ch) {
        SC_LOG_WARN("channels", "Unknown channel for outbound: %s", channel);
        return -1;
    }

    if (!ch->send) return -1;

    sc_outbound_msg_t msg = {
        .channel = (char *)channel,
        .chat_id = (char *)chat_id,
        .content = (char *)content,
    };

    return ch->send(ch, &msg);
}

int sc_channel_manager_send_typing(sc_channel_manager_t *mgr,
                                   const char *channel, const char *chat_id)
{
    if (!mgr || !channel) return -1;
    if (sc_is_internal_channel(channel)) return 0;
    sc_channel_t *ch = sc_channel_manager_get(mgr, channel);
    if (!ch || !ch->send_typing) return 0;
    return ch->send_typing(ch, chat_id);
}

/* Helper: replace a channel's allow_from list (thread-safe) */
static void reload_allow_list(sc_channel_t *ch, char **allow_from,
                               int allow_from_count, const char *dm_policy)
{
    if (!ch) return;

    /* Build new list before taking lock */
    char **new_list = NULL;
    int new_count = 0;
    if (allow_from_count > 0 && allow_from) {
        new_list = calloc((size_t)allow_from_count, sizeof(char *));
        if (new_list) {
            new_count = allow_from_count;
            for (int i = 0; i < allow_from_count; i++)
                new_list[i] = sc_strdup(allow_from[i]);
        }
    }

    sc_dm_policy_t new_policy = sc_dm_policy_from_str(dm_policy);

    /* Swap under lock (dm_policy + allow_list must be consistent) */
    pthread_mutex_lock(&ch->security_mutex);
    char **old_list = ch->allow_list;
    int old_count = ch->allow_list_count;
    ch->allow_list = new_list;
    ch->allow_list_count = new_count;
    ch->dm_policy = new_policy;
    pthread_mutex_unlock(&ch->security_mutex);

    /* Free old list outside lock */
    for (int i = 0; i < old_count; i++)
        free(old_list[i]);
    free(old_list);
}

void sc_channel_manager_reload_config(sc_channel_manager_t *mgr,
                                       const sc_config_t *cfg)
{
    if (!mgr || !cfg) return;

    for (int i = 0; i < mgr->count; i++) {
        sc_channel_t *ch = mgr->channels[i];
        if (!ch || !ch->name) continue;

        if (strcmp(ch->name, SC_CHANNEL_TELEGRAM) == 0) {
            reload_allow_list(ch, cfg->telegram.allow_from,
                              cfg->telegram.allow_from_count,
                              cfg->telegram.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_DISCORD) == 0) {
            reload_allow_list(ch, cfg->discord.allow_from,
                              cfg->discord.allow_from_count,
                              cfg->discord.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_IRC) == 0) {
            reload_allow_list(ch, cfg->irc.allow_from,
                              cfg->irc.allow_from_count,
                              cfg->irc.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_SLACK) == 0) {
            reload_allow_list(ch, cfg->slack.allow_from,
                              cfg->slack.allow_from_count,
                              cfg->slack.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_WEB) == 0) {
            reload_allow_list(ch, cfg->web.allow_from,
                              cfg->web.allow_from_count,
                              cfg->web.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_X) == 0) {
            reload_allow_list(ch, cfg->x.allow_from,
                              cfg->x.allow_from_count,
                              cfg->x.dm_policy);
        }

        /* Update rate limiter (thread-safe swap) */
        sc_rate_limiter_t *new_rl = NULL;
        if (cfg->rate_limit_per_minute > 0)
            new_rl = sc_rate_limiter_new(cfg->rate_limit_per_minute);

        pthread_mutex_lock(&ch->security_mutex);
        sc_rate_limiter_t *old_rl = ch->rate_limiter;
        ch->rate_limiter = new_rl;
        pthread_mutex_unlock(&ch->security_mutex);

        sc_rate_limiter_free(old_rl);
    }

    SC_LOG_INFO("channels", "Channel config reloaded (allow_from, dm_policy, rate_limits)");
}
