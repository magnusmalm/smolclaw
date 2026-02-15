/*
 * smolclaw - channel manager
 * Manages multiple communication channels, dispatches outbound messages.
 */

#include "channels/manager.h"

#include <stdlib.h>
#include <string.h>

#include "util/str.h"

#include "sc_features.h"
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
#if SC_ENABLE_VOICE
#include "voice/transcriber.h"
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
        SC_LOG_INFO("channels", "Initializing Telegram channel");
        sc_channel_t *tg = sc_channel_telegram_new(&cfg->telegram, bus);
        if (tg)
            manager_add_channel(mgr, tg, cfg->telegram.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Telegram channel");
    }
#endif

#if SC_ENABLE_DISCORD
    if (cfg->discord.enabled && cfg->discord.token && cfg->discord.token[0]) {
        SC_LOG_INFO("channels", "Initializing Discord channel");
        sc_channel_t *dc = sc_channel_discord_new(&cfg->discord, bus);
        if (dc)
            manager_add_channel(mgr, dc, cfg->discord.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Discord channel");
    }
#endif

#if SC_ENABLE_IRC
    if (cfg->irc.enabled && cfg->irc.hostname && cfg->irc.hostname[0]) {
        SC_LOG_INFO("channels", "Initializing IRC channel");
        sc_channel_t *irc = sc_channel_irc_new(&cfg->irc, bus);
        if (irc)
            manager_add_channel(mgr, irc, cfg->irc.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize IRC channel");
    }
#endif

#if SC_ENABLE_SLACK
    if (cfg->slack.enabled && cfg->slack.bot_token && cfg->slack.bot_token[0]
        && cfg->slack.app_token && cfg->slack.app_token[0]) {
        SC_LOG_INFO("channels", "Initializing Slack channel");
        sc_channel_t *sl = sc_channel_slack_new(&cfg->slack, bus);
        if (sl)
            manager_add_channel(mgr, sl, cfg->slack.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Slack channel");
    }
#endif

#if SC_ENABLE_WEB
    if (cfg->web.enabled) {
        SC_LOG_INFO("channels", "Initializing Web channel");
        sc_channel_t *web = sc_channel_web_new(&cfg->web, bus);
        if (web)
            manager_add_channel(mgr, web, cfg->web.dm_policy, rl);
        else
            SC_LOG_ERROR("channels", "Failed to initialize Web channel");
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

/* Helper: replace a channel's allow_from list */
static void reload_allow_list(sc_channel_t *ch, char **allow_from,
                               int allow_from_count)
{
    if (!ch) return;
    /* Free old list */
    for (int i = 0; i < ch->allow_list_count; i++)
        free(ch->allow_list[i]);
    free(ch->allow_list);
    /* Copy new list */
    if (allow_from_count > 0 && allow_from) {
        ch->allow_list = calloc((size_t)allow_from_count, sizeof(char *));
        if (ch->allow_list) {
            ch->allow_list_count = allow_from_count;
            for (int i = 0; i < allow_from_count; i++)
                ch->allow_list[i] = sc_strdup(allow_from[i]);
        } else {
            ch->allow_list_count = 0;
        }
    } else {
        ch->allow_list = NULL;
        ch->allow_list_count = 0;
    }
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
                              cfg->telegram.allow_from_count);
            ch->dm_policy = sc_dm_policy_from_str(cfg->telegram.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_DISCORD) == 0) {
            reload_allow_list(ch, cfg->discord.allow_from,
                              cfg->discord.allow_from_count);
            ch->dm_policy = sc_dm_policy_from_str(cfg->discord.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_IRC) == 0) {
            reload_allow_list(ch, cfg->irc.allow_from,
                              cfg->irc.allow_from_count);
            ch->dm_policy = sc_dm_policy_from_str(cfg->irc.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_SLACK) == 0) {
            reload_allow_list(ch, cfg->slack.allow_from,
                              cfg->slack.allow_from_count);
            ch->dm_policy = sc_dm_policy_from_str(cfg->slack.dm_policy);
        } else if (strcmp(ch->name, SC_CHANNEL_WEB) == 0) {
            reload_allow_list(ch, cfg->web.allow_from,
                              cfg->web.allow_from_count);
            ch->dm_policy = sc_dm_policy_from_str(cfg->web.dm_policy);
        }

        /* Update rate limiter */
        if (cfg->rate_limit_per_minute > 0) {
            if (ch->rate_limiter) {
                sc_rate_limiter_free(ch->rate_limiter);
            }
            ch->rate_limiter = sc_rate_limiter_new(cfg->rate_limit_per_minute);
        }
    }

    SC_LOG_INFO("channels", "Channel config reloaded (allow_from, dm_policy, rate_limits)");
}
