/*
 * tools/x_tools.h - X (Twitter) read-only API tools
 *
 * Native tools for fetching tweets, threads, searching, and user profiles.
 * Uses the shared OAuth 1.0a layer from util/x_api.h.
 */

#ifndef SC_TOOL_X_TOOLS_H
#define SC_TOOL_X_TOOLS_H

#include "tools/types.h"
#include "config.h"

/* Create X API read tools. Returns NULL if credentials missing. */
sc_tool_t *sc_tool_x_get_tweet_new(const sc_x_config_t *cfg);
sc_tool_t *sc_tool_x_get_thread_new(const sc_x_config_t *cfg);
sc_tool_t *sc_tool_x_search_new(const sc_x_config_t *cfg);
sc_tool_t *sc_tool_x_get_user_new(const sc_x_config_t *cfg);

#endif /* SC_TOOL_X_TOOLS_H */
