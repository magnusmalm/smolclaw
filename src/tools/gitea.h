#ifndef SC_TOOL_GITEA_H
#define SC_TOOL_GITEA_H

#include "tools/types.h"

/*
 * Gitea API tool — create repos, issues, PRs, and comments.
 *
 * api_url:     Gitea base URL (e.g. "https://gitea.example.com")
 * api_token:   Personal access token
 * default_org: Default org for repo creation (NULL for user repos)
 */
sc_tool_t *sc_tool_gitea_new(const char *api_url, const char *api_token,
                              const char *default_org);

#endif /* SC_TOOL_GITEA_H */
