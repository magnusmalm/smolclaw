#include "tools/gitea.h"
#include "tools/registry.h"
#include "util/curl_common.h"
#include "util/json_helpers.h"
#include "util/str.h"
#include "logger.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "gitea_tool"

typedef struct {
    char *api_url;
    char *api_token;
    char *default_org;
} gitea_data_t;

/* ------------------------------------------------------------------ */
/*  HTTP helpers                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} resp_buf_t;

static size_t
write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    resp_buf_t *buf = userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        size_t newcap = (buf->cap + total + 1) * 2;
        char *tmp = realloc(buf->data, newcap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/*
 * Perform an HTTP request to the Gitea API.
 * method: "GET", "POST", "DELETE", etc.
 * path: API path (e.g. "/api/v1/repos/org/repo/issues")
 * body: JSON body string, or NULL for GET/DELETE
 * Returns malloc'd response body, or NULL on error.
 * Sets *http_code if non-NULL.
 */
static char *
gitea_request(gitea_data_t *gd, const char *method, const char *path,
              const char *body, long *http_code)
{
    char url[1024];
    snprintf(url, sizeof(url), "%s%s", gd->api_url, path);

    CURL *curl = sc_curl_init();
    if (!curl) return NULL;

    resp_buf_t resp = {.data = malloc(1024), .len = 0, .cap = 1024};
    if (!resp.data) { curl_easy_cleanup(curl); return NULL; }
    resp.data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* Auth header */
    char auth[256];
    snprintf(auth, sizeof(auth), "Authorization: token %s", gd->api_token);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (strcmp(method, "PATCH") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    }

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        SC_LOG_WARN(TAG, "request failed: %s %s — %s",
                    method, path, curl_easy_strerror(rc));
        curl_easy_cleanup(curl);
        free(resp.data);
        return NULL;
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_code) *http_code = code;
    curl_easy_cleanup(curl);

    return resp.data;
}

/* ------------------------------------------------------------------ */
/*  Subcommands                                                        */
/* ------------------------------------------------------------------ */

static sc_tool_result_t *
cmd_create_repo(gitea_data_t *gd, cJSON *args)
{
    const char *name = sc_json_get_string(args, "name", NULL);
    const char *desc = sc_json_get_string(args, "description", "");
    const char *org = sc_json_get_string(args, "org", gd->default_org);

    if (!name || !name[0])
        return sc_tool_result_error("'name' is required");

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "name", name);
    cJSON_AddStringToObject(body, "description", desc);
    cJSON_AddBoolToObject(body, "auto_init", 1);
    cJSON_AddStringToObject(body, "default_branch", "main");
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    char path[256];
    if (org && org[0])
        snprintf(path, sizeof(path), "/api/v1/orgs/%s/repos", org);
    else
        snprintf(path, sizeof(path), "/api/v1/user/repos");

    long code = 0;
    char *resp = gitea_request(gd, "POST", path, body_str, &code);
    free(body_str);

    if (!resp)
        return sc_tool_result_error("Failed to create repo (network error)");

    if (code != 201) {
        cJSON *err = cJSON_Parse(resp);
        const char *msg = err ? sc_json_get_string(err, "message", resp) : resp;
        char buf[512];
        snprintf(buf, sizeof(buf), "Failed to create repo (HTTP %ld): %s",
                 code, msg);
        cJSON_Delete(err);
        free(resp);
        return sc_tool_result_error(buf);
    }

    cJSON *r = cJSON_Parse(resp);
    free(resp);
    if (!r) return sc_tool_result_error("Invalid JSON response");

    const char *full_name = sc_json_get_string(r, "full_name", "?");
    const char *html_url = sc_json_get_string(r, "html_url", "?");
    const char *clone_url = sc_json_get_string(r, "clone_url", "?");

    char result[1024];
    snprintf(result, sizeof(result),
             "Created repo: %s\nURL: %s\nClone: %s",
             full_name, html_url, clone_url);
    cJSON_Delete(r);
    return sc_tool_result_new(result);
}

static sc_tool_result_t *
cmd_list_repos(gitea_data_t *gd, cJSON *args)
{
    const char *org = sc_json_get_string(args, "org", gd->default_org);

    char path[256];
    if (org && org[0])
        snprintf(path, sizeof(path), "/api/v1/orgs/%s/repos?limit=50", org);
    else
        snprintf(path, sizeof(path), "/api/v1/user/repos?limit=50");

    long code = 0;
    char *resp = gitea_request(gd, "GET", path, NULL, &code);
    if (!resp || code != 200) {
        free(resp);
        return sc_tool_result_error("Failed to list repos");
    }

    cJSON *arr = cJSON_Parse(resp);
    free(resp);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return sc_tool_result_error("Invalid response");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    int count = cJSON_GetArraySize(arr);
    sc_strbuf_appendf(&sb, "%d repo(s):\n", count);

    cJSON *repo;
    cJSON_ArrayForEach(repo, arr) {
        const char *fn = sc_json_get_string(repo, "full_name", "?");
        const char *desc = sc_json_get_string(repo, "description", "");
        const char *url = sc_json_get_string(repo, "html_url", "");
        sc_strbuf_appendf(&sb, "  %s — %s (%s)\n", fn, desc, url);
    }

    cJSON_Delete(arr);
    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

static sc_tool_result_t *
cmd_create_pr(gitea_data_t *gd, cJSON *args)
{
    const char *repo = sc_json_get_string(args, "repo", NULL);
    const char *title = sc_json_get_string(args, "title", NULL);
    const char *head = sc_json_get_string(args, "head", NULL);
    const char *base = sc_json_get_string(args, "base", "main");
    const char *pr_body = sc_json_get_string(args, "body", "");

    if (!repo || !title || !head)
        return sc_tool_result_error("'repo', 'title', and 'head' are required");

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "title", title);
    cJSON_AddStringToObject(body, "head", head);
    cJSON_AddStringToObject(body, "base", base);
    cJSON_AddStringToObject(body, "body", pr_body);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    char path[256];
    snprintf(path, sizeof(path), "/api/v1/repos/%s/pulls", repo);

    long code = 0;
    char *resp = gitea_request(gd, "POST", path, body_str, &code);
    free(body_str);

    if (!resp || code != 201) {
        char buf[512];
        cJSON *err = resp ? cJSON_Parse(resp) : NULL;
        const char *msg = err ? sc_json_get_string(err, "message", resp) : "network error";
        snprintf(buf, sizeof(buf), "Failed to create PR (HTTP %ld): %s",
                 code, msg);
        cJSON_Delete(err);
        free(resp);
        return sc_tool_result_error(buf);
    }

    cJSON *r = cJSON_Parse(resp);
    free(resp);
    if (!r) return sc_tool_result_error("Invalid JSON response");

    int number = sc_json_get_int(r, "number", 0);
    const char *url = sc_json_get_string(r, "html_url", "?");
    char result[512];
    snprintf(result, sizeof(result), "Created PR #%d: %s\nURL: %s",
             number, title, url);
    cJSON_Delete(r);
    return sc_tool_result_new(result);
}

static sc_tool_result_t *
cmd_list_prs(gitea_data_t *gd, cJSON *args)
{
    const char *repo = sc_json_get_string(args, "repo", NULL);
    if (!repo)
        return sc_tool_result_error("'repo' is required");

    char path[256];
    snprintf(path, sizeof(path), "/api/v1/repos/%s/pulls?state=open&limit=20",
             repo);

    long code = 0;
    char *resp = gitea_request(gd, "GET", path, NULL, &code);
    if (!resp || code != 200) {
        free(resp);
        return sc_tool_result_error("Failed to list PRs");
    }

    cJSON *arr = cJSON_Parse(resp);
    free(resp);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return sc_tool_result_error("Invalid response");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    int count = cJSON_GetArraySize(arr);
    sc_strbuf_appendf(&sb, "%d open PR(s) in %s:\n", count, repo);

    cJSON *pr;
    cJSON_ArrayForEach(pr, arr) {
        int num = sc_json_get_int(pr, "number", 0);
        const char *t = sc_json_get_string(pr, "title", "?");
        const char *state = sc_json_get_string(pr, "state", "?");
        const char *head_ref = "";
        cJSON *h = cJSON_GetObjectItem(pr, "head");
        if (h) head_ref = sc_json_get_string(h, "ref", "?");
        sc_strbuf_appendf(&sb, "  #%d [%s] %s ← %s\n", num, state, t, head_ref);
    }

    cJSON_Delete(arr);
    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

static sc_tool_result_t *
cmd_create_issue(gitea_data_t *gd, cJSON *args)
{
    const char *repo = sc_json_get_string(args, "repo", NULL);
    const char *title = sc_json_get_string(args, "title", NULL);
    const char *issue_body = sc_json_get_string(args, "body", "");

    if (!repo || !title)
        return sc_tool_result_error("'repo' and 'title' are required");

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "title", title);
    cJSON_AddStringToObject(body, "body", issue_body);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    char path[256];
    snprintf(path, sizeof(path), "/api/v1/repos/%s/issues", repo);

    long code = 0;
    char *resp = gitea_request(gd, "POST", path, body_str, &code);
    free(body_str);

    if (!resp || code != 201) {
        free(resp);
        return sc_tool_result_error("Failed to create issue");
    }

    cJSON *r = cJSON_Parse(resp);
    free(resp);
    if (!r) return sc_tool_result_error("Invalid JSON response");

    int number = sc_json_get_int(r, "number", 0);
    const char *url = sc_json_get_string(r, "html_url", "?");
    char result[512];
    snprintf(result, sizeof(result), "Created issue #%d: %s\nURL: %s",
             number, title, url);
    cJSON_Delete(r);
    return sc_tool_result_new(result);
}

static sc_tool_result_t *
cmd_list_issues(gitea_data_t *gd, cJSON *args)
{
    const char *repo = sc_json_get_string(args, "repo", NULL);
    if (!repo)
        return sc_tool_result_error("'repo' is required");

    char path[256];
    snprintf(path, sizeof(path),
             "/api/v1/repos/%s/issues?state=open&type=issues&limit=20", repo);

    long code = 0;
    char *resp = gitea_request(gd, "GET", path, NULL, &code);
    if (!resp || code != 200) {
        free(resp);
        return sc_tool_result_error("Failed to list issues");
    }

    cJSON *arr = cJSON_Parse(resp);
    free(resp);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return sc_tool_result_error("Invalid response");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    int count = cJSON_GetArraySize(arr);
    sc_strbuf_appendf(&sb, "%d open issue(s) in %s:\n", count, repo);

    cJSON *issue;
    cJSON_ArrayForEach(issue, arr) {
        int num = sc_json_get_int(issue, "number", 0);
        const char *t = sc_json_get_string(issue, "title", "?");
        sc_strbuf_appendf(&sb, "  #%d %s\n", num, t);
    }

    cJSON_Delete(arr);
    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

static sc_tool_result_t *
cmd_add_comment(gitea_data_t *gd, cJSON *args)
{
    const char *repo = sc_json_get_string(args, "repo", NULL);
    const char *type = sc_json_get_string(args, "type", "issue");
    int id = sc_json_get_int(args, "id", 0);
    const char *comment_body = sc_json_get_string(args, "body", NULL);

    if (!repo || id <= 0 || !comment_body)
        return sc_tool_result_error("'repo', 'id', and 'body' are required");

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "body", comment_body);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    /* PRs and issues share the same comment endpoint in Gitea */
    char path[256];
    if (strcmp(type, "pr") == 0 || strcmp(type, "pull") == 0)
        snprintf(path, sizeof(path),
                 "/api/v1/repos/%s/issues/%d/comments", repo, id);
    else
        snprintf(path, sizeof(path),
                 "/api/v1/repos/%s/issues/%d/comments", repo, id);

    long code = 0;
    char *resp = gitea_request(gd, "POST", path, body_str, &code);
    free(body_str);

    if (!resp || code != 201) {
        free(resp);
        return sc_tool_result_error("Failed to add comment");
    }

    free(resp);
    char result[256];
    snprintf(result, sizeof(result), "Comment added to %s #%d in %s",
             type, id, repo);
    return sc_tool_result_new(result);
}

/* ------------------------------------------------------------------ */
/*  Tool vtable                                                        */
/* ------------------------------------------------------------------ */

static cJSON *
gitea_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON_AddStringToObject(action, "description",
        "Action: create_repo, list_repos, create_pr, list_prs, "
        "create_issue, list_issues, add_comment");

    cJSON *name = cJSON_AddObjectToObject(props, "name");
    cJSON_AddStringToObject(name, "type", "string");
    cJSON_AddStringToObject(name, "description",
        "Repository name (for create_repo)");

    cJSON *repo = cJSON_AddObjectToObject(props, "repo");
    cJSON_AddStringToObject(repo, "type", "string");
    cJSON_AddStringToObject(repo, "description",
        "Repository full name, e.g. 'agents/wgctl' "
        "(for PRs, issues, comments)");

    cJSON *org = cJSON_AddObjectToObject(props, "org");
    cJSON_AddStringToObject(org, "type", "string");
    cJSON_AddStringToObject(org, "description",
        "Organization name (for create_repo, list_repos). "
        "Uses default org if omitted.");

    cJSON *description = cJSON_AddObjectToObject(props, "description");
    cJSON_AddStringToObject(description, "type", "string");
    cJSON_AddStringToObject(description, "description",
        "Description (for create_repo)");

    cJSON *title = cJSON_AddObjectToObject(props, "title");
    cJSON_AddStringToObject(title, "type", "string");
    cJSON_AddStringToObject(title, "description",
        "Title (for create_pr, create_issue)");

    cJSON *head = cJSON_AddObjectToObject(props, "head");
    cJSON_AddStringToObject(head, "type", "string");
    cJSON_AddStringToObject(head, "description",
        "Source branch (for create_pr)");

    cJSON *base = cJSON_AddObjectToObject(props, "base");
    cJSON_AddStringToObject(base, "type", "string");
    cJSON_AddStringToObject(base, "description",
        "Target branch (for create_pr, default: main)");

    cJSON *body = cJSON_AddObjectToObject(props, "body");
    cJSON_AddStringToObject(body, "type", "string");
    cJSON_AddStringToObject(body, "description",
        "Body text (for create_pr, create_issue, add_comment)");

    cJSON *type = cJSON_AddObjectToObject(props, "type");
    cJSON_AddStringToObject(type, "type", "string");
    cJSON_AddStringToObject(type, "description",
        "Comment target type: 'issue' or 'pr' (for add_comment)");

    cJSON *id = cJSON_AddObjectToObject(props, "id");
    cJSON_AddStringToObject(id, "type", "integer");
    cJSON_AddStringToObject(id, "description",
        "Issue or PR number (for add_comment)");

    cJSON *required = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(required, cJSON_CreateString("action"));

    return schema;
}

static sc_tool_result_t *
gitea_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    gitea_data_t *gd = self->data;

    if (!gd->api_url || !gd->api_token)
        return sc_tool_result_error(
            "Gitea not configured (missing url or token)");

    const char *action = sc_json_get_string(args, "action", NULL);
    if (!action || !action[0])
        return sc_tool_result_error("'action' is required");

    if (strcmp(action, "create_repo") == 0)
        return cmd_create_repo(gd, args);
    if (strcmp(action, "list_repos") == 0)
        return cmd_list_repos(gd, args);
    if (strcmp(action, "create_pr") == 0)
        return cmd_create_pr(gd, args);
    if (strcmp(action, "list_prs") == 0)
        return cmd_list_prs(gd, args);
    if (strcmp(action, "create_issue") == 0)
        return cmd_create_issue(gd, args);
    if (strcmp(action, "list_issues") == 0)
        return cmd_list_issues(gd, args);
    if (strcmp(action, "add_comment") == 0)
        return cmd_add_comment(gd, args);

    char buf[128];
    snprintf(buf, sizeof(buf), "Unknown action: %s", action);
    return sc_tool_result_error(buf);
}

static void
gitea_destroy(sc_tool_t *self)
{
    if (!self) return;
    gitea_data_t *gd = self->data;
    if (gd) {
        free(gd->api_url);
        free(gd->api_token);
        free(gd->default_org);
        free(gd);
    }
    free(self);
}

/* ------------------------------------------------------------------ */
/*  Factory                                                            */
/* ------------------------------------------------------------------ */

sc_tool_t *
sc_tool_gitea_new(const char *api_url, const char *api_token,
                   const char *default_org)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    gitea_data_t *gd = calloc(1, sizeof(*gd));
    if (!gd) { free(t); return NULL; }

    if (api_url)     gd->api_url     = sc_strdup(api_url);
    if (api_token)   gd->api_token   = sc_strdup(api_token);
    if (default_org) gd->default_org = sc_strdup(default_org);

    t->name        = "gitea";
    t->description = "Gitea API — create repos, issues, PRs, and comments";
    t->parameters  = gitea_parameters;
    t->execute     = gitea_execute;
    t->set_context = NULL;
    t->destroy     = gitea_destroy;
    t->needs_confirm = 0;
    t->data        = gd;

    return t;
}
