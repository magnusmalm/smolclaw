/*
 * tools/x_tools.c - X (Twitter) read-only API tools
 *
 * x_get_tweet  — fetch a single tweet by ID
 * x_get_thread — fetch a conversation thread
 * x_search     — search recent tweets
 * x_get_user   — get user profile by username
 *
 * All read-only — never posts. Uses OAuth 1.0a via util/x_api.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tools/x_tools.h"
#include "tools/types.h"
#include "util/x_api.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

#define LOG_TAG "x-tools"

/* Validate tweet ID: digits only */
static int is_valid_tweet_id(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

/* Validate username: alphanumeric + underscore, max 15 chars */
static int is_valid_username(const char *s)
{
    if (!s || !*s) return 0;
    int len = 0;
    for (const char *p = s; *p; p++, len++)
        if (!isalnum((unsigned char)*p) && *p != '_') return 0;
    return len <= 15;
}

/* ---- Shared helpers ---- */

static sc_x_creds_t *creds_from_cfg(const sc_x_config_t *cfg)
{
    if (!cfg || !cfg->consumer_key || !cfg->access_token)
        return NULL;
    return sc_x_creds_new(cfg->consumer_key, cfg->consumer_secret,
                           cfg->access_token, cfg->access_token_secret,
                           cfg->api_base);
}

/* Find username for an author_id in the includes.users array */
static const char *find_username(cJSON *includes, const char *author_id)
{
    if (!includes || !author_id) return NULL;
    cJSON *users = cJSON_GetObjectItem(includes, "users");
    if (!users) return NULL;
    cJSON *user;
    cJSON_ArrayForEach(user, users) {
        const char *uid = sc_json_get_string(user, "id", NULL);
        if (uid && strcmp(uid, author_id) == 0)
            return sc_json_get_string(user, "name", NULL);
    }
    return NULL;
}

static const char *find_handle(cJSON *includes, const char *author_id)
{
    if (!includes || !author_id) return NULL;
    cJSON *users = cJSON_GetObjectItem(includes, "users");
    if (!users) return NULL;
    cJSON *user;
    cJSON_ArrayForEach(user, users) {
        const char *uid = sc_json_get_string(user, "id", NULL);
        if (uid && strcmp(uid, author_id) == 0)
            return sc_json_get_string(user, "username", NULL);
    }
    return NULL;
}

/* Check for API errors in response */
static char *check_api_error(cJSON *json)
{
    if (!json) return sc_strdup("X API request failed (no response)");
    cJSON *errors = cJSON_GetObjectItem(json, "errors");
    if (errors && cJSON_IsArray(errors)) {
        cJSON *first = cJSON_GetArrayItem(errors, 0);
        if (first) {
            const char *msg = sc_json_get_string(first, "message", "Unknown error");
            return sc_strdup(msg);
        }
    }
    /* Check for top-level error */
    const char *detail = sc_json_get_string(json, "detail", NULL);
    if (detail) return sc_strdup(detail);
    return NULL;
}

/* Format a tweet for display.
 * Prefers note_tweet.text (long tweets) or article content over the
 * truncated root-level text field. */
static void format_tweet(sc_strbuf_t *sb, cJSON *tweet, cJSON *includes)
{
    const char *text = sc_json_get_string(tweet, "text", "");
    const char *author_id = sc_json_get_string(tweet, "author_id", NULL);
    const char *created = sc_json_get_string(tweet, "created_at", "");
    const char *tweet_id = sc_json_get_string(tweet, "id", "");

    const char *name = find_username(includes, author_id);
    const char *handle = find_handle(includes, author_id);

    if (name && handle)
        sc_strbuf_appendf(sb, "%s (@%s)", name, handle);
    else if (handle)
        sc_strbuf_appendf(sb, "@%s", handle);
    else if (author_id)
        sc_strbuf_appendf(sb, "user:%s", author_id);

    if (created[0])
        sc_strbuf_appendf(sb, " · %s", created);
    sc_strbuf_appendf(sb, " [%s]", tweet_id);
    sc_strbuf_append(sb, "\n");

    /* Prefer full content: article > note_tweet > text */
    cJSON *article = cJSON_GetObjectItem(tweet, "article");
    cJSON *note = cJSON_GetObjectItem(tweet, "note_tweet");

    if (article && cJSON_IsObject(article)) {
        const char *title = sc_json_get_string(article, "title", NULL);
        const char *body = sc_json_get_string(article, "text", NULL);
        if (!body) body = sc_json_get_string(article, "body", NULL);
        if (!body) body = sc_json_get_string(article, "content", NULL);
        if (title)
            sc_strbuf_appendf(sb, "[Article] %s\n", title);
        else
            sc_strbuf_append(sb, "[Article]\n");
        if (body)
            sc_strbuf_appendf(sb, "%s\n", body);
        else {
            /* Dump article object for debugging if no known fields */
            char *raw = cJSON_Print(article);
            if (raw) {
                sc_strbuf_appendf(sb, "%s\n", raw);
                free(raw);
            } else {
                sc_strbuf_appendf(sb, "%s\n", text);
            }
        }
    } else if (note && cJSON_IsObject(note)) {
        const char *full_text = sc_json_get_string(note, "text", NULL);
        sc_strbuf_appendf(sb, "%s\n", full_text ? full_text : text);
    } else {
        sc_strbuf_appendf(sb, "%s\n", text);
    }

    /* Metrics */
    cJSON *metrics = cJSON_GetObjectItem(tweet, "public_metrics");
    if (metrics) {
        int likes = sc_json_get_int(metrics, "like_count", 0);
        int rts = sc_json_get_int(metrics, "retweet_count", 0);
        int replies = sc_json_get_int(metrics, "reply_count", 0);
        sc_strbuf_appendf(sb, "  %d likes · %d retweets · %d replies\n",
                          likes, rts, replies);
    }
}

/* ================================================================
 * x_get_tweet
 * ================================================================ */

static cJSON *get_tweet_params(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");
    cJSON *tid = cJSON_AddObjectToObject(props, "tweet_id");
    cJSON_AddStringToObject(tid, "type", "string");
    cJSON_AddStringToObject(tid, "description", "Tweet ID to fetch");
    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("tweet_id"));
    return schema;
}

static sc_tool_result_t *get_tweet_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    sc_x_creds_t *creds = self->data;
    const char *tweet_id = sc_json_get_string(args, "tweet_id", NULL);
    if (!tweet_id || !tweet_id[0])
        return sc_tool_result_error("tweet_id is required");
    if (!is_valid_tweet_id(tweet_id))
        return sc_tool_result_error("tweet_id must contain only digits");

    char path[128];
    snprintf(path, sizeof(path), "/2/tweets/%s", tweet_id);

    sc_x_param_t params[] = {
        { "tweet.fields", "author_id,created_at,text,public_metrics,"
                          "conversation_id,referenced_tweets,"
                          "note_tweet,article" },
        { "expansions", "author_id,referenced_tweets.id,"
                        "article.cover_media,article.media_entities" },
        { "user.fields", "username,name" },
    };

    cJSON *json = sc_x_api_get(creds, path, params, 3);
    if (!json)
        return sc_tool_result_error("X API request failed");

    char *err = check_api_error(json);
    if (err) {
        sc_tool_result_t *r = sc_tool_result_error(err);
        free(err);
        cJSON_Delete(json);
        return r;
    }

    cJSON *data = cJSON_GetObjectItem(json, "data");
    cJSON *includes = cJSON_GetObjectItem(json, "includes");
    if (!data) {
        cJSON_Delete(json);
        return sc_tool_result_error("Tweet not found");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    format_tweet(&sb, data, includes);

    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    cJSON_Delete(json);
    return r;
}

static void x_tool_destroy(sc_tool_t *self)
{
    if (!self) return;
    sc_x_creds_free(self->data);
    free(self);
}

sc_tool_t *sc_tool_x_get_tweet_new(const sc_x_config_t *cfg)
{
    sc_x_creds_t *creds = creds_from_cfg(cfg);
    if (!creds) return NULL;
    return sc_tool_new_simple(
        "x_get_tweet",
        "Fetch a tweet by ID from X (Twitter). Returns the tweet text, "
        "author, timestamp, and engagement metrics.",
        get_tweet_params, get_tweet_exec, x_tool_destroy, 0, creds);
}

/* ================================================================
 * x_get_thread
 * ================================================================ */

static cJSON *get_thread_params(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");
    cJSON *tid = cJSON_AddObjectToObject(props, "tweet_id");
    cJSON_AddStringToObject(tid, "type", "string");
    cJSON_AddStringToObject(tid, "description",
        "Tweet ID (root or any tweet in the thread)");
    cJSON *mr = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(mr, "type", "integer");
    cJSON_AddStringToObject(mr, "description",
        "Max tweets to return (default 20, max 100)");
    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("tweet_id"));
    return schema;
}

static sc_tool_result_t *get_thread_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    sc_x_creds_t *creds = self->data;
    const char *tweet_id = sc_json_get_string(args, "tweet_id", NULL);
    if (!tweet_id || !tweet_id[0])
        return sc_tool_result_error("tweet_id is required");
    if (!is_valid_tweet_id(tweet_id))
        return sc_tool_result_error("tweet_id must contain only digits");

    int max_results = sc_json_get_int(args, "max_results", 20);
    if (max_results < 10) max_results = 10;
    if (max_results > 100) max_results = 100;

    /* Step 1: Fetch the tweet to get its conversation_id */
    char path[128];
    snprintf(path, sizeof(path), "/2/tweets/%s", tweet_id);
    sc_x_param_t tweet_params[] = {
        { "tweet.fields", "conversation_id,author_id,created_at,text" },
        { "expansions", "author_id" },
        { "user.fields", "username,name" },
    };

    cJSON *tweet_json = sc_x_api_get(creds, path, tweet_params, 3);
    if (!tweet_json)
        return sc_tool_result_error("Failed to fetch tweet");

    char *err = check_api_error(tweet_json);
    if (err) {
        sc_tool_result_t *r = sc_tool_result_error(err);
        free(err);
        cJSON_Delete(tweet_json);
        return r;
    }

    cJSON *tweet_data = cJSON_GetObjectItem(tweet_json, "data");
    if (!tweet_data) {
        cJSON_Delete(tweet_json);
        return sc_tool_result_error("Tweet not found");
    }

    const char *conv_id = sc_json_get_string(tweet_data, "conversation_id", NULL);
    if (!conv_id) {
        /* No conversation_id — standalone tweet */
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_append(&sb, "Single tweet (no thread):\n\n");
        format_tweet(&sb, tweet_data, cJSON_GetObjectItem(tweet_json, "includes"));
        char *result = sc_strbuf_finish(&sb);
        sc_tool_result_t *r = sc_tool_result_new(result);
        free(result);
        cJSON_Delete(tweet_json);
        return r;
    }

    /* Step 2: Search for conversation thread */
    char query[128];
    snprintf(query, sizeof(query), "conversation_id:%s", conv_id);
    char max_str[16];
    snprintf(max_str, sizeof(max_str), "%d", max_results);

    sc_x_param_t search_params[] = {
        { "query", query },
        { "max_results", max_str },
        { "tweet.fields", "author_id,created_at,text,in_reply_to_user_id" },
        { "expansions", "author_id" },
        { "user.fields", "username,name" },
    };

    cJSON *search_json = sc_x_api_get(creds, "/2/tweets/search/recent",
                                       search_params, 5);
    cJSON_Delete(tweet_json);

    if (!search_json)
        return sc_tool_result_error("Thread search failed");

    err = check_api_error(search_json);
    if (err) {
        sc_tool_result_t *r = sc_tool_result_error(err);
        free(err);
        cJSON_Delete(search_json);
        return r;
    }

    cJSON *data_arr = cJSON_GetObjectItem(search_json, "data");
    cJSON *includes = cJSON_GetObjectItem(search_json, "includes");

    if (!data_arr || !cJSON_IsArray(data_arr) || cJSON_GetArraySize(data_arr) == 0) {
        cJSON_Delete(search_json);
        return sc_tool_result_new("Thread not found (may be older than 7 days)");
    }

    /* Reverse the array to show chronological order (API returns newest first) */
    int count = cJSON_GetArraySize(data_arr);
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Thread (%d tweets, conversation %s):\n\n", count, conv_id);

    for (int i = count - 1; i >= 0; i--) {
        cJSON *tweet = cJSON_GetArrayItem(data_arr, i);
        format_tweet(&sb, tweet, includes);
        if (i > 0) sc_strbuf_append(&sb, "\n---\n\n");
    }

    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    cJSON_Delete(search_json);
    return r;
}

sc_tool_t *sc_tool_x_get_thread_new(const sc_x_config_t *cfg)
{
    sc_x_creds_t *creds = creds_from_cfg(cfg);
    if (!creds) return NULL;
    return sc_tool_new_simple(
        "x_get_thread",
        "Fetch a conversation thread from X (Twitter). Given a tweet ID, "
        "retrieves all recent tweets in the same conversation.",
        get_thread_params, get_thread_exec, x_tool_destroy, 0, creds);
}

/* ================================================================
 * x_search
 * ================================================================ */

static cJSON *search_params(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");
    cJSON *q = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(q, "type", "string");
    cJSON_AddStringToObject(q, "description",
        "Search query (X search syntax, e.g. 'from:user topic')");
    cJSON *mr = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(mr, "type", "integer");
    cJSON_AddStringToObject(mr, "description",
        "Max results to return (default 10, max 100)");
    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("query"));
    return schema;
}

static sc_tool_result_t *search_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    sc_x_creds_t *creds = self->data;
    const char *query = sc_json_get_string(args, "query", NULL);
    if (!query || !query[0])
        return sc_tool_result_error("query is required");

    int max_results = sc_json_get_int(args, "max_results", 10);
    if (max_results < 10) max_results = 10;
    if (max_results > 100) max_results = 100;

    char max_str[16];
    snprintf(max_str, sizeof(max_str), "%d", max_results);

    sc_x_param_t params[] = {
        { "query", (char *)query },
        { "max_results", max_str },
        { "tweet.fields", "author_id,created_at,text,public_metrics" },
        { "expansions", "author_id" },
        { "user.fields", "username,name" },
    };

    cJSON *json = sc_x_api_get(creds, "/2/tweets/search/recent", params, 5);
    if (!json)
        return sc_tool_result_error("X API search failed");

    char *err = check_api_error(json);
    if (err) {
        sc_tool_result_t *r = sc_tool_result_error(err);
        free(err);
        cJSON_Delete(json);
        return r;
    }

    cJSON *data = cJSON_GetObjectItem(json, "data");
    cJSON *includes = cJSON_GetObjectItem(json, "includes");

    if (!data || !cJSON_IsArray(data) || cJSON_GetArraySize(data) == 0) {
        cJSON_Delete(json);
        return sc_tool_result_new("No results found");
    }

    int count = cJSON_GetArraySize(data);
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Search results for '%s' (%d tweets):\n\n", query, count);

    int idx = 0;
    cJSON *tweet;
    cJSON_ArrayForEach(tweet, data) {
        sc_strbuf_appendf(&sb, "[%d] ", ++idx);
        format_tweet(&sb, tweet, includes);
        sc_strbuf_append(&sb, "\n");
    }

    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    cJSON_Delete(json);
    return r;
}

sc_tool_t *sc_tool_x_search_new(const sc_x_config_t *cfg)
{
    sc_x_creds_t *creds = creds_from_cfg(cfg);
    if (!creds) return NULL;
    return sc_tool_new_simple(
        "x_search",
        "Search recent tweets on X (Twitter). Supports X search syntax "
        "like 'from:username', '#hashtag', quoted phrases, etc.",
        search_params, search_exec, x_tool_destroy, 0, creds);
}

/* ================================================================
 * x_get_user
 * ================================================================ */

static cJSON *get_user_params(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");
    cJSON *u = cJSON_AddObjectToObject(props, "username");
    cJSON_AddStringToObject(u, "type", "string");
    cJSON_AddStringToObject(u, "description",
        "X username (without @ prefix)");
    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("username"));
    return schema;
}

static sc_tool_result_t *get_user_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    sc_x_creds_t *creds = self->data;
    const char *username = sc_json_get_string(args, "username", NULL);
    if (!username || !username[0])
        return sc_tool_result_error("username is required");

    /* Strip leading @ if present */
    if (username[0] == '@') username++;

    if (!is_valid_username(username))
        return sc_tool_result_error("username must be alphanumeric/underscore, max 15 chars");

    char path[256];
    snprintf(path, sizeof(path), "/2/users/by/username/%s", username);

    sc_x_param_t params[] = {
        { "user.fields", "description,public_metrics,created_at,"
                         "location,url,verified,profile_image_url" },
    };

    cJSON *json = sc_x_api_get(creds, path, params, 1);
    if (!json)
        return sc_tool_result_error("X API request failed");

    char *err = check_api_error(json);
    if (err) {
        sc_tool_result_t *r = sc_tool_result_error(err);
        free(err);
        cJSON_Delete(json);
        return r;
    }

    cJSON *data = cJSON_GetObjectItem(json, "data");
    if (!data) {
        cJSON_Delete(json);
        return sc_tool_result_error("User not found");
    }

    const char *name = sc_json_get_string(data, "name", "");
    const char *handle = sc_json_get_string(data, "username", username);
    const char *bio = sc_json_get_string(data, "description", "");
    const char *location = sc_json_get_string(data, "location", NULL);
    const char *url = sc_json_get_string(data, "url", NULL);
    const char *created = sc_json_get_string(data, "created_at", "");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s (@%s)\n", name, handle);
    if (bio[0])
        sc_strbuf_appendf(&sb, "%s\n", bio);
    if (location)
        sc_strbuf_appendf(&sb, "Location: %s\n", location);
    if (url)
        sc_strbuf_appendf(&sb, "URL: %s\n", url);
    if (created[0])
        sc_strbuf_appendf(&sb, "Joined: %s\n", created);

    cJSON *metrics = cJSON_GetObjectItem(data, "public_metrics");
    if (metrics) {
        int followers = sc_json_get_int(metrics, "followers_count", 0);
        int following = sc_json_get_int(metrics, "following_count", 0);
        int tweets = sc_json_get_int(metrics, "tweet_count", 0);
        sc_strbuf_appendf(&sb, "%d followers · %d following · %d tweets\n",
                          followers, following, tweets);
    }

    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    cJSON_Delete(json);
    return r;
}

sc_tool_t *sc_tool_x_get_user_new(const sc_x_config_t *cfg)
{
    sc_x_creds_t *creds = creds_from_cfg(cfg);
    if (!creds) return NULL;
    return sc_tool_new_simple(
        "x_get_user",
        "Get a user's profile from X (Twitter). Returns their bio, "
        "follower counts, join date, and other public information.",
        get_user_params, get_user_exec, x_tool_destroy, 0, creds);
}
