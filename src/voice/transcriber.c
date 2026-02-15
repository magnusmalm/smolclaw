/*
 * voice/transcriber.c - Groq Whisper audio transcription
 *
 * Sends audio files to the Groq Whisper API via multipart form upload
 * and returns the transcribed text. Uses libcurl for HTTP.
 */

#include "voice/transcriber.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"

#define VOICE_TAG "voice"
#define WHISPER_MODEL "whisper-large-v3"

struct sc_transcriber {
    char *api_key;
    char *api_base;
};

/* CURL write callback */
static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    sc_strbuf_t *sb = userp;
    char *buf = malloc(total + 1);
    if (!buf) return 0;
    memcpy(buf, data, total);
    buf[total] = '\0';
    sc_strbuf_append(sb, buf);
    free(buf);
    return total;
}

/* CURL write-to-file callback */
static size_t write_file_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    FILE *fp = userp;
    return fwrite(data, size, nmemb, fp);
}

sc_transcriber_t *sc_transcriber_new(const char *api_key, const char *api_base)
{
    if (!api_key || api_key[0] == '\0') return NULL;

    sc_transcriber_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->api_key = sc_strdup(api_key);
    t->api_base = sc_strdup(api_base && api_base[0]
                            ? api_base : "https://api.groq.com/openai/v1");
    SC_LOG_INFO(VOICE_TAG, "Groq Whisper transcriber initialized");
    return t;
}

void sc_transcriber_free(sc_transcriber_t *t)
{
    if (!t) return;
    free(t->api_key);
    free(t->api_base);
    free(t);
}

int sc_transcriber_is_available(const sc_transcriber_t *t)
{
    return (t && t->api_key && t->api_key[0] != '\0');
}

char *sc_transcribe(sc_transcriber_t *t, const char *file_path)
{
    if (!t || !t->api_key || !file_path) return NULL;

    SC_LOG_INFO(VOICE_TAG, "Transcribing: %s", file_path);

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    /* Build Authorization header */
    sc_strbuf_t auth_buf;
    sc_strbuf_init(&auth_buf);
    sc_strbuf_appendf(&auth_buf, "Authorization: Bearer %s", t->api_key);
    char *auth_header = sc_strbuf_finish(&auth_buf);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);

    /* Multipart form: file + model + response_format */
    curl_mime *mime = curl_mime_init(curl);

    curl_mimepart *file_part = curl_mime_addpart(mime);
    curl_mime_name(file_part, "file");
    curl_mime_filedata(file_part, file_path);

    curl_mimepart *model_part = curl_mime_addpart(mime);
    curl_mime_name(model_part, "model");
    curl_mime_data(model_part, WHISPER_MODEL, CURL_ZERO_TERMINATED);

    curl_mimepart *fmt_part = curl_mime_addpart(mime);
    curl_mime_name(fmt_part, "response_format");
    curl_mime_data(fmt_part, "json", CURL_ZERO_TERMINATED);

    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s/audio/transcriptions", t->api_base);
    char *url = sc_strbuf_finish(&url_buf);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    free(auth_header);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(VOICE_TAG, "Transcription request failed: %s",
                     curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *response = sc_strbuf_finish(&resp);

    if (http_code != 200) {
        SC_LOG_ERROR(VOICE_TAG, "Transcription API error (HTTP %ld): %.200s",
                     http_code, response ? response : "");
        free(response);
        return NULL;
    }

    /* Parse JSON response for "text" field */
    cJSON *json = cJSON_Parse(response);
    free(response);

    if (!json) {
        SC_LOG_ERROR(VOICE_TAG, "Failed to parse transcription response");
        return NULL;
    }

    cJSON *text = cJSON_GetObjectItem(json, "text");
    char *result = NULL;
    if (text && cJSON_IsString(text) && text->valuestring[0] != '\0') {
        result = sc_strdup(text->valuestring);
        char *preview = sc_truncate(result, 120);
        SC_LOG_INFO(VOICE_TAG, "Transcription result: %s", preview ? preview : result);
        free(preview);
    } else {
        SC_LOG_WARN(VOICE_TAG, "Transcription returned empty text");
    }

    cJSON_Delete(json);
    return result;
}

char *sc_download_to_temp(const char *url, const char *auth_header)
{
    if (!url) return NULL;

    /* Scheme validation */
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        SC_LOG_ERROR(VOICE_TAG, "Invalid URL scheme for download");
        return NULL;
    }

    /* Create temp file */
    char tmp_path[] = "/tmp/smolclaw_audio_XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        SC_LOG_ERROR(VOICE_TAG, "Failed to create temp file");
        return NULL;
    }

    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        return NULL;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fclose(fp);
        remove(tmp_path);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)SC_DOWNLOAD_MAX_SIZE);

    struct curl_slist *headers = NULL;
    if (auth_header && auth_header[0]) {
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    fclose(fp);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(VOICE_TAG, "Download failed: %s", curl_easy_strerror(res));
        remove(tmp_path);
        return NULL;
    }

    SC_LOG_DEBUG(VOICE_TAG, "Downloaded to %s", tmp_path);
    return sc_strdup(tmp_path);
}
