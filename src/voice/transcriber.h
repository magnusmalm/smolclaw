#ifndef SC_VOICE_TRANSCRIBER_H
#define SC_VOICE_TRANSCRIBER_H

/*
 * Voice transcription via Groq Whisper API.
 * Sends audio files to the Groq API and returns transcribed text.
 */

typedef struct sc_transcriber sc_transcriber_t;

/* Create a transcriber with the given Groq API key and optional base URL.
 * If api_base is NULL/empty, defaults to "https://api.groq.com/openai/v1". */
sc_transcriber_t *sc_transcriber_new(const char *api_key, const char *api_base);

/* Free transcriber resources. */
void sc_transcriber_free(sc_transcriber_t *t);

/* Check if transcriber is available (has API key). */
int sc_transcriber_is_available(const sc_transcriber_t *t);

/* Transcribe audio file at path. Returns heap-allocated text, or NULL on error. */
char *sc_transcribe(sc_transcriber_t *t, const char *file_path);

/* Download a URL to a temporary file. Returns heap-allocated path, or NULL on error.
 * Caller must free the path AND delete the temp file when done. */
char *sc_download_to_temp(const char *url, const char *auth_header);

#endif /* SC_VOICE_TRANSCRIBER_H */
