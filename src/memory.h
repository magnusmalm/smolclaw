#ifndef SC_MEMORY_H
#define SC_MEMORY_H

/* Index update callback: called after successful writes */
typedef void (*sc_memory_index_cb)(const char *source, const char *content,
                                   void *ctx);

/* Memory store for long-term memory and daily notes */
typedef struct sc_memory {
    char *workspace;
    char *memory_dir;   /* {workspace}/memory/ */
    char *memory_file;  /* {workspace}/memory/MEMORY.md */
    sc_memory_index_cb index_cb;
    void *index_ctx;
} sc_memory_t;

/* Create/destroy */
sc_memory_t *sc_memory_new(const char *workspace);
void sc_memory_free(sc_memory_t *mem);

/* Long-term memory */
char *sc_memory_read_long_term(const sc_memory_t *mem);
int sc_memory_write_long_term(const sc_memory_t *mem, const char *content);

/* Daily notes */
char *sc_memory_read_today(const sc_memory_t *mem);
int sc_memory_append_today(const sc_memory_t *mem, const char *content);

/* Get recent daily notes (last N days). Caller owns result. */
char *sc_memory_get_recent_notes(const sc_memory_t *mem, int days);

/* Build memory context for system prompt. Caller owns result. */
char *sc_memory_get_context(const sc_memory_t *mem);

/* Set index update callback (called after write_long_term / append_today) */
void sc_memory_set_index_cb(sc_memory_t *mem, sc_memory_index_cb cb, void *ctx);

#endif /* SC_MEMORY_H */
