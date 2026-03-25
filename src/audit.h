#ifndef SC_AUDIT_H
#define SC_AUDIT_H

/* Initialize audit log (append mode). Call once at agent startup. */
void sc_audit_init(const char *log_path);

/* Close audit log file. */
void sc_audit_shutdown(void);

/* Log a tool execution event as a JSON line. */
void sc_audit_log(const char *tool, const char *args_summary,
                  int is_error, long ms);

/* Extended audit log with security event type, channel, and user info. */
void sc_audit_log_ext(const char *tool, const char *args_summary,
                      int is_error, long ms,
                      const char *channel, const char *user_id,
                      const char *event);

/* Log a tool execution with resource tracking (RSS delta in KB). */
void sc_audit_log_rss(const char *tool, const char *args_summary,
                      int is_error, long ms, long rss_delta_kb);

/* Set the current LLM model for inclusion in audit log entries. */
void sc_audit_set_model(const char *model);

#endif /* SC_AUDIT_H */
