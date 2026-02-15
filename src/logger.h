#ifndef SC_LOGGER_H
#define SC_LOGGER_H

typedef enum {
    SC_LOG_DEBUG = 0,
    SC_LOG_INFO  = 1,
    SC_LOG_WARN  = 2,
    SC_LOG_ERROR = 3
} sc_log_level_t;

/* Initialize logger. Optional log_file path (NULL = stderr only). */
void sc_logger_init(const char *log_file);
void sc_logger_shutdown(void);
void sc_logger_set_level(sc_log_level_t level);
/* Open a persistent log file (can be called after init). */
void sc_logger_set_file(const char *log_path);

/* Core logging functions */
void sc_log(sc_log_level_t level, const char *component, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Convenience macros */
#define SC_LOG_DEBUG(comp, ...) sc_log(SC_LOG_DEBUG, comp, __VA_ARGS__)
#define SC_LOG_INFO(comp, ...)  sc_log(SC_LOG_INFO, comp, __VA_ARGS__)
#define SC_LOG_WARN(comp, ...)  sc_log(SC_LOG_WARN, comp, __VA_ARGS__)
#define SC_LOG_ERROR(comp, ...) sc_log(SC_LOG_ERROR, comp, __VA_ARGS__)

#endif /* SC_LOGGER_H */
