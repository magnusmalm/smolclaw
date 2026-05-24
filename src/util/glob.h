#ifndef SC_UTIL_GLOB_H
#define SC_UTIL_GLOB_H

/*
 * Minimal glob matcher used by config-driven pattern filters.
 *
 * Supports:
 *   *   matches zero or more characters
 *   ?   matches exactly one character
 *
 * Does NOT support character classes, escaping, or path separators
 * (treats every character uniformly). For richer matching, fall back
 * to fnmatch(3).
 *
 * Returns 1 on match, 0 on no match. NULL pattern or NULL str returns 0.
 * Empty pattern matches only an empty string.
 */
int sc_glob_match(const char *pattern, const char *str);

#endif /* SC_UTIL_GLOB_H */
