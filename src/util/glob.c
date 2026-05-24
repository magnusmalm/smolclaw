#include "glob.h"

#include <stddef.h>

int sc_glob_match(const char *pattern, const char *str)
{
    if (!pattern || !str) return 0;

    const char *p = pattern;
    const char *s = str;
    const char *star = NULL;
    const char *star_match = NULL;

    while (*s) {
        if (*p == '*') {
            star = ++p;
            star_match = s;
        } else if (*p == '?' || *p == *s) {
            p++;
            s++;
        } else if (star) {
            p = star;
            s = ++star_match;
        } else {
            return 0;
        }
    }

    while (*p == '*') p++;
    return *p == '\0';
}
