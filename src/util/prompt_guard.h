#ifndef SC_PROMPT_GUARD_H
#define SC_PROMPT_GUARD_H

/* Scan text for prompt injection patterns.
 * Returns count of injection patterns found (0 = clean).
 * Detection only — does not modify the text. */
int sc_prompt_guard_scan(const char *text);

/* Scan text for high-confidence prompt injection patterns.
 * Returns 1 if definite injection attempt detected, 0 otherwise.
 * Used to trigger active warnings (not just audit logging). */
int sc_prompt_guard_scan_high(const char *text);

#endif /* SC_PROMPT_GUARD_H */
