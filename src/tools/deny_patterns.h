/*
 * tools/deny_patterns.h - Shared deny patterns for shell/background tools
 *
 * POSIX extended regex patterns that block dangerous shell commands.
 * Included by shell.c and background.c. Matched against lowercased input.
 */

#ifndef SC_DENY_PATTERNS_H
#define SC_DENY_PATTERNS_H

static const char *sc_deny_patterns[] = {
    /* Original patterns — destructive commands */
    "\\brm[[:space:]]+-[rf]{1,2}\\b",
    "\\bdel[[:space:]]+/[fq]\\b",
    "\\brmdir[[:space:]]+/s\\b",
    "\\b(format|mkfs|diskpart)\\b[[:space:]]",
    "\\bdd[[:space:]]+if=",
    ">[[:space:]]*/dev/sd[a-z]\\b",
    "\\b(shutdown|reboot|poweroff)\\b",
    ":\\(\\)[[:space:]]*\\{",

    /* Absolute path bypass */
    "/bin/rm[[:space:]]+-[rf]",
    "/usr/bin/rm[[:space:]]+-[rf]",

    /* Indirect execution via scripting languages */
    "\\bpython[23]?[[:space:]]+-c\\b",
    "\\bperl[[:space:]]+-e\\b",
    "\\bruby[[:space:]]+-e\\b",
    "\\bnode[[:space:]]+-e\\b",

    /* Pipe to shell (download-and-exec, base64 decode) */
    "\\|[[:space:]]*(ba)?sh\\b",

    /* Reverse shells / network exfil */
    "\\bnc[[:space:]]+-[el]",
    "\\bncat[[:space:]]",
    "/dev/tcp/",

    /* Privilege escalation */
    "\\bsudo[[:space:]]",
    "\\bsu[[:space:]]+-",
    "\\bchmod[[:space:]].*777\\b",

    /* Dangerous file operations targeting system dirs */
    ">[[:space:]]*/etc/",
    "\\bcp[[:space:]].*[[:space:]]/etc/",

    /* Process killing */
    "\\bkillall[[:space:]]",
    "\\bpkill[[:space:]]",

    /* System crontab manipulation */
    "\\bcrontab[[:space:]]",

    /* Indirect execution / evasion */
    "\\beval[[:space:]]",
    "\\bsource[[:space:]]",
    "\\b\\.[[:space:]]+/",                      /* . /path (source alias) */
    "\\$'[^']*\\\\[0-9x][^']*'",               /* $'\162\155' bash octal/hex */
    /* Variable expansion evasion */
    "\\$[{(]?[a-z_]+[})]?[[:space:]]+-[rf]",
    /* Destructive commands missing from current list */
    "\\bfind[[:space:]].*-delete\\b",
    "\\bfind[[:space:]].*-exec[[:space:]].*rm\\b",
    "\\btruncate[[:space:]]+-s[[:space:]]+0\\b",
    "\\bshred[[:space:]]",
    /* Data exfiltration */
    "\\bcurl[[:space:]].*-d[[:space:]]*@",
    "\\bcurl[[:space:]].*--data[[:space:]]*@",
    "\\bwget[[:space:]].*--post-file",
    /* Reverse shells / network tools */
    "\\bsocat[[:space:]]",
    /* Preload injection */
    "\\bld_preload=",
    /* su without hyphen (su root, su username) */
    "\\bsu[[:space:]]+root\\b",
    "\\bsu[[:space:]]+[a-z]",
    /* System writes via tee */
    "\\btee[[:space:]].*(/etc/|/proc/|/sys/)",
    /* System control */
    "\\bsystemctl[[:space:]]",
    /* Command substitution (prevents deny pattern evasion) */
    "`",
    "\\$\\(",
    /* sh/bash -c (direct shell interpreter invocation) */
    "\\b(ba)?sh[[:space:]]+-c\\b",
    /* Pipe to interpreters beyond sh/bash */
    "\\|[[:space:]]*(python[23]?|perl|ruby|node|php)\\b",
    /* xargs as rm proxy */
    "\\bxargs[[:space:]].*\\brm\\b",
    /* env as command prefix bypass */
    "\\benv[[:space:]].*\\b(rm|dd|mkfs|shutdown|reboot)\\b",
    /* busybox wrapping dangerous commands */
    "\\bbusybox[[:space:]].*\\b(rm|dd|mkfs)\\b",
    /* Heredoc to shell */
    "\\b(ba)?sh[[:space:]]*<<",
    /* base64 decode piped to execution */
    "\\bbase64[[:space:]]+-d\\b.*\\|",
    /* wget -O - piped to execution */
    "\\bwget[[:space:]].*-O[[:space:]]*-.*\\|",
    /* IFS variable evasion (rm${IFS}-rf → rm -rf) */
    "\\$\\{?ifs\\}?",
    /* Glob chars adjacent to dangerous commands (r? → rm, r* → rm) */
    "\\br[?*\\[]",
    /* Inline IFS assignment before command */
    "\\bifs=[^[:space:]]*[[:space:]]+",
    /* mv to system directories */
    "\\bmv[[:space:]].*/(etc|bin|sbin|usr|boot|dev|proc|sys)/",
    /* ln (symlink/hardlink creation — LLM should use write_file) */
    "\\bln[[:space:]]",
    /* kill with signal (kill -9, kill -TERM, kill -s) */
    "\\bkill[[:space:]]+-[0-9]",
    "\\bkill[[:space:]]+-s[[:space:]]",
    /* tar extraction to system dirs (covers -x, x, --extract, -C, C) */
    "\\btar[[:space:]].*[[:space:]-][xC].*/(etc|bin|sbin|usr)/",
    /* chown/chgrp */
    "\\bchown[[:space:]]",
    "\\bchgrp[[:space:]]",
    /* mount/umount */
    "\\b(u?mount)[[:space:]]",
    /* docker/podman (container escape/control) */
    "\\b(docker|podman)[[:space:]]",
    /* iptables/firewall */
    "\\b(iptables|ip6tables|ufw|nft)[[:space:]]",
    /* sed -i to system paths */
    "\\bsed[[:space:]]+-i.*/(etc|bin|sbin|usr)/",
    /* rsync/scp data exfiltration (remote targets with @) */
    "\\b(rsync|scp)[[:space:]].*@",
    /* Debug/scanning tools */
    "\\b(strace|ltrace|nmap)[[:space:]]",
    /* Package managers (system modification) */
    "\\b(apt-get|apt|yum|dnf|pacman|pip|npm)[[:space:]]+(install|remove|purge|upgrade)\\b",
    /* Read sensitive system files via cat/head/tail */
    "\\b(cat|head|tail|less|more)[[:space:]].*/(etc/(shadow|passwd|sudoers)|\\.ssh/)",
    /* Brace expansion evasion ({rm,-rf,/} → rm -rf / in bash) */
    "\\{[^}]*(rm|dd|mkfs|chmod|chown|kill|shutdown)[^}]*\\}",
    /* awk/gawk system() call */
    "\\b(g?awk|mawk)[[:space:]].*system[[:space:]]*\\(",
    /* printf format string abuse for command execution */
    "\\bprintf[[:space:]].*\\\\x[0-9a-f]",
    /* Pipe to awk/gawk (command execution via awk) */
    "\\|[[:space:]]*(g?awk|mawk)\\b",
    /* Archive extraction (overwrite attacks, extraction to system dirs) */
    "\\bunzip[[:space:]].*-o",
    "\\bunzip[[:space:]].*-d[[:space:]]*/(etc|bin|sbin|usr|boot)/",
    "\\bcpio[[:space:]]",
    "\\b7z[[:space:]]+x\\b",
    /* Mail exfiltration (data sent to arbitrary recipients) */
    "\\b(sendmail|mailx?|msmtp|mutt)[[:space:]]",
    /* Dangerous commands missing from blocklist (H-6) */
    "\\bexec[[:space:]]",                     /* replaces shell process */
    "\\bnsenter[[:space:]]",                  /* namespace escape */
    "\\bunshare[[:space:]]",                  /* namespace creation */
    "\\binstall[[:space:]].*/(etc|bin|sbin|usr)/",  /* install to system dirs */
    "\\bscript[[:space:]]",                   /* typescript session capture */
    "\\bscreen[[:space:]]",                   /* interactive terminal multiplexer */
    "\\btmux[[:space:]]",                     /* interactive terminal multiplexer */
    /* Writes to smolclaw config directory (prevent OpenClaw-style config destruction) */
    ">.*\\.smolclaw/",
    "\\b(cp|mv|tee|sed)[[:space:]].*\\.smolclaw/",
};

#define SC_DENY_PATTERN_COUNT \
    (sizeof(sc_deny_patterns) / sizeof(sc_deny_patterns[0]))

#endif /* SC_DENY_PATTERNS_H */
