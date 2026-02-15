/*
 * smolclaw - workspace extraction
 * Writes embedded workspace template files to disk.
 */

#include "workspace.h"
#include "workspace_data.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int sc_workspace_extract(const char *target_dir)
{
    if (!target_dir) return -1;

    for (int i = 0; i < sc_workspace_file_count; i++) {
        const sc_workspace_file_t *wf = &sc_workspace_files[i];
        if (!wf->name || !wf->data) continue;

        /* Build full path */
        size_t len = strlen(target_dir) + 1 + strlen(wf->name) + 1;
        char *path = malloc(len);
        if (!path) continue;
        snprintf(path, len, "%s/%s", target_dir, wf->name);

        /* Skip if file already exists */
        struct stat st;
        if (stat(path, &st) == 0) {
            free(path);
            continue;
        }

        /* Create parent directories if needed */
        char *slash = strrchr(path, '/');
        if (slash && slash != path) {
            char saved = *slash;
            *slash = '\0';
            mkdir(path, 0755);
            *slash = saved;
        }

        FILE *fp = fopen(path, "wb");
        if (fp) {
            fwrite(wf->data, 1, wf->size, fp);
            fclose(fp);
        }
        free(path);
    }

    return 0;
}
