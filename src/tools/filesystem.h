#ifndef SC_TOOL_FILESYSTEM_H
#define SC_TOOL_FILESYSTEM_H

#include "tools/types.h"

sc_tool_t *sc_tool_read_file_new(const char *workspace, int restrict_to_ws);
sc_tool_t *sc_tool_write_file_new(const char *workspace, int restrict_to_ws);
sc_tool_t *sc_tool_list_dir_new(const char *workspace, int restrict_to_ws);
sc_tool_t *sc_tool_edit_file_new(const char *workspace, int restrict_to_ws);
sc_tool_t *sc_tool_append_file_new(const char *workspace, int restrict_to_ws);

#endif /* SC_TOOL_FILESYSTEM_H */
