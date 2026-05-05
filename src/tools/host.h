#ifndef SC_TOOL_HOST_H
#define SC_TOOL_HOST_H

#include "tools/types.h"

typedef struct sc_memory_index sc_memory_index_t;

/* host_status — read-only host and process status snapshot */
sc_tool_t *sc_tool_host_status_new(const char *workspace, int sandbox_enabled);
/* host_inventory — refresh slower-changing host inventory and persist context docs */
sc_tool_t *sc_tool_host_inventory_new(const char *workspace,
                                      sc_memory_index_t *idx,
                                      int sandbox_enabled);
/* host_trend — analyze retained host/process samples for leak/trend signals */
sc_tool_t *sc_tool_host_trend_new(const char *workspace);
/* Refresh workspace/context/host inventory artifacts. */
int sc_host_refresh_inventory_artifacts(const char *workspace,
                                        sc_memory_index_t *idx,
                                        int sandbox_enabled);
/* Record one retained host sample. If force is false, sampling is rate-limited. */
int sc_host_record_sample(const char *workspace, int force);
/* Shared retained-sample cadence used by tools and gateway sampler. */
int sc_host_sample_interval_sec(void);

#endif /* SC_TOOL_HOST_H */
