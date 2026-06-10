#ifndef SC_TOOLS_CAMERA_H
#define SC_TOOLS_CAMERA_H

#include "tools/types.h"

/*
 * Camera tool — capture stills, list motion-event captures, and
 * describe images via a remote vision model (ollama /api/chat).
 *
 * snap_command: argv prefix run without a shell; the output JPEG path
 *               is appended as the final argument
 *               (e.g. "rpicam-still -n --width 1280 --height 720 -o").
 * events_dir:   directory of motion-daemon captures, relative to the
 *               workspace (default "camera/motion").
 * vision_url:   base URL of an ollama-compatible vision endpoint
 *               (e.g. "http://10.100.0.3:11434"); NULL disables describe.
 * vision_model: model name for describe (e.g. "gemma4:e4b").
 */
sc_tool_t *sc_tool_camera_new(const char *workspace,
                              const char *snap_command,
                              const char *events_dir,
                              const char *vision_url,
                              const char *vision_model,
                              int vision_timeout_secs);

#endif /* SC_TOOLS_CAMERA_H */
