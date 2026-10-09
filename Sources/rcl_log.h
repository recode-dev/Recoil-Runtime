// rcl_log.h - logging for the runtime offset searcher.
//
// Writes to a file (so the result survives a crash and can be pulled off the device) and mirrors to
// os_log when available. POSIX-only core, so it also builds on the host.
#ifndef RCL_LOG_H
#define RCL_LOG_H

#include <stdarg.h>

namespace rcl {

// Opens the log file. `dir` defaults to the app's Documents directory on device, "." on host.
// Returns the path actually used (empty on failure).
void log_open(const char *dir);
bool log_is_open();
void log_close();
void log_printf(const char *fmt, ...);

} // namespace rcl

#define RCL_LOG(...) ::rcl::log_printf(__VA_ARGS__)
#define RCL_LOGLN(...) do { ::rcl::log_printf(__VA_ARGS__); ::rcl::log_printf("\n"); } while (0)

#endif
