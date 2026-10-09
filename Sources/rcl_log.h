#ifndef RCL_LOG_H
#define RCL_LOG_H

#include <stdarg.h>

namespace rcl {

void log_open(const char *dir);
bool log_is_open();
void log_close();
void log_printf(const char *fmt, ...);

}

#define RCL_LOG(...) ::rcl::log_printf(__VA_ARGS__)
#define RCL_LOGLN(...) do { ::rcl::log_printf(__VA_ARGS__); ::rcl::log_printf("\n"); } while (0)

#endif
