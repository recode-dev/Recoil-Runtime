#include "rcl_log.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

namespace rcl {

static int g_fd = -1;
static char g_path[512];
static char g_dir[512];

void log_open(const char *dir) {
    if (g_fd >= 0) return;
    const char *d = (dir && *dir) ? dir : ".";
    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    snprintf(g_path, sizeof g_path, "%s/recoil-runtime-%04d%02d%02d-%02d%02d%02d.log", d,
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    snprintf(g_dir, sizeof g_dir, "%s", d);
    g_fd = open(g_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

bool log_is_open() { return g_fd >= 0; }

const char *log_dir() { return g_dir; }

void log_close() {
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
}

void log_printf(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
    if (g_fd >= 0) {
        ssize_t r = write(g_fd, buf, (size_t)n);
        (void)r;
    }

    if (g_fd < 0 || getenv("RCL_STDERR")) fwrite(buf, 1, (size_t)n, stderr);
}

}
