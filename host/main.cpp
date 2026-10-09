// host/main.cpp - runs the shipped scanner over a Mach-O image on the host.
//
// The device dylib calls rcl::report_run() on live memory; this calls the very same function on the
// mapped file. Whatever this prints is what the dylib writes into its log on device, so the report
// format is verified before it ever runs on a phone.
//
//   make -C host && ./host/rclscan <image> [outdir]

#include "../Sources/rcl_scan.h"
#include "../Sources/rcl_report.h"
#include "../Sources/rcl_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

static std::vector<uint8_t> g_buf;

static bool buf_read(void *ctx, uint64_t va, void *dst, size_t n) {
    (void)ctx;
    const uint64_t base = 0x100000000ULL;
    if (va < base) return false;
    uint64_t off = va - base;
    if (off + n > g_buf.size()) return false;
    memcpy(dst, g_buf.data() + off, n);
    return true;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <image> [outdir]\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    g_buf.resize((size_t)sz);
    if (fread(g_buf.data(), 1, (size_t)sz, f) != (size_t)sz) { perror("read"); return 2; }
    fclose(f);

    rcl::Image img;
    img.base = 0x100000000ULL;
    img.vmsize = (uint64_t)sz;
    img.ctx = nullptr;
    img.read = buf_read;

    const char *dir = argc > 2 ? argv[2] : "/tmp";
    rcl::log_open(dir);
    rcl::report_run(img, rcl::Seeds::build69());
    rcl::log_close();

    // mirror the log to stdout, so CI and the terminal see the same report the device would write
    std::string cmd = std::string("ls -t ") + dir + "/recoil-runtime-*.log 2>/dev/null | head -1";
    FILE *d = popen(cmd.c_str(), "r");
    if (d) {
        char p[512] = {0};
        if (fgets(p, sizeof p, d)) {
            size_t L = strlen(p);
            while (L && (p[L-1] == '\n' || p[L-1] == '\r')) p[--L] = 0;
            FILE *lf = fopen(p, "r");
            if (lf) {
                char line[2048];
                while (fgets(line, sizeof line, lf)) fputs(line, stdout);
                fclose(lf);
            }
            printf("\n(log written to %s)\n", p);
        }
        pclose(d);
    }
    return 0;
}
