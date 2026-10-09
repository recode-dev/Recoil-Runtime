#include "rcl_scan.h"
#include "rcl_report.h"
#include "rcl_log.h"
#include "rcl_ident.h"
#include "rcl_live.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <unistd.h>
#include <pthread.h>
#endif

namespace rcl {

#if defined(__APPLE__)

static const char *kSelfName = "RecoilRuntime";

static bool live_read(void *ctx, uint64_t va, void *dst, size_t n) {
    const Image *im = (const Image *)ctx;
    if (va < im->base) return false;
    uint64_t off = va - im->base;
    if (off + n > im->vmsize) return false;
    memcpy(dst, (const void *)(uintptr_t)va, n);
    return true;
}

static uint64_t text_vmsize(const struct mach_header_64 *h) {
    uint64_t t = 0;
    const uint8_t *p = (const uint8_t *)h + sizeof(struct mach_header_64);
    for (uint32_t c = 0; c < h->ncmds; c++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strncmp(sg->segname, "__TEXT", 16) == 0) t = sg->vmsize;
        }
        p += lc->cmdsize;
    }
    return t;
}

static bool stamp_image(const struct mach_header_64 *h, uint64_t ts, Image &img, Stamp &st) {
    img.base = (uint64_t)(uintptr_t)h;
    img.vmsize = ts;
    img.image_vmsize = macho_image_size(h);
    img.ctx = &img;
    img.read = live_read;
    st = text_stamp(img);
    return st.valid;
}

static bool find_image(Image &out, std::string &why) {
    const char *want = getenv("RCL_IMAGE_MATCH");
    static Image holder;
    static uint32_t last_count = 0xFFFFFFFFu;
    const uint32_t total = _dyld_image_count();
    const bool verbose = (total != last_count);
    if (verbose) last_count = total;

    for (uint32_t i = 0; i < total; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *) _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, kSelfName)) continue;
        uint64_t ts = text_vmsize(h);
        if (ts < 0x100000) continue;
        if (want && !strstr(name, want)) continue;

        Image probe;
        Stamp st;
        const bool ok = stamp_image(h, ts, probe, st);
        if (verbose)
            RCL_LOGLN("[image] %2u __TEXT=0x%08llx probes=%s crc=0x%08x %s  %s", i,
                      (unsigned long long)ts, st.probes_ok ? "ok" : "no", st.crc, st.crc_ok ? "MATCH" : "",
                      name);
        if (!ok) continue;

        holder = probe;
        holder.ctx = &holder;
        out = holder;
        why = name;
        return true;
    }

    if (verbose) RCL_LOGLN("[image] no image carries the build-69.252 text stamp");
    why = "no image matched the 69.252 stamp";
    return false;
}

static void log_image_list() {
    const char *all_flag = getenv("RCL_IMAGES");
    const bool all = all_flag && *all_flag;
    uint32_t shown = 0;
    uint32_t hits = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        if (text_vmsize(h) < 0x80000) continue;
        hits++;
    }
    RCL_LOGLN("[loaded images] %u of %u are >=512KB%s", hits, _dyld_image_count(),
              all ? "" : " (summary only, RCL_IMAGES=1 for the full list)");
    if (!all) return;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        uint64_t ts = text_vmsize(h);
        if (ts < 0x80000) continue;
        RCL_LOGLN("   [%2u] 0x%08llx  %s", i, (unsigned long long)ts,
                  _dyld_get_image_name(i) ? _dyld_get_image_name(i) : "?");
        shown++;
    }
    RCL_LOGLN("[loaded images] listed %u", shown);
}

static void open_log_anywhere() {
    char home_docs[512] = {0}, home[512] = {0};
    const char *env = getenv("RCL_LOG_DIR");
    const char *h = getenv("HOME");
    if (h) { snprintf(home, sizeof home, "%s", h); snprintf(home_docs, sizeof home_docs, "%s/Documents", h); }

    const char *cands[5];
    int n = 0;
    if (env && *env) cands[n++] = env;
    if (home_docs[0]) cands[n++] = home_docs;
    if (home[0]) cands[n++] = home;
    cands[n++] = "/var/mobile/Documents";
    cands[n++] = "/tmp";

    for (int i = 0; i < n; i++) {
        log_open(cands[i]);
        if (log_is_open()) { RCL_LOGLN("[log] %s", cands[i]); return; }
    }
}

static void run_once(const Image &img, const std::string &why) {
    const Seeds s = Seeds::build69();
    log_image_list();
    RCL_LOGLN("[target image] %s", why.c_str());
    RCL_LOGLN("[target base] 0x%llx text_vmsize 0x%llx image_vmsize 0x%llx",
              (unsigned long long)img.base, (unsigned long long)img.vmsize,
              (unsigned long long)img.image_vmsize);
    report_run(img, s);
    live_session(img, s);
    log_close();
}

static void *waiter(void *) {
    open_log_anywhere();
    RCL_LOGLN("[boot] pid %d images %u", (int)getpid(), _dyld_image_count());

    for (int i = 0; i < 120; i++) {
        Image img; std::string why;
        if (find_image(img, why)) {
            run_once(img, why);
            return nullptr;
        }
        if (i % 10 == 9) RCL_LOGLN("[wait] %.0fs, images %u", (i + 1) * 0.5, _dyld_image_count());
        usleep(500000);
    }
    RCL_LOGLN("Recoil-Runtime: no target image after 60s, images %u", _dyld_image_count());
    log_close();
    return nullptr;
}

__attribute__((constructor)) static void rcl_ctor(void) {
    pthread_t th;
    if (pthread_create(&th, nullptr, waiter, nullptr) == 0) pthread_detach(th);
    else waiter(nullptr);
}

#else

static bool host_read(void *, uint64_t, void *, size_t) { return false; }

Image rcl_host_placeholder_image() {
    Image i{};
    i.read = host_read;
    return i;
}

void rcl_run_once_for_host() {
    Image img = rcl_host_placeholder_image();
    log_open("/tmp");
    report_run(img, Seeds::build69());
    log_close();
}

#endif

}
