// rcl_main.cpp - entry point of the injected dylib.
//
// READ-ONLY by design: the dylib scans the loaded game image and writes a log. It installs no
// inline hooks, patches no code and rewires no pointers - there is nothing to turn off, because the
// write path is not used here at all.
//
// LiveContainer-aware: in LiveContainer the guest app is not image 0, it is a dylib loaded into the
// host process, so the target is chosen by shape (an .app/ path, large __TEXT, not the host app)
// rather than by index. RCL_IMAGE_MATCH forces a substring when needed.
//
// Darwin parts are guarded so this file also compiles on the host, which is how its build is
// verified without an iOS toolchain.

#include "rcl_scan.h"
#include "rcl_report.h"
#include "rcl_hook.h"
#include "rcl_log.h"

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
    memcpy(dst, (const void *)(uintptr_t)va, n);      // VA == pointer in-process
    return true;
}

struct Cand { const struct mach_header_64 *h; int64_t slide; const char *name; uint64_t textsize; };

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

// Pick the target image; false while the guest app is not mapped yet.
static bool find_image(Image &out, std::string &why) {
    const char *want = getenv("RCL_IMAGE_MATCH");
    Cand best{nullptr, 0, nullptr, 0};        // best .app/ image that is not the host
    Cand biggest{nullptr, 0, nullptr, 0};     // fallback: biggest non-system image

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *) _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, kSelfName)) continue;                  // our own dylib
        uint64_t ts = text_vmsize(h);
        if (ts < 0x200000) continue;                            // system libs, small dylibs
        Cand c{h, _dyld_get_image_vmaddr_slide(i), name, ts};

        if (want) { if (strstr(name, want) && ts > biggest.textsize) biggest = c; continue; }

        const bool inApp = strstr(name, ".app/") != nullptr;
        const bool host  = strstr(name, "LiveContainer") || strstr(name, "TrollStore");
        if (inApp && !host && ts > best.textsize) best = c;
        if (ts > biggest.textsize) biggest = c;
    }

    Cand pick = (want && biggest.h) ? biggest : (best.h ? best : biggest);
    if (!pick.h) { why = "no candidate image yet"; return false; }

    static Image holder;
    holder.base = (uint64_t)(uintptr_t)pick.h;
    holder.vmsize = pick.textsize;
    holder.ctx = &holder;
    holder.read = live_read;
    out = holder;
    why = pick.name ? pick.name : "?";
    return true;
}

static void log_image_list() {
    RCL_LOGLN("[loaded images] >=512KB, with __TEXT vmsize - shows how the guest app is mapped");
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *) _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        uint64_t ts = text_vmsize(h);
        if (ts < 0x80000) continue;
        RCL_LOGLN("   [%2u] 0x%08llx  %s", i, (unsigned long long)ts,
                  _dyld_get_image_name(i) ? _dyld_get_image_name(i) : "?");
    }
}

// First writable directory wins. LiveContainer gives the guest its own HOME, so $HOME/Documents is
// the primary candidate; the shared and jailbreak paths are fallbacks.
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

static void run_once() {
    Image img;
    std::string why;
    if (!find_image(img, why)) return;
    log_image_list();
    RCL_LOGLN("[target image] %s", why.c_str());
    report_run(img, Seeds::build69());
    log_close();
}

static void *waiter(void *) {
    // LiveContainer may inject the tweak before the guest app is mapped: poll up to ~60s.
    for (int i = 0; i < 120; i++) {
        Image img; std::string why;
        if (find_image(img, why)) {
            open_log_anywhere();
            run_once();
            return nullptr;
        }
        usleep(500000);
    }
    open_log_anywhere();
    RCL_LOGLN("Recoil-Runtime: no target image after 60s");
    log_close();
    return nullptr;
}

__attribute__((constructor)) static void rcl_ctor(void) {
    pthread_t th;
    if (pthread_create(&th, nullptr, waiter, nullptr) == 0) pthread_detach(th);
    else { open_log_anywhere(); waiter(nullptr); }
}

#else  // ---------- host ----------

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

} // namespace rcl
