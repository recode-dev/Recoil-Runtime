#include "rcl_scan.h"
#include "rcl_report.h"
#include "rcl_log.h"
#include "rcl_ident.h"
#include "rcl_live.h"
#include "rcl_classdump.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

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
    const uint64_t span = im->image_vmsize ? im->image_vmsize : im->vmsize;
    if (va < im->base) return false;
    uint64_t off = va - im->base;
    if (off + n > span) return false;
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

static uint64_t env_u64(const char *name, uint64_t def) {
    const char *v = getenv(name);
    if (!v || !*v) return def;
    return strtoull(v, nullptr, 0);
}

static bool structural_ok(const struct mach_header_64 *h) {
    if (!h || h->magic != MH_MAGIC_64) return false;
    return ((uint32_t)h->cputype & 0x00FFFFFFu) == 12u;
}

struct Loaded {
    Image img;
    std::string name;
    uint64_t text = 0;
};

static int gather_images(std::vector<Loaded> &out, bool verbose) {
    const char *want = getenv("RCL_IMAGE_MATCH");
    const uint64_t mintext = env_u64("RCL_MIN_TEXT", 0x80000);
    const uint32_t total = _dyld_image_count();
    for (uint32_t i = 0; i < total; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!structural_ok(h)) continue;
        const char *name = _dyld_get_image_name(i);
        if (!name || strstr(name, kSelfName)) continue;
        const uint64_t ts = text_vmsize(h);
        if (ts < mintext) continue;
        if (want && !strstr(name, want)) continue;
        Loaded l;
        l.img.base = (uint64_t)(uintptr_t)h;
        l.img.vmsize = ts;
        l.img.image_vmsize = macho_image_size(h);
        l.img.read = live_read;
        l.img.ctx = nullptr;
        l.name = name;
        l.text = ts;
        out.push_back(l);
        if (verbose) RCL_LOGLN("   [%2u] __TEXT=0x%08llx %s", i, (unsigned long long)ts, name);
    }
    for (size_t i = 0; i < out.size(); i++) out[i].img.ctx = &out[i].img;
    return (int)out.size();
}

static bool pick_image(Image &out, std::string &why, std::vector<Loaded> &all) {
    const uint64_t mintext = env_u64("RCL_MIN_TEXT", 0x80000);
    RCL_LOGLN("[images] %u loaded, __TEXT threshold 0x%llx", _dyld_image_count(),
              (unsigned long long)mintext);
    gather_images(all, true);
    {
        int bcBest = -1;
        for (size_t i = 0; i < all.size(); i++) {
            const bool bcApp = all[i].name.find(".app/") != std::string::npos &&
                               all[i].name.find(".framework/") == std::string::npos;
            if (!bcApp) continue;
            if (bcBest < 0 || all[i].text > all[bcBest].text) bcBest = (int)i;
        }
        if (bcBest < 0 && !all.empty()) bcBest = 0;
        if (bcBest >= 0) battle_capture_autostart(all[bcBest].img);
    }
    if (all.empty()) {
        why = "no image passed the structural filter";
        return false;
    }
    int best = -1;
    for (size_t i = 0; i < all.size(); i++) {
        const bool app = all[i].name.find(".app/") != std::string::npos &&
                         all[i].name.find(".framework/") == std::string::npos;
        if (!app) continue;
        if (best < 0 || all[i].text > all[best].text) best = (int)i;
    }
    if (best < 0) {
        best = 0;
        for (size_t i = 1; i < all.size(); i++)
            if (all[i].text > all[best].text) best = (int)i;
    }
    const Stamp st = text_stamp(all[best].img);
    out = all[best].img;
    why = all[best].name;
    RCL_LOGLN("[image] selected __TEXT=0x%08llx crc=0x%08x %s",
              (unsigned long long)all[best].text, st.crc, why.c_str());
    return true;
}

static void log_image_list() {
    const char *all_flag = getenv("RCL_IMAGES");
    const bool all = all_flag && *all_flag;
    const uint64_t mintext = env_u64("RCL_MIN_TEXT", 0x80000);
    uint32_t hits = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!structural_ok(h)) continue;
        if (text_vmsize(h) < mintext) continue;
        hits++;
    }
    RCL_LOGLN("[loaded images] %u of %u are >=0x%llx%s", hits, _dyld_image_count(),
              (unsigned long long)mintext,
              all ? "" : " (summary only, RCL_IMAGES=1 for the full list)");
    if (!all) return;
    uint32_t shown = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!structural_ok(h)) continue;
        const uint64_t ts = text_vmsize(h);
        if (ts < mintext) continue;
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

    const char *cands[6];
    int n = 0;
    if (env && *env) cands[n++] = env;
    cands[n++] = dumps_root();
    if (home_docs[0]) cands[n++] = home_docs;
    if (home[0]) cands[n++] = home;
    cands[n++] = "/var/mobile/Documents";
    cands[n++] = "/tmp";

    for (int i = 0; i < n; i++) {
        log_open(cands[i]);
        battle_capture_open();
        if (log_is_open()) { RCL_LOGLN("[log] %s", cands[i]); return; }
    }
}

static Image g_live_img;
static Seeds g_live_seeds;
static bool g_live_started = false;

static void *live_worker(void *) {
    g_live_started = true;
    for (;;) {
        live_session(g_live_img, g_live_seeds);
        sleep(5);
    }
    return nullptr;
}

static void run_pass(const Image &img, const std::string &why, int pass) {
    const Seeds s = Seeds::discover(img);
    if (pass == 0) {
        log_image_list();
        RCL_LOGLN("[target image] %s", why.c_str());
        RCL_LOGLN("[target base] 0x%llx text_vmsize 0x%llx image_vmsize 0x%llx",
                  (unsigned long long)img.base, (unsigned long long)img.vmsize,
                  (unsigned long long)img.image_vmsize);
    } else {
        RCL_LOGLN("");
        RCL_LOGLN("[pass %d] base 0x%llx images %u", pass, (unsigned long long)img.base,
                  _dyld_image_count());
    }
    set_skip_bundle(pass > 0);
    report_run(img, s);
    set_skip_bundle(false);
    if (pass > 0) return;
    if (g_live_started) return;
    if ((int)env_u64("RCL_RESCAN_SEC", 20) <= 0) {
        live_session(img, s);
        return;
    }
    g_live_img = img;
    g_live_seeds = s;
    pthread_t lt;
    if (pthread_create(&lt, nullptr, live_worker, nullptr) == 0) pthread_detach(lt);
    else live_session(img, s);
}

static void *waiter(void *) {
    open_log_anywhere();
    RCL_LOGLN("[boot] pid %d images %u", (int)getpid(), _dyld_image_count());

    const int wait_ms = (int)env_u64("RCL_WAIT_SEC", 60) * 1000;
    const int step_ms = 500;

    for (int i = 0; i * step_ms < wait_ms; i++) {
        std::vector<Loaded> all;
        Image img;
        std::string why;
        if (pick_image(img, why, all)) {
            const int delay = (int)env_u64("RCL_DELAY_MS", 0);
            if (delay > 0) usleep((useconds_t)delay * 1000);
            const char *all_flag = getenv("RCL_ALL_IMAGES");
            if (all_flag && *all_flag) {
                log_image_list();
                for (size_t k = 0; k < all.size(); k++) {
                    RCL_LOGLN("");
                    RCL_LOGLN("[scan %zu/%zu] %s", k + 1, all.size(), all[k].name.c_str());
                    report_run(all[k].img, Seeds::discover(all[k].img));
                }
                live_session(all[0].img, Seeds::discover(all[0].img));
                log_close();
                return nullptr;
            }
            run_pass(img, why, 0);
            const int secs = (int)env_u64("RCL_RESCAN_SEC", 20);
            if (secs <= 0) {
                log_close();
                return nullptr;
            }
            for (int pass = 1;; pass++) {
                sleep((unsigned)secs);
                std::vector<Loaded> again;
                Image i2;
                std::string w2;
                if (!pick_image(i2, w2, again)) continue;
                run_pass(i2, w2, pass);
            }
        }
        if (i % 20 == 19)
            RCL_LOGLN("[wait] %.0fs, images %u", (i + 1) * step_ms / 1000.0, _dyld_image_count());
        usleep((useconds_t)step_ms * 1000);
    }
    RCL_LOGLN("Recoil-Runtime: no target image after %ds, images %u", wait_ms / 1000,
              _dyld_image_count());
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
    report_run(img, Seeds::discover(img));
    log_close();
}

#endif

}
