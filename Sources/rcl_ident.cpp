#include "rcl_ident.h"
#include "rcl_log.h"

namespace rcl {

uint32_t crc32_update(uint32_t c, const uint8_t *p, size_t n) {
    static uint32_t tab[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t v = i;
            for (int k = 0; k < 8; k++) v = (v & 1u) ? (0xEDB88320u ^ (v >> 1)) : (v >> 1);
            tab[i] = v;
        }
        ready = true;
    }
    for (size_t i = 0; i < n; i++) c = tab[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c;
}

static const uint64_t kProbeRva[4] = {0x4000ULL, 0x8c5130ULL, 0xa23afcULL, 0x9cd834ULL};
static const uint64_t kProbeWord[4] = {
    0x45361f3f18209937ULL,
    0xa9017bfda9be4ff4ULL,
    0xd65f03c0b9403000ULL,
    0xd65f03c0b9412400ULL,
};
static const uint64_t kTextOff = 0x4000ULL;
static const uint64_t kTextEnd = 0xd8af60ULL;
static const uint32_t kTextCrc = 0x5a34cc68u;

Stamp text_stamp(const Image &img) {
    Stamp s;
    if (!img.ok()) return s;
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        if (!img.read(img.ctx, img.base + kProbeRva[i], &w, sizeof w)) return s;
        if (w != kProbeWord[i]) return s;
    }
    s.probes_ok = true;

    uint32_t c = 0xFFFFFFFFu;
    uint8_t buf[8192];
    for (uint64_t off = kTextOff; off < kTextEnd; ) {
        uint64_t left = kTextEnd - off;
        size_t n = (size_t)(left < (uint64_t)sizeof buf ? left : (uint64_t)sizeof buf);
        if (!img.read(img.ctx, img.base + off, buf, n)) return s;
        c = crc32_update(c, buf, n);
        off += (uint64_t)n;
    }
    s.crc = c ^ 0xFFFFFFFFu;
    s.crc_ok = (s.crc == kTextCrc);
    s.valid = true;
    return s;
}

}
