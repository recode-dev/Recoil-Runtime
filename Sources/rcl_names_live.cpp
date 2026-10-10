#include "rcl_names_live.h"
#include "rcl_docdata.h"
#include "rcl_names.h"

#include <map>
#include <string>
#include <vector>
#include <string.h>
#include <stdio.h>

namespace rcl
{
namespace
{

NlReadFn g_read = nullptr;
void *g_ctx = nullptr;
uint64_t g_lo = 0;
uint64_t g_hi = 0;
uint64_t g_base = 0;
bool g_ready = false;

std::map<uint32_t, uint32_t> g_doc_vt;
std::map<uint32_t, uint32_t> g_doc_method;
std::map<std::string, std::vector<uint32_t>> g_sig;
std::map<uint32_t, uint32_t> g_inst;
std::map<uint32_t, uint32_t> g_inst_score;
uint32_t g_hits[NL_SRC_MAX + 1] = {0, 0, 0, 0, 0, 0, 0};
std::map<uint32_t, std::string> g_asset;
std::map<uint32_t, uint32_t> g_kind;

const uint32_t kSigDfMax = 3;
const uint32_t kSigMinLen = 4;
const uint32_t kWindow = 160;
const uint32_t kMaxSlots = 64;
const uint32_t kMinMethodVotes = 2;
const uint32_t kMinStringHits = 1;

bool read_va(uint64_t va, void *dst, size_t n)
{
    return g_read && g_read(g_ctx, va, dst, n);
}

void read_cstr(uint64_t va, char *out, size_t cap)
{
    size_t i = 0;
    out[0] = 0;
    while (i + 1 < cap)
    {
        char c = 0;
        if (!read_va(va + i, &c, 1) || c == 0)
        {
            break;
        }
        unsigned char u = (unsigned char)c;
        if (u < 32 || u > 126)
        {
            out[0] = 0;
            return;
        }
        out[i++] = c;
    }
    out[i] = 0;
}

bool adrp_page(uint32_t w, int64_t &page, int &rd)
{
    if ((w & 0x9F000000u) != 0x90000000u)
    {
        return false;
    }
    int64_t imm = (int64_t)((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3));
    if (imm & (1 << 20))
    {
        imm -= (1 << 21);
    }
    page = imm << 12;
    rd = (int)(w & 31);
    return true;
}

bool add_imm64(uint32_t w, int &rn, int &rd, uint64_t &off)
{
    if ((w & 0x7F000000u) != 0x11000000u)
    {
        return false;
    }
    rn = (int)((w >> 5) & 31);
    rd = (int)(w & 31);
    uint64_t imm12 = (w >> 10) & 0xFFF;
    off = ((w >> 22) & 1) ? (imm12 << 12) : imm12;
    return true;
}

bool is_exit(uint32_t w)
{
    if ((w & 0xFFFFFC1Fu) == 0xD65F0000u)
    {
        return true;
    }
    if ((w & 0xFFFFFC1Fu) == 0xD61F0000u)
    {
        return true;
    }
    return w == 0xD69F03E0u;
}

void scan_window(uint64_t va, std::vector<std::string> &out)
{
    char win[kWindow];
    if (!read_va(va, win, kWindow))
    {
        return;
    }
    int64_t page[32];
    for (int r = 0; r < 32; r++)
    {
        page[r] = 0;
    }
    for (uint32_t o = 0; o + 4 <= kWindow; o += 4)
    {
        uint32_t w = 0;
        memcpy(&w, win + o, 4);
        int64_t p = 0;
        int rd = 0;
        if (adrp_page(w, p, rd))
        {
            page[rd] = (int64_t)((va + o) & ~0xFFFull) + p;
            continue;
        }
        int rn = 0;
        int rdd = 0;
        uint64_t off = 0;
        if (add_imm64(w, rn, rdd, off))
        {
            if (rn == rdd && rn != 31 && page[rn])
            {
                uint64_t t = (uint64_t)page[rn] + off;
                if (t >= g_lo && t < g_hi)
                {
                    char s[208];
                    read_cstr(t, s, sizeof s);
                    if (s[0])
                    {
                        out.push_back(std::string(s));
                    }
                }
            }
            continue;
        }
        if (is_exit(w))
        {
            break;
        }
    }
}

void collect_sig(uint32_t cls, std::map<std::string, uint32_t> &df,
                 std::map<std::string, std::vector<uint32_t>> *into)
{
    const DocClass &d = kDocClasses[cls];
    if (!d.strings)
    {
        return;
    }
    const char *p = kDocBlob + d.strings;
    std::string cur;
    for (;;)
    {
        if (*p == 0x1f || *p == 0)
        {
            if (cur.size() >= kSigMinLen)
            {
                if (into == nullptr)
                {
                    df[cur]++;
                }
                else
                {
                    std::map<std::string, uint32_t>::const_iterator it = df.find(cur);
                    if (it != df.end() && it->second <= kSigDfMax)
                    {
                        (*into)[cur].push_back(cls);
                    }
                }
            }
            cur.clear();
            if (*p == 0)
            {
                break;
            }
        }
        else
        {
            cur.push_back(*p);
        }
        p++;
    }
}

void build()
{
    std::map<std::string, uint32_t> df;
    for (uint32_t i = 0; i < kDocClassCount; i++)
    {
        const DocClass &d = kDocClasses[i];
        if (d.vt)
        {
            g_doc_vt[d.vt] = i;
        }
        for (uint32_t k = d.first; k < d.first + d.count && k < kDocMethodCount; k++)
        {
            if (!g_doc_method.count(kDocMethods[k].rva))
            {
                g_doc_method[kDocMethods[k].rva] = i;
            }
        }
        collect_sig(i, df, nullptr);
    }
    for (uint32_t i = 0; i < kDocClassCount; i++)
    {
        collect_sig(i, df, &g_sig);
    }
    g_ready = true;
}

void label_of(uint32_t idx, char *buf, size_t cap)
{
    const DocClass &d = kDocClasses[idx];
    const char *n = kDocBlob + d.name;
    const char *c = kDocBlob + d.cat;
    if (c && *c && strcmp(c, "-") != 0)
    {
        snprintf(buf, cap, "%s/%s", c, n);
        return;
    }
    snprintf(buf, cap, "%s", n);
}

template <typename K> bool best_of(const std::map<K, uint32_t> &score, uint32_t need, K &out)
{
    uint32_t bn = 0;
    bool tie = false;
    for (typename std::map<K, uint32_t>::const_iterator it = score.begin(); it != score.end(); ++it)
    {
        if (it->second > bn)
        {
            bn = it->second;
            out = it->first;
            tie = false;
        }
        else if (it->second == bn)
        {
            tie = true;
        }
    }
    return bn >= need && !tie;
}

void score_strings(const std::vector<std::string> &refs, std::map<uint32_t, uint32_t> &out)
{
    for (size_t r = 0; r < refs.size(); r++)
    {
        std::map<std::string, std::vector<uint32_t>>::const_iterator it = g_sig.find(refs[r]);
        if (it == g_sig.end())
        {
            continue;
        }
        for (size_t v = 0; v < it->second.size(); v++)
        {
            out[it->second[v]]++;
        }
    }
}

} // namespace

void nl_init(NlReadFn fn, void *ctx, uint64_t img_lo, uint64_t img_hi)
{
    g_read = fn;
    g_ctx = ctx;
    g_lo = img_lo;
    g_hi = img_hi;
    g_base = img_lo;
    if (!g_ready && fn)
    {
        build();
    }
}

bool asset_like(const std::string &s)
{
    if (s.size() < 8 || s.size() > 96)
        return false;
    bool alnum = true;
    for (size_t i = 0; i < s.size(); i++)
    {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= '_') || c == '/' ||
              c == '.'))
            alnum = false;
    }
    if (alnum)
        return true;
    return s.find('/') != std::string::npos;
}

void asset_take(uint32_t vt, const std::vector<std::string> &refs)
{
    const std::string *pick = nullptr;
    for (size_t i = 0; i < refs.size(); i++)
    {
        if (!asset_like(refs[i]))
            continue;
        if (pick == nullptr || refs[i].size() > pick->size())
            pick = &refs[i];
    }
    if (pick == nullptr)
        return;
    std::map<uint32_t, std::string>::iterator it = g_asset.find(vt);
    if (it != g_asset.end() && it->second.size() >= pick->size())
        return;
    g_asset[vt] = *pick;
}

std::string lower_ascii(const std::string &s)
{
    std::string r = s;
    for (size_t i = 0; i < r.size(); i++)
    {
        if (r[i] >= 'A' && r[i] <= 'Z')
        {
            r[i] = (char)(r[i] - 'A' + 'a');
        }
    }
    return r;
}

bool has_any(const std::string &h, const char *const *marks, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        if (h.find(marks[i]) != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

uint32_t kind_of_text(const std::string &s)
{
    if (s.empty())
    {
        return NLK_UNKNOWN;
    }
    const std::string h = lower_ascii(s);
    static const char *const kLogic[] = {"csv_logic", "logic", "battle",     "charac", "player",
                                        "projectile", "tile",  "avatar",      "gamemodel", "game/",
                                        "network",    "input", "joystick",    "camera", "scid",
                                        "csv"};
    static const char *const kAudio[] = {"sound", ".wav",  ".mp3",    ".m4a",  ".ogg",
                                        "music", "sfx",   "audio",   "bgm",   "ambient",
                                        "voice", "speaker"};
    static const char *const kUi[] = {"ui_",     "/ui",    "ui.sc",    "popup",  "movieclip",
                                      "timeline", "gui",    "button_",  "icon_",  "tid_",
                                      "_txt",     "screen", "menu",     "popover", "stream",
                                      "tooltip",  "banner", "slider",   "textfield", "label"};
    static const char *const kAsset[] = {".glb",   ".sctx",  ".sc",     ".tex",      ".png",
                                         ".pvr",   ".ktx",   "sc3d/",   "sc/",       "effects",
                                         "particle", "trail", "explo",  "smoke",     "decal",
                                         "material", "shader", "anim",  "album_",    "_red",
                                         "_blue",  "_green", "_spawn",  "_impact",   "_ripple",
                                         "_debris", "_spark", "_lobby_", "_ulti",    "_atk",
                                         "_def",   "_idle",  "_walk",   "_run",      "_hit",
                                         "_ground", "_wall"};
    if (has_any(h, kLogic, sizeof kLogic / sizeof kLogic[0]))
    {
        return NLK_LOGIC;
    }
    if (has_any(h, kAudio, sizeof kAudio / sizeof kAudio[0]))
    {
        return NLK_AUDIO;
    }
    if (has_any(h, kUi, sizeof kUi / sizeof kUi[0]))
    {
        return NLK_UI;
    }
    if (has_any(h, kAsset, sizeof kAsset / sizeof kAsset[0]))
    {
        return NLK_ASSET;
    }
    return NLK_UNKNOWN;
}

void nl_observe(uint32_t vt, const char *const *strs, uint32_t n)
{
    if (!g_ready && g_read)
    {
        build();
    }
    if (n == 0)
    {
        return;
    }
    std::vector<std::string> refs;
    for (uint32_t i = 0; i < n; i++)
    {
        if (strs[i] && strs[i][0])
        {
            refs.push_back(std::string(strs[i]));
        }
    }
    std::map<uint32_t, uint32_t> score;
    asset_take(vt, refs);
    score_strings(refs, score);
    uint32_t best = 0;
    if (!best_of(score, kMinStringHits, best))
    {
        return;
    }
    const uint32_t hits = score[best];
    if (g_inst.count(vt) && g_inst_score[vt] >= hits)
    {
        return;
    }
    g_inst[vt] = best;
    g_inst_score[vt] = hits;
}

const char *nl_label(uint32_t vt, const uint32_t *slots, uint32_t nslots, char *buf, size_t cap,
                     uint32_t *src)
{
    if (src)
    {
        *src = NL_NONE;
    }
    if (!g_ready && g_read)
    {
        build();
    }
    if (nslots > kMaxSlots)
    {
        nslots = kMaxSlots;
    }

    std::map<uint32_t, uint32_t>::const_iterator vtit = g_doc_vt.find(vt);
    if (vtit != g_doc_vt.end())
    {
        label_of(vtit->second, buf, cap);
        g_hits[NL_DOC_VT]++;
        if (src)
        {
            *src = NL_DOC_VT;
        }
        return buf;
    }

    std::map<uint32_t, uint32_t>::const_iterator inst = g_inst.find(vt);
    if (inst != g_inst.end())
    {
        label_of(inst->second, buf, cap);
        g_hits[NL_INSTANCE]++;
        if (src)
        {
            *src = NL_INSTANCE;
        }
        return buf;
    }

    std::map<uint32_t, uint32_t> by_method;
    for (uint32_t i = 0; i < nslots; i++)
    {
        std::map<uint32_t, uint32_t>::const_iterator it = g_doc_method.find(slots[i]);
        if (it != g_doc_method.end())
        {
            by_method[it->second]++;
        }
    }
    uint32_t best = 0;
    if (best_of(by_method, kMinMethodVotes, best))
    {
        label_of(best, buf, cap);
        g_hits[NL_DOC_METHODS]++;
        if (src)
        {
            *src = NL_DOC_METHODS;
        }
        return buf;
    }

    std::map<uint32_t, uint32_t> by_string;
    for (uint32_t i = 0; i < nslots; i++)
    {
        std::vector<std::string> refs;
        scan_window(g_base + (uint64_t)slots[i], refs);
        score_strings(refs, by_string);
    }
    std::map<uint32_t, std::string>::const_iterator as = g_asset.find(vt);
    if (as != g_asset.end())
    {
        snprintf(buf, cap, "%s", as->second.c_str());
        g_hits[NL_ASSET]++;
        if (src)
        {
            *src = NL_ASSET;
        }
        return buf;
    }

    if (best_of(by_string, kMinStringHits, best))
    {
        label_of(best, buf, cap);
        g_hits[NL_STRINGS]++;
        if (src)
        {
            *src = NL_STRINGS;
        }
        return buf;
    }

    std::map<std::string, uint32_t> freq;
    for (uint32_t i = 0; i < nslots; i++)
    {
        const char *nm = name_for_rva(slots[i]);
        if (!nm || strcmp(nm, "-") == 0)
        {
            continue;
        }
        const char *sep = strstr(nm, "::");
        if (!sep || sep == nm)
        {
            continue;
        }
        freq[std::string(nm, (size_t)(sep - nm))]++;
    }
    std::string bestname;
    if (best_of(freq, kMinMethodVotes, bestname))
    {
        snprintf(buf, cap, "%s", bestname.c_str());
        g_hits[NL_METHOD_NAMES]++;
        if (src)
        {
            *src = NL_METHOD_NAMES;
        }
        return buf;
    }

    snprintf(buf, cap, "vt_%06x", vt);
    return buf;
}

void nl_stats(uint32_t hits[NL_SRC_MAX + 1])
{
    for (uint32_t i = 0; i <= NL_SRC_MAX; i++)
    {
        hits[i] = g_hits[i];
    }
}

bool nl_kind_keep(uint32_t kind)
{
    return kind == NLK_LOGIC || kind == NLK_UNKNOWN;
}

uint32_t nl_kind(uint32_t vt)
{
    std::map<uint32_t, uint32_t>::const_iterator it = g_kind.find(vt);
    if (it != g_kind.end())
    {
        return it->second;
    }
    uint32_t kind = NLK_UNKNOWN;
    uint32_t idx = 0;
    bool have = false;
    std::map<uint32_t, uint32_t>::const_iterator di = g_doc_vt.find(vt);
    if (di != g_doc_vt.end())
    {
        idx = di->second;
        have = true;
    }
    else
    {
        std::map<uint32_t, uint32_t>::const_iterator ii = g_inst.find(vt);
        if (ii != g_inst.end())
        {
            idx = ii->second;
            have = true;
        }
    }
    if (have)
    {
        char lb[256];
        label_of(idx, lb, sizeof lb);
        kind = kind_of_text(lb);
    }
    if (kind == NLK_UNKNOWN)
    {
        std::map<uint32_t, std::string>::const_iterator ai = g_asset.find(vt);
        if (ai != g_asset.end())
        {
            kind = kind_of_text(ai->second);
        }
    }
    g_kind[vt] = kind;
    return kind;
}

const char *nl_kind_name(uint32_t kind)
{
    switch (kind)
    {
    case NLK_LOGIC:
        return "logic";
    case NLK_UI:
        return "ui";
    case NLK_ASSET:
        return "asset";
    case NLK_AUDIO:
        return "audio";
    default:
        return "unknown";
    }
}

} // namespace rcl
