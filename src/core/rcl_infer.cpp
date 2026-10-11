#include "rcl_infer.h"
#include "rcl_syms.h"
#include "rcl_log.h"

#include <ctype.h>
#include <map>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

namespace rcl
{

namespace
{

std::vector<InferredName> g_cache;
bool g_loaded = false;
std::string g_dict_path;

bool sane_token(const std::string &t)
{
    if (t.size() < 6 || t.size() > 96)
        return false;
    if (!isalpha((unsigned char)t[0]) && t[0] != '_')
        return false;
    for (size_t i = 0; i < t.size(); i++)
    {
        const char c = t[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != ':')
            return false;
    }
    if (t.compare(0, 3, "_Z") == 0 || t.compare(0, 2, "__") == 0)
        return false;
    return true;
}

void add_token(std::vector<std::string> &out, std::set<std::string> &seen, const std::string &raw)
{
    std::string t = raw;
    const size_t args = t.find('(');
    if (args != std::string::npos)
        t = t.substr(0, args);
    while (!t.empty() && (t[t.size() - 1] == ' ' || t[t.size() - 1] == '&'))
        t.erase(t.size() - 1);
    if (t.size() > 6 && t.compare(t.size() - 6, 6, " const") == 0)
        t.erase(t.size() - 6);
    if (!sane_token(t))
        return;
    if (seen.insert(t).second)
        out.push_back(t);
    const size_t sep = t.rfind("::");
    if (sep != std::string::npos)
    {
        const std::string cls = t.substr(0, sep);
        const std::string meth = t.substr(sep + 2);
        if (sane_token(cls) && seen.insert(cls).second)
            out.push_back(cls);
        const size_t csep = cls.rfind("::");
        const std::string leaf = csep == std::string::npos ? cls : cls.substr(csep + 2);
        if (leaf != cls && sane_token(leaf) && seen.insert(leaf).second)
            out.push_back(leaf);
        if (sane_token(meth) && seen.insert(meth).second)
            out.push_back(meth);
    }
}

} // namespace

size_t infer_load_dict(const char *path, std::vector<std::string> &out)
{
    if (!path || !*path)
        return 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    std::set<std::string> seen;
    bool in_game_classes = false;
    char line[1024];
    bool first_header = true;
    while (fgets(line, sizeof line, f))
    {
        if (line[0] == '#' && line[1] == '#' && line[2] != '#')
        {
            in_game_classes = strstr(line, "кл") != nullptr && strstr(line, "Игровые") != nullptr;
            if (first_header)
            {
                first_header = false;
                in_game_classes = true;
            }
            continue;
        }
        if (!in_game_classes)
            continue;
        const char *a = strchr(line, '`');
        if (!a)
            continue;
        const char *b = strchr(a + 1, '`');
        if (!b || b == a + 1)
            continue;
        add_token(out, seen, std::string(a + 1, (size_t)(b - a - 1)));
    }
    fclose(f);
    RCL_LOGLN("[infer] dict %s: %zu tokens", path, out.size());
    return out.size();
}

const std::vector<InferredName> &infer_cached(const Image &img, const Seeds &s)
{
    if (g_loaded)
        return g_cache;
    g_loaded = true;

    const char *env = getenv("RCL_SYM_DICT");
    std::string path = env && *env ? env : "";
    if (path.empty())
    {
        char buf[512];
        const char *dir = getenv("RCL_LOG_DIR");
        snprintf(buf, sizeof buf, "%s/Symbols_v36.218.md", dir && *dir ? dir : "/tmp");
        struct stat st;
        if (stat(buf, &st) == 0)
            path = buf;
    }
    if (path.empty())
    {
        RCL_LOGLN("[infer] no dictionary (set RCL_SYM_DICT)");
        return g_cache;
    }
    g_dict_path = path;

    std::vector<std::string> dict;
    if (!infer_load_dict(path.c_str(), dict) || !dict.size())
        return g_cache;

    uint64_t lo = 0;
    uint64_t hi = 0;
    uint64_t cva = s.cstr_va;
    uint64_t csz = s.cstr_size;
    if (!code_text_range(img, lo, hi))
    {
        RCL_LOGLN("[infer] no text range");
        return g_cache;
    }
    if ((!cva || !csz) && !code_cstr_range(img, cva, csz))
    {
        RCL_LOGLN("[infer] no cstring range");
        return g_cache;
    }

    std::map<uint64_t, std::vector<uint64_t>> refs;
    code_str_refs(img, cva, csz, refs);
    if (refs.empty())
    {
        RCL_LOGLN("[infer] no string refs");
        return g_cache;
    }

    std::map<uint64_t, std::set<std::string>> by_fn;
    size_t matched = 0;
    for (size_t i = 0; i < dict.size(); i++)
    {
        uint32_t hits = 0;
        const uint64_t str_va = code_str_lookup(img, cva, csz, dict[i].c_str(), &hits);
        if (!str_va || !hits)
            continue;
        std::map<uint64_t, std::vector<uint64_t>>::iterator it = refs.find(str_va);
        if (it == refs.end())
            continue;
        matched++;
        for (size_t k = 0; k < it->second.size() && k < 24; k++)
        {
            const uint64_t fn = code_fn_start(img, it->second[k], lo);
            if (fn < lo || fn >= hi)
                continue;
            by_fn[fn - img.base].insert(dict[i]);
        }
    }

    for (std::map<uint64_t, std::set<std::string>>::iterator it = by_fn.begin(); it != by_fn.end();
         ++it)
    {
        InferredName n;
        n.rva = it->first;
        std::string evidence;
        std::string full;
        std::string plain;
        for (std::set<std::string>::iterator t = it->second.begin(); t != it->second.end(); ++t)
        {
            if (!evidence.empty())
                evidence += " ";
            evidence += *t;
            if (t->find("::") != std::string::npos)
            {
                if (full.empty())
                    full = *t;
            }
            else if (plain.empty())
                plain = *t;
        }
        n.name = !full.empty() ? ("inferred:" + full) : ("inferred:" + plain);
        n.evidence = evidence;
        g_cache.push_back(n);
    }
    RCL_LOGLN("[infer] %s: dict %zu, matched %zu, functions %zu", g_dict_path.c_str(), dict.size(),
              matched, g_cache.size());
    return g_cache;
}

void infer_names(const std::vector<InferredName> &in, NameTable &names)
{
    for (size_t i = 0; i < in.size(); i++)
        names.add(in[i].rva, in[i].name);
}

} // namespace rcl
