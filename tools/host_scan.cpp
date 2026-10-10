#include "rcl_classdump.h"
#include "rcl_docdata.h"
#include "rcl_log.h"
#include "rcl_names_live.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

static uint8_t *g_mem = nullptr;
static uint64_t g_lo = 0;
static uint64_t g_hi = 0;

static bool host_read(void *ctx, uint64_t va, void *dst, size_t n)
{
    (void)ctx;
    if (!n || va < g_lo || va + n > g_hi)
        return false;
    memcpy(dst, g_mem + (va - g_lo), n);
    return true;
}

int mach_task_self_ = 0;
static const char *g_bin_path = "";

extern "C" uint32_t _dyld_image_count(void)
{
    return 1;
}

extern "C" const void *_dyld_get_image_header(uint32_t index)
{
    (void)index;
    return (const void *)(uintptr_t)g_lo;
}

extern "C" const char *_dyld_get_image_name(unsigned int index)
{
    (void)index;
    return g_bin_path;
}

extern "C" intptr_t _dyld_get_image_vmaddr_slide(uint32_t index)
{
    (void)index;
    return 0;
}

extern "C" int mach_vm_region(unsigned int task, unsigned long long *address,
                              unsigned long long *size, int flavor, void *info,
                              unsigned int *count, unsigned int *object_name)
{
    (void)task;
    (void)address;
    (void)size;
    (void)flavor;
    (void)info;
    (void)count;
    (void)object_name;
    return 1;
}

extern "C" int mach_vm_read_overwrite(unsigned int task, unsigned long long addr,
                                      unsigned long long size, unsigned long long out,
                                      unsigned long long *got)
{
    (void)task;
    if (got)
        *got = 0;
    if (!host_read(nullptr, addr, (void *)(uintptr_t)out, (size_t)size))
        return 1;
    if (got)
        *got = size;
    return 0;
}

namespace rcl
{

void alert_show(const char *title, const char *body)
{
    (void)title;
    (void)body;
}

} // namespace rcl

static bool map_image(const char *path)
{
    const int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    struct stat sb;
    if (fstat(fd, &sb) != 0)
    {
        close(fd);
        return false;
    }
    const size_t size = (size_t)sb.st_size;
    uint8_t *file = (uint8_t *)mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file == MAP_FAILED)
        return false;

    g_lo = 0x100000000ull;
    g_hi = 0x101170000ull;
    const size_t span = (size_t)(g_hi - g_lo);
    g_mem = (uint8_t *)mmap((void *)(uintptr_t)g_lo, span, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (g_mem != (uint8_t *)(uintptr_t)g_lo)
    {
        printf("map at %#llx failed\n", (unsigned long long)g_lo);
        return false;
    }

    const uint32_t ncmds = *(const uint32_t *)(file + 16);
    uint32_t off = 32;
    for (uint32_t i = 0; i < ncmds; i++)
    {
        const uint32_t cmd = *(const uint32_t *)(file + off);
        const uint32_t cmdsize = *(const uint32_t *)(file + off + 4);
        if (cmd == 0x19u)
        {
            const uint64_t vmaddr = *(const uint64_t *)(file + off + 24);
            const uint64_t vmsize = *(const uint64_t *)(file + off + 32);
            const uint64_t fileoff = *(const uint64_t *)(file + off + 40);
            const uint64_t filesize = *(const uint64_t *)(file + off + 48);
            if (vmaddr == 0 && filesize == 0)
            {
                off += cmdsize;
                continue;
            }
            if (vmaddr < g_lo || filesize == 0)
            {
                off += cmdsize;
                continue;
            }
            const size_t copy = (size_t)((filesize > vmsize) ? filesize : filesize);
            if (vmaddr + copy > g_hi)
            {
                off += cmdsize;
                continue;
            }
            memcpy(g_mem + (vmaddr - g_lo), file + fileoff, copy);
        }
        off += cmdsize;
    }
    munmap(file, size);
    return true;
}

static void split_fields(const std::string &line, std::vector<std::string> &out)
{
    out.clear();
    size_t i = 0;
    while (i < line.size())
    {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
            i++;
        const size_t st = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t')
            i++;
        if (i > st)
            out.push_back(line.substr(st, i - st));
    }
}

int main(int argc, char **argv)
{
    const char *bin = (argc > 1) ? argv[1] : "bin/NullsBrawl";
    g_bin_path = bin;
    const char *want = (argc > 2) ? argv[2] : nullptr;
    if (!map_image(bin))
    {
        printf("cannot load %s\n", bin);
        return 2;
    }

    rcl::Image img;
    img.base = g_lo;
    img.vmsize = g_hi - g_lo;
    img.image_vmsize = g_hi - g_lo;
    img.ctx = nullptr;
    img.read = host_read;

    uint32_t doc_in = 0;
    uint32_t doc_classes = 0;
    uint32_t doc_rvas = 0;
    rcl::nl_build_check(&doc_classes, &doc_rvas, &doc_in);
    printf("image base %#llx vmsize %#llx\n", (unsigned long long)g_lo,
           (unsigned long long)(g_hi - g_lo));
    printf("bundle: %u classes, %u first-method rvas inside the image\n", doc_classes, doc_in);

    rcl::nl_init(host_read, nullptr, g_lo, g_hi);
    printf("deep scan\n");
    fflush(stdout);
    rcl::dump_class_tree(img);

    rcl::ScanStats st;
    std::vector<rcl::ClassTable> tables = rcl::scan_class_tables(img, &st);
    rcl::symbolize_tables(img, tables);
    uint32_t named = 0;
    std::map<std::string, uint32_t> by_name;
    for (size_t i = 0; i < tables.size(); i++)
    {
        const char *nm = rcl::rcl_table_label(tables[i].start);
        if (!nm || !*nm)
            nm = (tables[i].name && *tables[i].name) ? tables[i].name : nullptr;
        if (!nm || !*nm)
            continue;
        named++;
        by_name[nm] = tables[i].start;
    }
    printf("class tables %zu, named %u, strict %u loose %u\n", tables.size(), named,
           st.tables_strict, st.tables_loose);

    {
        const char *dump = getenv("RCL_NAMES_OUT");
        if (dump && *dump)
        {
            FILE *o = fopen(dump, "w");
            if (o)
            {
                for (size_t i = 0; i < tables.size(); i++)
                {
                    const char *nm = rcl::rcl_table_label(tables[i].start);
                    if (!nm || !*nm)
                        nm = (tables[i].name && *tables[i].name) ? tables[i].name : nullptr;
                    if (!nm || !*nm)
                        continue;
                    fprintf(o, "%s\t%x\t%u\n", nm, tables[i].start, tables[i].slots);
                }
                fclose(o);
            }
        }
    }

    if (want)
    {
        FILE *f = fopen(want, "r");
        if (!f)
        {
            printf("cannot read %s\n", want);
            return 2;
        }
        char line[256];
        uint32_t symbols = 0;
        uint32_t class_hits = 0;
        std::set<std::string> hit_classes;
        while (fgets(line, sizeof line, f))
        {
            std::string s(line);
            while (!s.empty() && (s[s.size() - 1] == '\n' || s[s.size() - 1] == '\r'))
                s.erase(s.size() - 1);
            if (s.empty())
                continue;
            symbols++;
            std::string best;
            for (std::map<std::string, uint32_t>::const_iterator it = by_name.begin();
                 it != by_name.end(); ++it)
            {
                const std::string &k = it->first;
                if (k.size() < 4)
                    continue;
                if (s == k || s.compare(0, k.size(), k) == 0 && (s[k.size()] == '_'))
                {
                    if (best.size() < k.size())
                        best = k;
                }
            }
            if (!best.empty())
            {
                class_hits++;
                hit_classes.insert(best);
            }
        }
        fclose(f);
        printf("targets %u, class resolved %u, distinct classes %zu\n", symbols, class_hits,
               hit_classes.size());
        for (std::set<std::string>::const_iterator it = hit_classes.begin();
             it != hit_classes.end(); ++it)
        {
            const std::map<std::string, uint32_t>::const_iterator t = by_name.find(*it);
            printf("   %-44s table rva %#x slots %u named %u\n", it->c_str(),
                   t == by_name.end() ? 0u : t->second, 0u, 0u);
        }
    }
    return 0;
}
