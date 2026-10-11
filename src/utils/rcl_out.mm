#include "rcl_out.h"

#import <Foundation/Foundation.h>

#include <map>

namespace rcl
{

static std::string g_root;
static std::map<std::string, size_t> g_counts;

static NSString *ns(const std::string &s)
{
    return [NSString stringWithUTF8String:s.c_str()];
}

static bool write_text(const std::string &path, const std::string &text)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [ns(path) stringByDeletingLastPathComponent];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSData *data = [NSData dataWithBytes:text.data() length:text.size()];
    return [data writeToFile:ns(path) atomically:YES] == YES;
}

std::string out_fmt(const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0)
        return std::string();
    return std::string(buf, (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1);
}

void out_begin(const char *dir)
{
    g_root = std::string(dir && *dir ? dir : ".") + "/RecoilRuntime";
    g_counts.clear();
    write_text(g_root + "/.keep", "recoil-runtime\n");
}

std::string out_root()
{
    return g_root;
}

bool out_write(const char *section, const char *name, const std::string &text)
{
    if (g_root.empty())
        return false;
    g_counts[section]++;
    return write_text(g_root + "/" + section + "/" + name + ".md", text);
}

bool out_write_root(const char *name, const std::string &text)
{
    if (g_root.empty())
        return false;
    return write_text(g_root + "/" + name + ".md", text);
}

} // namespace rcl
