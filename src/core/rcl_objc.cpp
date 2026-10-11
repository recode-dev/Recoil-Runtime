#include "rcl_objc.h"
#include "rcl_log.h"

#include <dlfcn.h>
#include <set>
#include <stdlib.h>

namespace rcl
{

namespace
{

typedef void *Cls;
typedef void *Method;
typedef void *Sel;
typedef void *Imp;

typedef Cls *(*FnCopyClassList)(unsigned int *);
typedef const char *(*FnClassName)(Cls);
typedef Method *(*FnCopyMethodList)(Cls, unsigned int *);
typedef Sel (*FnMethodName)(Method);
typedef const char *(*FnSelName)(Sel);
typedef Imp (*FnMethodImp)(Method);
typedef Cls (*FnMetaClass)(const char *);

struct Api
{
    FnCopyClassList copy_classes = nullptr;
    FnClassName class_name = nullptr;
    FnCopyMethodList copy_methods = nullptr;
    FnMethodName method_name = nullptr;
    FnSelName sel_name = nullptr;
    FnMethodImp method_imp = nullptr;
    FnMetaClass meta_class = nullptr;

    bool ready() const
    {
        return copy_classes && class_name && copy_methods && method_name && sel_name && method_imp;
    }
};

Api api()
{
    Api a;
    a.copy_classes = (FnCopyClassList)dlsym(RTLD_DEFAULT, "objc_copyClassList");
    a.class_name = (FnClassName)dlsym(RTLD_DEFAULT, "class_getName");
    a.copy_methods = (FnCopyMethodList)dlsym(RTLD_DEFAULT, "class_copyMethodList");
    a.method_name = (FnMethodName)dlsym(RTLD_DEFAULT, "method_getName");
    a.sel_name = (FnSelName)dlsym(RTLD_DEFAULT, "sel_getName");
    a.method_imp = (FnMethodImp)dlsym(RTLD_DEFAULT, "method_getImplementation");
    a.meta_class = (FnMetaClass)dlsym(RTLD_DEFAULT, "objc_getMetaClass");
    return a;
}

void scan_class(const Api &a, Cls cls, const char *cname, bool meta, const Image &img,
                std::set<uint64_t> &seen, std::vector<ObjcSymbol> &out)
{
    unsigned int count = 0;
    Method *methods = a.copy_methods(cls, &count);
    for (unsigned int i = 0; methods && i < count; i++)
    {
        const Sel s = a.method_name(methods[i]);
        const Imp imp = a.method_imp(methods[i]);
        const char *sname = s ? a.sel_name(s) : nullptr;
        if (!sname || !*sname)
            continue;
        const uint64_t addr = (uint64_t)(uintptr_t)imp;
        if (addr < img.base)
            continue;
        const uint64_t rva = addr - img.base;
        if (img.image_vmsize && rva >= img.image_vmsize)
            continue;
        if (!seen.insert(rva).second)
            continue;
        ObjcSymbol sym;
        sym.rva = rva;
        sym.cls = cname;
        sym.sel = sname;
        sym.meta = meta;
        out.push_back(sym);
    }
    if (methods)
        free(methods);
}

} // namespace

size_t objc_collect(const Image &img, std::vector<ObjcSymbol> &out)
{
    const Api a = api();
    if (!a.ready())
    {
        RCL_LOGLN("[objc] runtime unavailable, skipping symbolisation");
        return 0;
    }
    unsigned int count = 0;
    Cls *classes = a.copy_classes(&count);
    if (!classes)
    {
        RCL_LOGLN("[objc] no classes");
        return 0;
    }
    std::set<uint64_t> seen;
    unsigned int meta_classes = 0;
    for (unsigned int i = 0; i < count; i++)
    {
        const char *cname = a.class_name(classes[i]);
        if (!cname || !*cname)
            continue;
        scan_class(a, classes[i], cname, false, img, seen, out);
        if (a.meta_class)
        {
            Cls meta = a.meta_class(cname);
            if (meta)
                scan_class(a, meta, cname, true, img, seen, out);
        }
    }
    (void)meta_classes;
    free(classes);
    RCL_LOGLN("[objc] classes %u, methods in image %zu", count, out.size());
    return out.size();
}

void objc_names(const std::vector<ObjcSymbol> &in, NameTable &names)
{
    size_t i = 0;
    for (i = 0; i < in.size(); i++)
    {
        std::string n = in[i].meta ? "+[" : "-[";
        n += in[i].cls;
        n += " ";
        n += in[i].sel;
        n += "]";
        names.add(in[i].rva, n);
    }
}

size_t objc_class_count(const std::vector<ObjcSymbol> &in)
{
    std::set<std::string> cls;
    size_t i = 0;
    for (i = 0; i < in.size(); i++)
        cls.insert(in[i].cls);
    return cls.size();
}

} // namespace rcl
