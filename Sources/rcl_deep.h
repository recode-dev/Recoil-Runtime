#ifndef RCL_DEEP_H
#define RCL_DEEP_H

#include "rcl_classdump.h"
#include "rcl_macho.h"

#include <map>
#include <string>
#include <vector>

namespace rcl {

struct DeepStats {
    int fstarts_source = 0;
    uint32_t fstarts = 0;
    uint32_t fstarts_rejected = 0;
    uint32_t data_in_code = 0;

    uint32_t objc_classes = 0;
    uint32_t objc_methods = 0;
    uint32_t objc_cats = 0;
    uint32_t objc_selrefs = 0;
    uint32_t objc_methnames = 0;
    uint32_t swift_types = 0;

    uint32_t mangled_found = 0;
    uint32_t mangled_classes = 0;

    uint32_t loaders = 0;
    uint32_t field_pairs = 0;

    uint32_t accessors = 0;
    uint32_t getters = 0;
    uint32_t setters = 0;
    uint32_t accessors_owned = 0;

    uint32_t func_total = 0;
    uint32_t func_ctor = 0;
    uint32_t func_dtor = 0;
    uint32_t func_singletons = 0;
    uint32_t globals = 0;
    uint32_t globals_named = 0;

    uint32_t indirect_bases = 0;
    uint32_t indirect_calls = 0;
    uint32_t indirect_added = 0;

    uint32_t logic_files = 0;
    uint32_t logic_fields = 0;

    uint32_t heap_regions = 0;
    uint32_t heap_words = 0;
    uint32_t heap_vptrs = 0;
    uint32_t heap_tables = 0;

    uint32_t order_pairs = 0;
    uint32_t order_named = 0;
    uint32_t fp_written = 0;
    uint32_t fp_matched = 0;
    uint32_t fp_named = 0;
    uint32_t cache_names = 0;
};

void deep_macho_report(const Image &img, const MachInsight &mi, const FnStarts &fs,
                       const std::vector<SecRange> &dic, const char *root, DeepStats &st);
void deep_objc(const Image &img, const MachInsight &mi, const char *root, DeepStats &st);
void deep_mangled(const Image &img, const MachInsight &mi, const char *root, DeepStats &st);
void deep_fieldmap(const Image &img, const MachInsight &mi, const FnStarts &fs, const char *root,
                   DeepStats &st);
void deep_accessors(const Image &img, const MachInsight &mi, const FnStarts &fs,
                    const std::vector<ClassTable> &tables, const char *root, DeepStats &st);
void deep_functions(const Image &img, const MachInsight &mi, const FnStarts &fs,
                    const std::vector<ClassTable> &tables, const char *root, DeepStats &st);
void deep_globals(const Image &img, const MachInsight &mi, const FnStarts &fs,
                  const std::vector<ClassTable> &tables, const char *root, DeepStats &st);
void deep_indirect(const Image &img, const MachInsight &mi, const FnStarts &fs,
                   std::vector<ClassTable> &extra, DeepStats &st);
void deep_logic(const char *root, DeepStats &st);
void deep_heap(const Image &img, const MachInsight &mi, const FnStarts &fs, const char *root,
               DeepStats &st);
void deep_order(const Image &img, const MachInsight &mi, const std::vector<ClassTable> &tables,
                const std::map<uint32_t, std::string> &named, const char *root,
                std::map<uint32_t, std::string> &out, DeepStats &st);
void deep_fingerprints(const Image &img, const MachInsight &mi, const FnStarts &fs,
                       const std::vector<ClassTable> &tables,
                       const std::map<uint32_t, std::string> &named, const char *root,
                       std::map<uint32_t, std::string> &carried, DeepStats &st);
void deep_cache_load(const char *root, const char *uuid, std::map<uint32_t, std::string> &names,
                     DeepStats &st);
void deep_cache_save(const char *root, const char *uuid,
                     const std::map<uint32_t, std::string> &names);
void write_deep_summary(const MachInsight &mi, const char *root, const DeepStats &st);

bool demangle_itanium(const char *m, std::string &out);
const char *deep_ref_class(uint32_t vt);

}

#endif
