#!/usr/bin/env python3
"""offline precompute for the recoil classdump: table rva -> class name.

The device build has no C++ symbols and no RTTI for the game's own classes, so every
name has to come from a string or from structure. Doing that on the device is a single
pass with no way to look twice; doing it here costs nothing and lets the run apply a
finished map. Sources, in priority order:

  1. exact method-address index - a documented method address that sits in ONE table
     only (an address shared by many tables is a base-class method and names nothing);
  2. 'Class::method' said by the string itself - reference-free;
  3. an optional _strings.md from a previous run, for (2) over real anchors.

writes Sources/rcl_tablenames.h
usage: python3 tools/tablenames.py [--strings _strings.md] [--check]
"""
import argparse
import collections
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCDATA = os.path.join(ROOT, "Sources", "rcl_docdata.h")
OUT = os.path.join(ROOT, "Sources", "rcl_tablenames.h")


def docs_root():
    for cand in (os.path.join(ROOT, "classes_docs"),
                 os.path.join(os.path.dirname(ROOT), "classes_docs")):
        if os.path.isdir(cand):
            return cand
    return os.path.join(ROOT, "classes_docs")


DOCS = docs_root()
UNKNOWN = os.path.join(DOCS, "Unknown")

CLASS_RE = re.compile(r"(?:^|[^A-Za-z0-9_:])([A-Z][A-Za-z0-9_]{2,})::([A-Za-z_~][A-Za-z0-9_]*)")
TABLE_RE = re.compile(r"Class Table:\*\*\s*`(0x[0-9a-f]+)`\s*\*\*Slots:\*\*\s*(\d+)")
SLOT_RE = re.compile(r"\| `\+0x[0-9a-f]+` \| `(0x[0-9a-f]+)` \|")
METHOD_RE = re.compile(r"\|\s*\d+\s*\|\s*`[^`]+`\s*\|\s*`(0x[0-9a-f]+)`")
ANCHOR_RE = re.compile(r"^\| `(0x[0-9a-f]+)` \| `(0x[0-9a-f]+)` \| .*? \| `(.*)` \|")


def decode_c(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(s):
            break
        e = s[i]
        if e in "01234567":
            j = i
            while j < len(s) and j < i + 3 and s[j] in "01234567":
                j += 1
            out.append(chr(int(s[i:j], 8)))
            i = j
            continue
        out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(e, e))
        i += 1
    return "".join(out)


def doc_methods():
    src = open(DOCDATA, encoding="utf-8", errors="replace").read()
    st = src.index("static const DocMethod kDocMethods[] =")
    en = src.index("static const DocClass kDocClasses[]")
    blob_src = src[src.index("static const char kDocBlob[] ="):en]
    blob = "".join(decode_c(p) for p in re.findall(r'"((?:[^"\\]|\\.)*)"', blob_src))

    def cstr(o):
        e = blob.find("\0", o)
        return blob[o:e if e >= 0 else len(blob)]

    methods = [int(m.group(1), 0) for m in
               re.finditer(r"^\s*\{\s*(0x[0-9a-fA-F]+|\d+),\s*\d+,\s*\d+,\s*\d+,\s*\d+\s*\},?\s*$",
                           src[st:en], re.M)]
    m2c = {}
    for m in re.finditer(r"^\s*\{\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(0x[0-9a-fA-F]+|\d+),"
                         r"\s*(\d+),\s*(\d+),\s*(\d+)\s*\},?\s*$", src[en:], re.M):
        _, _, _, _, vt, _, first, count = (int(x, 0) for x in m.groups())
        name = cstr(int(m.group(1)))
        for k in range(first, first + count):
            if k < len(methods):
                m2c[methods[k]] = name
        _ = vt
    return m2c


def table_slots():
    tabs = {}
    if not os.path.isdir(UNKNOWN):
        return tabs
    for f in os.listdir(UNKNOWN):
        if not f.endswith(".md"):
            continue
        t = open(os.path.join(UNKNOWN, f), encoding="utf-8", errors="replace").read()
        m = TABLE_RE.search(t)
        if not m:
            continue
        tabs[int(m.group(1), 16)] = [int(s, 16) for s in SLOT_RE.findall(t)]
    return tabs


def documented_methods_by_class():
    out = {}
    for cat in os.listdir(DOCS):
        d = os.path.join(DOCS, cat)
        if cat in ("Unknown", "docs") or not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if not f.endswith(".md"):
                continue
            txt = open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
            for a in METHOD_RE.findall(txt):
                v = int(a, 16)
                out.setdefault(v - 0x100000000 if v > 0x100000000 else v, f[:-3])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strings", help="a _strings.md from an earlier run")
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    args = ap.parse_args()

    m2c = doc_methods()
    direct = documented_methods_by_class()
    for rva, cls in direct.items():
        m2c.setdefault(rva, cls)
    tabs = table_slots()
    if not tabs:
        raise SystemExit("no table files under classes_docs/Unknown - run the dump first")

    occ = collections.Counter()
    for sv in tabs.values():
        for s in set(sv):
            if s in m2c:
                occ[s] += 1

    seed = {}
    votes = collections.defaultdict(collections.Counter)
    for tab, sv in tabs.items():
        for s in set(sv):
            if s in m2c and occ[s] == 1:
                votes[tab][m2c[s]] += 1
    exact = {}
    for tab, c in votes.items():
        name, n = c.most_common(1)[0]
        exact[tab] = name
        del n
    seed.update(exact)
    print("exact method-address match (address used by exactly one table): %d tables" % len(exact))

    own = {}
    if args.strings and os.path.exists(args.strings):
        for line in open(args.strings, encoding="utf-8", errors="replace"):
            m = ANCHOR_RE.match(line.rstrip())
            if not m:
                continue
            tab, s = int(m.group(2), 16), m.group(3)
            mm = CLASS_RE.search(s)
            if mm:
                own.setdefault(tab, collections.Counter())[mm.group(1)] += 1
        own = {t: c.most_common(1)[0][0] for t, c in own.items()}
        print("'Class::method' from %s: %d tables" % (args.strings, len(own)))
    else:
        print("'Class::method': skipped (no --strings)")

    new = 0
    for t, c in own.items():
        old = seed.get(t)
        if old is not None and old != c:
            print("  keep %#x -> %s (string said %s)" % (t, old, c))
            continue
        if old is None:
            new += 1
        seed[t] = c
    print("seed total: %d (%d from strings)" % (len(seed), new))

    if args.check:
        return
    lines = ["// generated by tools/tablenames.py - offline table rva -> class name map",
             "// sources: exact method-address index (rcl_docdata.h + classes_docs), "
             "'Class::method' strings", "#pragma once", "", "#include <stdint.h>", "",
             "namespace rcl {", "", "struct SeedName {", "    uint32_t vt;",
             "    const char *name;", "};", "", "static const SeedName kSeedNames[] = {"]
    for t in sorted(seed):
        lines.append('    { %#x, "%s" },' % (t, seed[t]))
    lines += ["};", "", "static const uint32_t kSeedNameCount = %d;" % len(seed), "",
              "}  // namespace rcl", ""]
    open(OUT, "w", encoding="utf-8").write("\n".join(lines))
    print("wrote %s (%d entries)" % (OUT, len(seed)))


if __name__ == "__main__":
    main()
