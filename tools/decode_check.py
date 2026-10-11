#!/usr/bin/env python3
"""Differential test for src/core/rcl_disasm.cpp against capstone.

Samples A64 words out of a Mach-O __TEXT, decodes them with both the Recoil decoder and
capstone, and reports decode gaps plus real mismatches (mnemonic aliases and number
formatting are normalised away).

    pip install capstone
    python3 tools/decode_check.py <macho> [samples] [stride]

The reference binary is not shipped with the repo; point this at the client you dumped.
"""
import collections
import os
import random
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

ALIAS = {
    ("mov", "movz"), ("mov", "movn"), ("mov", "add"), ("mov", "orr"), ("mov", "movi"),
    ("mul", "madd"), ("neg", "sub"), ("ror", "extr"), ("lsl", "lslv"), ("lsr", "lsrv"),
    ("asr", "asrv"), ("cset", "csel"), ("cinc", "csinc"), ("cinv", "csinv"), ("cneg", "csneg"),
    ("cmp", "subs"), ("cmn", "adds"), ("tst", "ands"), ("mvn", "orn"),
    ("smull", "madd"), ("umull", "madd"), ("smaddl", "madd"), ("umaddl", "madd"),
    ("ldr", "ldur"), ("str", "stur"), ("b.hs", "b.cs"), ("b.lo", "b.cc"),
    ("csel", "csinc"), ("csel", "csinv"), ("csel", "csneg"),
}


def text_range(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    size = 0
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8:off + 24].split(b"\0")[0].decode()
            if name == "__TEXT":
                size = struct.unpack_from("<Q", data, off + 24 + 24)[0]
        off += sz
    return min(size, len(data))


def nums(text):
    out = []
    for tok in re.findall(r"#?-?0x[0-9a-fA-F]+|#?-?\d+(?:\.\d+)?", text):
        tok = tok.lstrip("#")
        try:
            out.append(float(int(tok, 16)) if "0x" in tok else float(tok))
        except ValueError:
            pass
    return out


def norm(text):
    text = text.lower().replace("#", "")
    text = re.sub(r"\s+", "", text)
    text = text.replace("[", "").replace("]", "")
    text = re.sub(r",0x0$|,0$", "", text)
    return text


def build_helper():
    out = os.path.join(tempfile.gettempdir(), "recoil_decode_words")
    inc = ["-I" + os.path.join(ROOT, "src"), "-I" + os.path.join(ROOT, "src", "core"),
           "-I" + os.path.join(ROOT, "src", "scan"), "-I" + os.path.join(ROOT, "src", "utils")]
    srcs = [os.path.join(HERE, "decode_words.cpp"),
            os.path.join(ROOT, "src", "core", "rcl_disasm.cpp"),
            os.path.join(ROOT, "src", "core", "rcl_syms.cpp"),
            os.path.join(ROOT, "src", "core", "rcl_scan.cpp"),
            os.path.join(ROOT, "src", "scan", "rcl_objects.cpp"),
            os.path.join(ROOT, "src", "core", "rcl_code.cpp"),
            os.path.join(ROOT, "src", "core", "rcl_log.cpp")]
    subprocess.run(["g++", "-std=c++17", "-O1", "-o", out] + inc + srcs,
                   check=True, cwd=ROOT)
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 40000
    stride = int(sys.argv[3]) if len(sys.argv) > 3 else 7
    import capstone

    data = open(binary, "rb").read()
    limit = text_range(data)
    random.seed(1234)
    offs = list(range(0x4000, limit - 4, 4 * stride))
    random.shuffle(offs)
    words = [struct.unpack_from("<I", data, o)[0] for o in offs[:samples]]

    helper = build_helper()
    payload = "".join("%08x\n" % w for w in words)
    proc = subprocess.run([helper], input=payload, capture_output=True, text=True)
    mine = dict(l.split("\t", 1) for l in proc.stdout.splitlines() if "\t" in l)

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.skipdata = True

    stat = collections.Counter()
    gaps = collections.Counter()
    real_mn = collections.Counter()
    real_op = collections.Counter()
    ex = collections.defaultdict(list)

    for w in words:
        t = mine.get("%08x" % w, ".word 0x%08x" % w)
        mymn = t.split(" ", 1)[0]
        myops = t.split(" ", 1)[1] if " " in t else ""
        ins = list(md.disasm(struct.pack("<I", w), 0))
        if not ins:
            stat["reference_refuses"] += 1
            continue
        cmn, cops = ins[0].mnemonic, ins[0].op_str
        stat["reference_decodes"] += 1
        if mymn == ".word":
            stat["gap"] += 1
            gaps[cmn] += 1
            if len(ex["gap_" + cmn]) < 3:
                ex["gap_" + cmn].append("%s %s" % (cmn, cops))
            continue
        stat["mine_decodes"] += 1
        if mymn != cmn:
            if (cmn, mymn) in ALIAS or (mymn, cmn) in ALIAS:
                stat["alias"] += 1
                continue
            real_mn[(cmn, mymn)] += 1
            if len(ex["mn_" + cmn + "_" + mymn]) < 3:
                ex["mn_" + cmn + "_" + mymn].append((t, "%s %s" % (cmn, cops)))
            continue
        if norm(myops) != norm(cops) and nums(myops) != nums(cops):
            real_op[cmn] += 1
            if len(ex["op_" + cmn]) < 3:
                ex["op_" + cmn].append((t, "%s %s" % (cmn, cops)))

    total = max(1, stat["reference_decodes"])
    print("sampled words          : %d" % len(words))
    print("capstone decodes       : %d" % stat["reference_decodes"])
    print("recoil decodes         : %d (%.2f%%)" % (stat["mine_decodes"],
                                                   100.0 * stat["mine_decodes"] / total))
    print("recoil emits .word     : %d (%.2f%%)" % (stat["gap"], 100.0 * stat["gap"] / total))
    print("mnemonic alias only    : %d" % stat["alias"])
    print("REAL mnemonic mismatch : %d" % sum(real_mn.values()))
    print("REAL operand mismatch  : %d" % sum(real_op.values()))
    print()
    print("=== decode gaps (reference mnemonic -> count) ===")
    for k, v in gaps.most_common(25):
        print("  %-12s %5d   %s" % (k, v, ex["gap_" + k][0] if ex["gap_" + k] else ""))
    print()
    print("=== REAL mnemonic mismatches (reference -> recoil) ===")
    for (cmn, mymn), v in real_mn.most_common(25):
        e = ex["mn_" + cmn + "_" + mymn][0]
        print("  %-10s -> %-10s %5d   mine: %-30s ref: %s" % (cmn, mymn, v, e[0], e[1]))
    print()
    print("=== REAL operand mismatches ===")
    for k, v in real_op.most_common(20):
        e = ex["op_" + k][0]
        print("  %-10s %5d   mine: %-30s ref: %s" % (k, v, e[0], e[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
