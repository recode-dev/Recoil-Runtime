#!/usr/bin/env python3
"""inject.py - add an LC_LOAD_DYLIB to a Mach-O so the app loads our dylib at launch.

No external tools (no insert_dylib / optool). Handles thin arm64/arm64e and fat (universal)
binaries: every slice gets the command, each inside its own header slack.

  inject.py --dylib @executable_path/Frameworks/RecoilRuntime.dylib --target <macho> [--out <path>] [--dry-run]

What it does per slice:
  * appends an LC_LOAD_DYLIB to the load-command block, growing ncmds/sizeofcmds
  * refuses if the block would grow past the first section's file offset (no blind relocation)
  * leaves every byte outside the load-command block untouched

What it deliberately does NOT do: re-sign. Changing the header invalidates the signature, so after
this you must re-sign the binary (ldid / codesign) - see tools/package.sh.
"""
import argparse
import shutil
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def align4(n):
    return (n + 3) & ~3


class Slice:
    def __init__(self, data, off, size):
        self.data = data          # whole file (bytearray)
        self.off = off            # slice start in the file
        self.size = size


def dylib_command(path):
    raw = path.encode() + b"\0"
    cmdsize = align4(24 + len(raw))
    cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 0, 0x00010000, 0x00010000)
    return cmd + raw.ljust(cmdsize - 24, b"\0"), cmdsize


def first_section_offset(buf, slice_off, ncmds):
    """smallest file offset among all sections, i.e. where real data starts"""
    p = slice_off + 32
    lo = None
    for _ in range(ncmds):
        cmd = u32(buf, p)
        cmdsize = u32(buf, p + 4)
        if cmd == LC_SEGMENT_64:
            nsects = u32(buf, p + 64)
            for i in range(nsects):
                s = p + 72 + i * 80
                if u32(buf, s + 32) or u32(buf, s + 36):      # section has data
                    if lo is None or u32(buf, s + 48) < lo:   # offset field
                        pass
                    off = u32(buf, s + 48)
                    if off and (lo is None or off < lo):
                        lo = off
        p += cmdsize
    return lo


def inject_thin(buf, slice_off, slice_size, path, dry_run):
    magic = u32(buf, slice_off)
    if magic != MH_MAGIC_64:
        return None, f"not a 64-bit Mach-O (magic 0x{magic:08x})"
    ncmds = u32(buf, slice_off + 16)
    sizeofcmds = u32(buf, slice_off + 20)
    lc_start = slice_off + 32
    lc_end = lc_start + sizeofcmds

    cmd, cmdsize = dylib_command(path)

    # already present?
    p = lc_start
    for _ in range(ncmds):
        c = u32(buf, p)
        cs = u32(buf, p + 4)
        if c == LC_LOAD_DYLIB:
            noff = u32(buf, p + 8)
            s = bytes(buf[p + noff:p + cs]).split(b"\0")[0].decode(errors="replace")
            if s == path:
                return 0, "already injected"
        p += cs

    limit = first_section_offset(buf, slice_off, ncmds)
    if limit is None:
        limit = lc_end + 0x1000          # no sections with data: fall back to slack after the block
    room = limit - lc_end
    if room < cmdsize:
        return None, (f"only {room} free bytes after the load commands, need {cmdsize}; "
                      f"nothing was changed")

    if dry_run:
        return cmdsize, f"would add {cmdsize} bytes into {room} free"

    buf[lc_end:lc_end + cmdsize] = cmd
    struct.pack_into("<I", buf, slice_off + 16, ncmds + 1)
    struct.pack_into("<I", buf, slice_off + 20, sizeofcmds + cmdsize)
    return cmdsize, f"added, {room - cmdsize} bytes of slack left"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Mach-O to modify")
    ap.add_argument("--dylib", required=True, help="load path, e.g. @executable_path/Frameworks/X.dylib")
    ap.add_argument("--out", help="write here instead of in place")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    with open(a.target, "rb") as f:
        buf = bytearray(f.read())

    magic_be = struct.unpack_from(">I", buf, 0)[0]
    slices = []
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack_from(">I", buf, 4)[0]
        step = 20 if magic_be == FAT_MAGIC else 32
        for i in range(nfat):
            base = 8 + i * step
            cputype = struct.unpack_from(">i", buf, base)[0]
            off = struct.unpack_from(">I", buf, base + 8)[0]
            size = struct.unpack_from(">I", buf, base + 12)[0]
            if cputype in (0x0100000C, 0x0200000C):          # arm64 / arm64e
                slices.append((cputype, off, size))
        if not slices:
            print("fat image has no arm64 slice", file=sys.stderr)
            return 2
        print(f"fat image: {len(slices)} arm64 slice(s)")
    else:
        slices.append((struct.unpack_from("<I", buf, 4)[0], 0, len(buf)))
        print("thin image")

    rc = 0
    for cputype, off, size in slices:
        extra, msg = inject_thin(buf, off, size, a.dylib, a.dry_run)
        name = "arm64e" if cputype == 0x0200000C else "arm64"
        if extra is None:
            print(f"  {name} @0x{off:x}: FAILED - {msg}")
            rc = 1
        else:
            print(f"  {name} @0x{off:x}: {msg}")

    if rc == 0 and not a.dry_run:
        dest = a.out or a.target
        if a.out:
            shutil.copyfile(a.target, a.out)
            with open(a.out, "wb") as f:
                f.write(buf)
        else:
            with open(a.target, "wb") as f:
                f.write(buf)
        print(f"written: {dest}")
        print("NOTE: the code signature is now invalid - re-sign before installing")
    return rc


if __name__ == "__main__":
    sys.exit(main())
