/*
 * arm64_decode.js - minimal AArch64 reader used by the runtime logger.
 *
 * The point: when we hook the property getter 0xafd76c, the *field offset* is not in the getter,
 * it is in the caller - the instruction right after the `bl`. So on every call we peek at the
 * return address and decode the first store to W0 we find there. That turns
 *   mov w1,#id ; bl getter ; strb w0,[x19,#field]
 * into a live (id -> field) pair without any static scan.
 *
 * Kept dependency-free and dual-usable: Frida loads it by concatenation (see tools/run_agent.py),
 * Node loads it via require() in test/decode_test.js, so the tested code is the shipped code.
 *
 * getU32(k) must return the 32-bit word at instruction index k, little-endian.
 */

function rclDecodeStoreToW0(getU32, maxInsns) {
    const n = maxInsns || 8;
    for (let k = 0; k < n; k++) {
        const w = getU32(k) >>> 0;

        // STRB W0, [Xn, #imm]   (size=00, unsigned offset)
        if ((w & 0xFFC0001F) === 0x39000000) {
            return { kind: "strb", off: (w >>> 10) & 0xFFF, bytes: 1 };
        }
        // STR W0, [Xn, #imm]
        if ((w & 0xFFC0001F) === 0xB9000000) {
            return { kind: "str", off: ((w >>> 10) & 0xFFF) * 4, bytes: 4 };
        }
        // STR X0, [Xn, #imm]
        if ((w & 0xFFC0001F) === 0xF9000000) {
            return { kind: "strx", off: ((w >>> 10) & 0xFFF) * 8, bytes: 8 };
        }
        // STURB W0, [Xn, #simm9]  (unscaled, pre/post indexed forms)
        if ((w & 0xFFE00C1F) === 0x38000000) {
            let i9 = (w >>> 12) & 0x1FF;
            if (i9 & 0x100) i9 -= 0x200;
            return { kind: "sturb", off: i9, bytes: 1 };
        }
        // STUR W0, [Xn, #simm9]
        if ((w & 0xFFE00C1F) === 0xB8000000) {
            let i9 = (w >>> 12) & 0x1FF;
            if (i9 & 0x100) i9 -= 0x200;
            return { kind: "stur", off: i9, bytes: 4 };
        }
        // STRB WZR, [Xn, #imm]  (Rt = 31) - a clear, also interesting
        if ((w & 0xFFC00000) === 0x39000000 && ((w & 0x1F) === 31)) {
            return { kind: "strb_zr", off: (w >>> 10) & 0xFFF, bytes: 1 };
        }
        // STP W0, W1, [Xn, #imm]  (a pair store, seen when two properties land together)
        if ((w & 0xFFC00000) === 0x29000000) {
            return { kind: "stp_w", off: ((w >>> 15) & 0x7F) * 4, bytes: 8 };
        }
    }
    return null;
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = { rclDecodeStoreToW0 };
}
