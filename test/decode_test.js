#!/usr/bin/env node
/*
 * decode_test.js - verifies the SHIPPED arm64 decoder against the REAL binary.
 *
 * The decoder in agent/arm64_decode.js is what runs on the device inside Frida. Rather than trust
 * it, this test runs the same code over the actual Nulls Brawl image: it finds every `bl 0xafd76c`
 * (the property getter), decodes the first store-to-W0 after each call, and checks the result
 * against the sites that were confirmed by hand in the static analysis.
 *
 *   RCL_BIN=/path/to/attach.txt node test/decode_test.js
 */
const fs = require("fs");
const { rclDecodeStoreToW0 } = require("../agent/arm64_decode.js");

const BASE = 0x100000000n;
const BIN = process.env.RCL_BIN || "/tmp/dl/attach.txt";
const GETTER = 0x100afd76cn;          // property-value getter (0xafd76c)
const TA = 0x100004000n, TEND = 0x100d8af60n;

// pairs confirmed by hand in the disassembly
const EXPECT = [
    { site: 0x9fa418n, off: 0x32d, kind: "strb" },
    { site: 0x9fa428n, off: 0x32e, kind: "strb" },
    { site: 0x9faa44n, off: 0x32e, kind: "strb" },
];

function main() {
    if (!fs.existsSync(BIN)) {
        console.error("binary not found:", BIN, "- set RCL_BIN");
        process.exit(2);
    }
    const buf = fs.readFileSync(BIN);
    const at = (va) => Number(va - BASE);

    function getU32From(va, k) {
        const o = at(va) + k * 4;
        if (o < 0 || o + 4 > buf.length) return 0xFFFFFFFF;
        return buf.readUInt32LE(o);
    }

    // 1) known sites must decode exactly
    let bad = 0;
    for (const e of EXPECT) {
        const retAddr = BASE + e.site + 4n;        // EXPECT holds RVAs; readers take VAs
        const dec = rclDecodeStoreToW0((k) => getU32From(retAddr, k), 8);
        const ok = dec && dec.off === e.off && dec.kind === e.kind;
        if (!ok) bad++;
        console.log(`${ok ? "PASS" : "FAIL"}  site 0x${e.site.toString(16)}  expected +0x${e.off.toString(16)} (${e.kind})  got ${dec ? "+0x" + dec.off.toString(16) + " (" + dec.kind + ")" : "null"}`);
    }

    // 2) sweep the whole image: every bl to the getter, decoded
    let sites = 0, decoded = 0;
    const hist = {};
    for (let va = TA; va < TEND; va += 4n) {
        const w = getU32From(va, 0) >>> 0;
        if (((w & 0xFC000000) >>> 0) !== 0x94000000) continue;   // >>> 0: & gives a signed int32
        let imm = w & 0x03FFFFFF;
        if (imm & 0x02000000) imm -= 0x04000000;
        if ((va + (BigInt(imm) << 2n)) !== GETTER) continue;
        sites++;
        const dec = rclDecodeStoreToW0((k) => getU32From(va + 4n, k), 8);
        if (dec) {
            decoded++;
            const key = dec.kind + "+0x" + dec.off.toString(16);
            hist[key] = (hist[key] || 0) + 1;
        }
    }
    console.log(`\nbl 0xafd76c sites: ${sites}, decoded a store-to-W0: ${decoded}`);
    const top = Object.entries(hist).sort((a, b) => b[1] - a[1]).slice(0, 12);
    for (const [k, n] of top) console.log(`   ${k}  x${n}`);

    if (bad) { console.error(`\n${bad} known site(s) failed`); process.exit(1); }
    if (decoded === 0) { console.error("\nno site decoded - decoder is broken"); process.exit(1); }
    console.log("\nall known sites decode correctly; decoder verified against the real image");
}

main();
