"use strict";

const { expect } = require("chai");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// The RSS checks above depend on how eagerly the OS commits zero-filled pages.
// These tests make the same regression deterministic on every platform and Node
// version: Buffer.alloc is wrapped so that any request large enough to have been
// sized from the declared (attacker-controlled) uncompressed size fails fast
// instead of being committed, and the largest request is recorded.
describe("decompression bomb (declared size) - CVE-2026-39244 allocation guard", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024;
    const ALLOC_LIMIT = 64 * 1024 * 1024;
    const GUARD_ERROR = /declared-size allocation/;
    const destination = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244");

    const bombs = [
        { label: "STORED", method: 0, content: Buffer.from("A") },
        { label: "DEFLATED", method: 8, content: Buffer.from([0x00]) }
    ];

    let originalAlloc = null;
    let largest = 0;

    beforeEach(() => {
        originalAlloc = Buffer.alloc;
        largest = 0;
        Buffer.alloc = function (size) {
            if (typeof size === "number" && size > largest) largest = size;
            if (size > ALLOC_LIMIT) {
                throw new Error("declared-size allocation of " + size + " bytes");
            }
            return originalAlloc.apply(this, arguments);
        };
    });

    afterEach(() => {
        if (originalAlloc) {
            Buffer.alloc = originalAlloc;
            originalAlloc = null;
        }
        rimraf.sync(destination);
    });

    function errorOf(fn) {
        try {
            fn();
        } catch (err) {
            return err;
        }
        return null;
    }

    bombs.forEach(({ label, method, content }) => {
        it(`getData() rejects a ${label} entry without allocating the declared size`, () => {
            const entry = new Zip(craftBomb(DECLARED, method, content)).getEntries()[0];
            expect(entry.header.size).to.equal(DECLARED);

            const err = errorOf(() => entry.getData());
            expect(err).to.be.an("error");
            expect(err.message).to.not.match(GUARD_ERROR);
            if (method === 0) expect(err.message).to.match(/CRC32/);
            expect(largest).to.be.below(ALLOC_LIMIT);
        });

        it(`readFile(), readAsText(), test() and extractAllTo() reject a ${label} entry without allocating the declared size`, () => {
            const zip = new Zip(craftBomb(DECLARED, method, content));
            const readers = [() => zip.readFile("a"), () => zip.readAsText("a"), () => zip.extractAllTo(destination, true)];
            readers.forEach((read) => {
                const err = errorOf(read);
                expect(err).to.be.an("error");
                expect(err.message).to.not.match(GUARD_ERROR);
            });
            expect(zip.test()).to.equal(false);
            expect(largest).to.be.below(ALLOC_LIMIT);
        });
    });

    it("getDataAsync() reports a bad STORED entry without allocating the declared size", () => {
        const entry = new Zip(craftBomb(DECLARED, 0, Buffer.from("A"))).getEntries()[0];
        let reported = null;
        // the STORED branch reports through the callback and then also throws
        const thrown = errorOf(() =>
            entry.getDataAsync((data, err) => {
                reported = err;
            })
        );
        expect(reported).to.be.an("error");
        expect(reported.message).to.match(/CRC32/);
        if (thrown) expect(thrown.message).to.match(/CRC32/);
        expect(largest).to.be.below(ALLOC_LIMIT);
    });

    it("getDataAsync() reports a bad DEFLATED entry without allocating the declared size", (done) => {
        const entry = new Zip(craftBomb(DECLARED, 8, Buffer.from([0x00]))).getEntries()[0];
        entry.getDataAsync((data, err) => {
            try {
                expect(err).to.be.an("error");
                expect(err.message).to.not.match(GUARD_ERROR);
                expect(largest).to.be.below(ALLOC_LIMIT);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readFileAsync() reports a bad DEFLATED entry without allocating the declared size", (done) => {
        const zip = new Zip(craftBomb(DECLARED, 8, Buffer.from([0x00])));
        zip.readFileAsync("a", (data, err) => {
            try {
                expect(err).to.be.an("error");
                expect(err.message).to.not.match(GUARD_ERROR);
                expect(largest).to.be.below(ALLOC_LIMIT);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads legitimate STORED and DEFLATED entries, sync and async", (done) => {
        const stored = Buffer.from([1, 2, 3, 4, 5]);
        const deflated = Buffer.from("hello world ".repeat(5000));
        const zip = new Zip();
        zip.addFile("s.bin", stored);
        zip.getEntry("s.bin").header.method = 0;
        zip.addFile("d.txt", deflated);
        const round = new Zip(zip.toBuffer());

        expect(round.getEntry("s.bin").header.method).to.equal(0);
        expect(round.getEntry("d.txt").header.method).to.equal(8);
        expect(round.readFile("s.bin").equals(stored)).to.equal(true);
        expect(round.readFile("d.txt").equals(deflated)).to.equal(true);

        round.getEntry("s.bin").getDataAsync((sData, sErr) => {
            round.getEntry("d.txt").getDataAsync((dData, dErr) => {
                try {
                    expect(sErr).to.be.undefined;
                    expect(sData.equals(stored)).to.equal(true);
                    expect(dErr).to.be.undefined;
                    expect(dData.equals(deflated)).to.equal(true);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
    });
});
