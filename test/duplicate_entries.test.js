"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for GHSA-p634-w6r4-rjp2:
// a ZIP archive can declare the same entry name twice. adm-zip kept every entry
// in its entry list but only the last one in its name lookup table, so
// getEntry(name) (table) and extractAllTo() (list) resolved one name to
// different content. An application validating an entry via getEntry() before
// extracting the archive could approve one file's bytes while a different
// file's bytes were written to disk under that name. Such archives must now be
// rejected outright.

const DUPLICATE_ERROR = /Duplicate entry name/;

// Build an archive whose STORED entries keep the given order (noSort), so the
// raw name bytes can be patched afterwards without touching any content.
function buildArchive(entries) {
    const zip = new Zip({ noSort: true });
    for (const { name, content } of entries) {
        const entry = zip.addFile(name, Buffer.from(content));
        entry.header.method = 0; // STORED
    }
    return zip.toBuffer();
}

// Overwrite every occurrence of `from` with `to` (same length) in the raw
// archive bytes, i.e. in both the local file header and the central directory.
function renameRaw(buffer, from, to) {
    const out = Buffer.from(buffer);
    const needle = Buffer.from(from);
    const replacement = Buffer.from(to);
    expect(replacement.length).to.equal(needle.length);
    let count = 0;
    let pos = out.indexOf(needle);
    while (pos !== -1) {
        replacement.copy(out, pos);
        count++;
        pos = out.indexOf(needle, pos + needle.length);
    }
    expect(count, "local + central header name").to.equal(2);
    return out;
}

// The advisory PoC: a.txt ("FIRST") and b.txt ("SECOND"), with the a.txt name
// rewritten to b.txt, so the archive holds "b.txt" twice, FIRST before SECOND.
function craftDuplicateArchive() {
    const archive = buildArchive([
        { name: "a.txt", content: "FIRST" },
        { name: "b.txt", content: "SECOND" }
    ]);
    return renameRaw(archive, "a.txt", "b.txt");
}

function errorOf(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    return null;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    const destination = pth.join(os.tmpdir(), "adm-zip-ghsa-p634-w6r4-rjp2");

    afterEach(() => rimraf.sync(destination));

    it("the crafted archive really declares the same name twice", () => {
        const buffer = craftDuplicateArchive();
        // count occurrences of the central directory names without parsing via adm-zip
        const name = Buffer.from("b.txt");
        let occurrences = 0;
        for (let pos = buffer.indexOf(name); pos !== -1; pos = buffer.indexOf(name, pos + 1)) occurrences++;
        expect(occurrences).to.equal(4); // 2 entries x (local header + central header)
        expect(buffer.indexOf(Buffer.from("a.txt"))).to.equal(-1);
    });

    it("getEntry() rejects an archive with a duplicated entry name instead of returning one of them", () => {
        const zip = new Zip(craftDuplicateArchive());
        const err = errorOf(() => zip.getEntry("b.txt"));
        expect(err, "getEntry() must not silently pick one duplicate").to.be.an("error");
        expect(err.message).to.match(DUPLICATE_ERROR);
    });

    it("getEntries(), readFile() and readAsText() reject an archive with a duplicated entry name", () => {
        const buffer = craftDuplicateArchive();
        expect(() => new Zip(buffer).getEntries()).to.throw(DUPLICATE_ERROR);
        expect(() => new Zip(buffer).readFile("b.txt")).to.throw(DUPLICATE_ERROR);
        expect(() => new Zip(buffer).readAsText("b.txt")).to.throw(DUPLICATE_ERROR);
    });

    it("extractAllTo() rejects the archive and writes nothing (no check/use split)", () => {
        const zip = new Zip(craftDuplicateArchive());
        expect(() => zip.extractAllTo(destination)).to.throw(DUPLICATE_ERROR);
        expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
    });

    it("validate-with-getEntry() then extractAllTo() can no longer approve one file and write another", () => {
        const zip = new Zip(craftDuplicateArchive());
        let validated = null;
        const err = errorOf(() => {
            // what a consumer does: inspect the named entry, then extract everything
            validated = zip.getEntry("b.txt").getData().toString();
            zip.extractAllTo(destination);
        });
        expect(err, "the duplicate must be rejected before anything is validated or extracted").to.be.an("error");
        expect(err.message).to.match(DUPLICATE_ERROR);
        expect(validated).to.equal(null);
        expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
    });

    it("extractAllToAsync() rejects the archive and writes nothing", async () => {
        const zip = new Zip(craftDuplicateArchive());
        let err = null;
        try {
            await zip.extractAllToAsync(destination);
        } catch (e) {
            err = e;
        }
        expect(err).to.be.an("error");
        expect(err.message).to.match(DUPLICATE_ERROR);
        expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
    });

    it("eager loading (readEntries: true) rejects the archive at construction", () => {
        const buffer = craftDuplicateArchive();
        expect(() => new Zip(buffer, { readEntries: true })).to.throw(DUPLICATE_ERROR);
    });

    it("rejects names that differ in raw bytes but decode to the same entry name", () => {
        // 0xFF and 0xFE are both invalid UTF-8 and both decode to U+FFFD, so the
        // two entries end up with the same (decoded) name "�.txt"
        let buffer = buildArchive([
            { name: "a.txt", content: "FIRST" },
            { name: "b.txt", content: "SECOND" }
        ]);
        buffer = renameRaw(buffer, "a.txt", Buffer.from([0xff, 0x2e, 0x74, 0x78, 0x74]));
        buffer = renameRaw(buffer, "b.txt", Buffer.from([0xfe, 0x2e, 0x74, 0x78, 0x74]));
        expect(() => new Zip(buffer).getEntry("�.txt")).to.throw(DUPLICATE_ERROR);
        expect(() => new Zip(buffer).extractAllTo(destination)).to.throw(DUPLICATE_ERROR);
    });

    it("rejects a duplicated __proto__ entry name", () => {
        let buffer = buildArchive([
            { name: "__protX__", content: "FIRST" },
            { name: "__proto__", content: "SECOND" }
        ]);
        buffer = renameRaw(buffer, "__protX__", "__proto__");
        expect(() => new Zip(buffer).getEntry("__proto__")).to.throw(DUPLICATE_ERROR);
        expect(() => new Zip(buffer).extractAllTo(destination)).to.throw(DUPLICATE_ERROR);
        expect({}.entryName).to.equal(undefined);
    });

    it("does not mistake Object.prototype member names for duplicates", () => {
        const names = ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__", "__defineGetter__"];
        const zip = new Zip(buildArchive(names.map((name) => ({ name, content: "content of " + name }))));
        expect(zip.getEntries().map((e) => e.entryName)).to.deep.equal(names);
        for (const name of names) {
            expect(zip.readAsText(name)).to.equal("content of " + name);
        }
    });

    it("still loads archives whose entries only share a base name", () => {
        const zip = new Zip(
            buildArchive([
                { name: "b.txt", content: "ROOT" },
                { name: "dir/b.txt", content: "NESTED" },
                { name: "B.txt", content: "UPPER" }
            ])
        );
        expect(zip.getEntries().map((e) => e.entryName)).to.deep.equal(["b.txt", "dir/b.txt", "B.txt"]);
        expect(zip.readAsText("b.txt")).to.equal("ROOT");
        expect(zip.readAsText("dir/b.txt")).to.equal("NESTED");
        expect(zip.readAsText("B.txt")).to.equal("UPPER");
    });
});
