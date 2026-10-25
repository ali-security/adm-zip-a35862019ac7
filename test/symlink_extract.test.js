"use strict";

// Extraction only sanitized entry names textually: a symlink (or Windows
// junction) that already exists inside the target directory was silently
// followed by mkdir()/open()/utimes(), so a crafted archive could create or
// overwrite files outside the extraction root. Every write path now rejects a
// destination whose path below the root goes through a symlink.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");

const isWin = process.platform === "win32";
const IN_THE_WAY = /There is a file in the way/;

// symlink creation can be refused on Windows without the required privilege
function skipWhenUnsupported(ctx, err) {
    if (err && (err.code === "EPERM" || err.code === "EACCES" || err.code === "ENOSYS")) ctx.skip();
    throw err;
}

// directory link: a junction on Windows (needs no privilege), a dir symlink elsewhere
function linkDir(ctx, linkTarget, linkPath) {
    try {
        fs.symlinkSync(pth.resolve(linkTarget), linkPath, isWin ? "junction" : "dir");
    } catch (err) {
        skipWhenUnsupported(ctx, err);
    }
}

// file symlink (may be dangling)
function linkFile(ctx, linkTarget, linkPath) {
    try {
        fs.symlinkSync(pth.resolve(linkTarget), linkPath, "file");
    } catch (err) {
        skipWhenUnsupported(ctx, err);
    }
}

// build an archive the way an attacker would ship it (null content = directory entry)
function makeZip(entries) {
    const zip = new Zip();
    entries.forEach(function (e) {
        zip.addFile(e[0], e[1] === null ? null : Buffer.from(e[1]));
    });
    return new Zip(zip.toBuffer());
}

describe("ADM-ZIP - extraction through pre-existing symlinks", function () {
    let base, target, outside;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        target = pth.join(base, "target");
        outside = pth.join(base, "outside");
        fs.mkdirSync(target);
        fs.mkdirSync(outside);
    });

    afterEach(function (done) {
        rimraf(base, done);
    });

    describe("extractAllTo", function () {
        it("does not write a file through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["evil/pwned.txt", "owned"]]);

            assert.throws(() => zip.extractAllTo(target), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("does not write a file through a symlinked directory nested below the root", function () {
            fs.mkdirSync(pth.join(target, "sub"));
            linkDir(this, outside, pth.join(target, "sub", "evil"));
            const zip = makeZip([["sub/evil/deep/pwned.txt", "owned"]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["evil/newdir/", null]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("does not overwrite a file outside the root through a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "original");
            linkFile(this, victim, pth.join(target, "link.txt"));
            const zip = makeZip([["link.txt", "owned"]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.strictEqual(fs.readFileSync(victim, "utf8"), "original");
            assert.deepStrictEqual(fs.readdirSync(outside), ["victim.txt"]);
        });

        it("does not create a file outside the root through a dangling symlink", function () {
            linkFile(this, pth.join(outside, "created.txt"), pth.join(target, "dangling.txt"));
            const zip = makeZip([["dangling.txt", "owned"]]);

            assert.throws(() => zip.extractAllTo(target), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("still extracts when the extraction root itself is a symlink", function () {
            const realRoot = pth.join(base, "real");
            fs.mkdirSync(realRoot);
            const rootLink = pth.join(base, "rootlink");
            linkDir(this, realRoot, rootLink);
            fs.mkdirSync(pth.join(realRoot, "existing"));
            const zip = makeZip([
                ["a/", null],
                ["a/b.txt", "hello"],
                ["existing/c.txt", "world"]
            ]);

            zip.extractAllTo(rootLink, true);
            assert.strictEqual(fs.readFileSync(pth.join(realRoot, "a", "b.txt"), "utf8"), "hello");
            assert.strictEqual(fs.readFileSync(pth.join(realRoot, "existing", "c.txt"), "utf8"), "world");
        });
    });

    describe("extractEntryTo", function () {
        it("does not write a file entry through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["evil/pwned.txt", "owned"]]);

            assert.throws(() => zip.extractEntryTo("evil/pwned.txt", target, true, true), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("does not write through a symlinked directory named by outFileName", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["safe.txt", "owned"]]);

            assert.throws(() => zip.extractEntryTo("safe.txt", target, false, true, false, "evil/renamed.txt"), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("does not overwrite a file outside the root through a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "original");
            linkFile(this, victim, pth.join(target, "link.txt"));
            const zip = makeZip([["link.txt", "owned"]]);

            assert.throws(() => zip.extractEntryTo("link.txt", target, true, true), IN_THE_WAY);
            assert.strictEqual(fs.readFileSync(victim, "utf8"), "original");
        });

        it("does not write the children of a directory entry through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([
                ["evil/", null],
                ["evil/a.txt", "owned"]
            ]);

            assert.throws(() => zip.extractEntryTo("evil/", target, true, true), IN_THE_WAY);
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });

        it("still extracts into a real directory inside the root", function () {
            fs.mkdirSync(pth.join(target, "real"));
            const zip = makeZip([["real/ok.txt", "fine"]]);

            assert.strictEqual(zip.extractEntryTo("real/ok.txt", target, true, true), true);
            assert.strictEqual(fs.readFileSync(pth.join(target, "real", "ok.txt"), "utf8"), "fine");
        });
    });

    describe("extractAllToAsync", function () {
        it("does not write a file through a symlinked directory (callback)", function (done) {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["evil/pwned.txt", "owned"]]);

            let finished = false;
            zip.extractAllToAsync(target, true, false, function (err) {
                if (finished) return;
                finished = true;
                try {
                    assert.ok(err instanceof Error, "expected an error");
                    assert.ok(IN_THE_WAY.test(err.message), err.message);
                    assert.deepStrictEqual(fs.readdirSync(outside), []);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("does not create a directory through a symlinked directory (callback)", function (done) {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["evil/newdir/", null]]);

            let finished = false;
            zip.extractAllToAsync(target, true, false, function (err) {
                // the first callback carries the outcome of the directory pass
                if (finished) return;
                finished = true;
                try {
                    assert.ok(err instanceof Error, "expected an error");
                    assert.deepStrictEqual(fs.readdirSync(outside), []);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("rejects writing through a symlinked directory (promise)", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const zip = makeZip([["evil/pwned.txt", "owned"]]);

            return zip.extractAllToAsync(target, true, false).then(
                function () {
                    throw new Error("expected extractAllToAsync to reject");
                },
                function (err) {
                    assert.ok(IN_THE_WAY.test(err.message), err.message);
                    assert.deepStrictEqual(fs.readdirSync(outside), []);
                }
            );
        });

        it("does not create a file outside the root through a dangling symlink", function (done) {
            linkFile(this, pth.join(outside, "created.txt"), pth.join(target, "dangling.txt"));
            const zip = makeZip([["dangling.txt", "owned"]]);

            let finished = false;
            zip.extractAllToAsync(target, false, false, function (err) {
                if (finished) return;
                finished = true;
                try {
                    assert.ok(err instanceof Error, "expected an error");
                    assert.deepStrictEqual(fs.readdirSync(outside), []);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("still extracts when the extraction root itself is a symlink", function () {
            const realRoot = pth.join(base, "real");
            fs.mkdirSync(realRoot);
            const rootLink = pth.join(base, "rootlink");
            linkDir(this, realRoot, rootLink);
            const zip = makeZip([
                ["a/", null],
                ["a/b.txt", "hello"]
            ]);

            return zip.extractAllToAsync(rootLink, true, false).then(function () {
                assert.strictEqual(fs.readFileSync(pth.join(realRoot, "a", "b.txt"), "utf8"), "hello");
            });
        });
    });

    describe("Utils.assertPathSafe", function () {
        it("rejects a path with a symlinked component below the root", function () {
            fs.mkdirSync(pth.join(target, "sub"));
            linkDir(this, outside, pth.join(target, "sub", "evil"));
            const utils = new Utils();

            assert.throws(() => utils.assertPathSafe(target, pth.join(target, "sub", "evil", "x.txt")), IN_THE_WAY);
            assert.throws(() => utils.assertPathSafe(target, pth.join(target, "sub", "evil")), IN_THE_WAY);
        });

        it("accepts the root itself, missing components and paths outside the root", function () {
            fs.mkdirSync(pth.join(target, "sub"));
            const rootLink = pth.join(base, "rootlink");
            linkDir(this, target, rootLink);
            const utils = new Utils();

            assert.doesNotThrow(() => utils.assertPathSafe(target, target));
            assert.doesNotThrow(() => utils.assertPathSafe(target, pth.join(target, "sub", "missing", "x.txt")));
            assert.doesNotThrow(() => utils.assertPathSafe(target, pth.join(outside, "x.txt")));
            // a symlinked root is the caller's choice
            assert.doesNotThrow(() => utils.assertPathSafe(rootLink, pth.join(rootLink, "sub", "x.txt")));
        });

        it("is a no-op for a custom fs without lstatSync", function () {
            linkDir(this, outside, pth.join(target, "evil"));
            const utils = new Utils({ fs: { statSync: fs.statSync } });

            assert.doesNotThrow(() => utils.assertPathSafe(target, pth.join(target, "evil", "x.txt")));
        });
    });
});
