"use strict";
const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods/inflater");
const Constants = require("../../util/constants");

// zlib's maxOutputLength is only passed to the synchronous inflater on Node >= 15
const nodeMajor = +process.versions.node.split(".")[0] || 0;
const syncCapSupported = nodeMajor >= 15;

const MAX_OUTPUT_EXCEEDED = /Decompressed data exceeds the declared uncompressed size/;

describe("method - inflater decompression bomb", () => {
    // highly compressible payload: 1 MiB of "a" deflates to ~1 KiB
    const payload = Buffer.alloc(1024 * 1024, 0x61);
    const deflated = zlib.deflateRawSync(payload);

    // Build an archive with a single DEFLATED entry and rewrite the declared
    // uncompressed size in both the local and the central header, leaving the
    // compressed data and crc-32 untouched so the crc check still passes.
    function bombZip(declaredSize) {
        const zip = new Zip();
        zip.addFile("bomb.txt", payload);
        const buf = zip.toBuffer();

        const endOffset = buf.length - Constants.ENDHDR;
        expect(buf.readUInt32LE(endOffset)).to.equal(Constants.ENDSIG);
        const cenOffset = buf.readUInt32LE(endOffset + Constants.ENDOFF);
        expect(buf.readUInt32LE(cenOffset)).to.equal(Constants.CENSIG);
        expect(buf.readUInt16LE(cenOffset + Constants.CENHOW)).to.equal(Constants.DEFLATED);
        const locOffset = buf.readUInt32LE(cenOffset + Constants.CENOFF);
        expect(buf.readUInt32LE(locOffset)).to.equal(Constants.LOCSIG);

        buf.writeUInt32LE(declaredSize, cenOffset + Constants.CENLEN);
        buf.writeUInt32LE(declaredSize, locOffset + Constants.LOCLEN);
        return buf;
    }

    describe("inflater sync", () => {
        it("caps output when the declared size is 0", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is not applied before Node 15
            const inflater = new Inflater(deflated, 0);
            expect(() => inflater.inflate()).to.throw(RangeError);
        });

        it("caps output when the declared size is smaller than the data", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is not applied before Node 15
            const inflater = new Inflater(deflated, 1024);
            expect(() => inflater.inflate()).to.throw(RangeError);
        });

        it("inflates an empty entry with a declared size of 0", () => {
            const result = new Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0).inflate();
            expect(result).to.have.lengthOf(0);
        });

        it("inflates data matching the declared size", () => {
            const result = new Inflater(deflated, payload.length).inflate();
            expect(result.equals(payload)).to.be.true;
        });
    });

    describe("inflater async", () => {
        it("caps output when the declared size is 0", (done) => {
            new Inflater(deflated, 0).inflateAsync((result, err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(MAX_OUTPUT_EXCEEDED);
                expect(result).to.have.lengthOf(0);
                done();
            });
        });

        it("caps output when the declared size is smaller than the data", (done) => {
            new Inflater(deflated, 1).inflateAsync((result, err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(MAX_OUTPUT_EXCEEDED);
                expect(result).to.have.lengthOf(0);
                done();
            });
        });

        it("calls back only once when the cap is exceeded", (done) => {
            let calls = 0;
            new Inflater(deflated, 1).inflateAsync(() => {
                calls++;
            });
            setTimeout(() => {
                expect(calls).to.equal(1);
                done();
            }, 100);
        });

        it("inflates an empty entry with a declared size of 0", (done) => {
            new Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0).inflateAsync((result, err) => {
                expect(err).to.be.undefined;
                expect(result).to.have.lengthOf(0);
                done();
            });
        });

        it("inflates data matching the declared size", (done) => {
            new Inflater(deflated, payload.length).inflateAsync((result, err) => {
                expect(err).to.be.undefined;
                expect(result.equals(payload)).to.be.true;
                done();
            });
        });

        it("reports malformed data through the callback", (done) => {
            // BFINAL=1, BTYPE=11 (reserved) -> zlib "invalid block type"
            new Inflater(Buffer.from([0xff, 0xff, 0xff, 0xff]), 16).inflateAsync((result, err) => {
                expect(err).to.be.an("error");
                expect(result).to.have.lengthOf(0);
                done();
            });
        });
    });

    describe("zip entry with a forged uncompressed size", () => {
        it("getData() does not inflate past a declared size of 0", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is not applied before Node 15
            const entry = new Zip(bombZip(0)).getEntry("bomb.txt");
            expect(entry.header.size).to.equal(0);
            // without the cap the whole payload is inflated before the crc check fails
            expect(() => entry.getData()).to.throw(RangeError);
        });

        it("getDataAsync() does not inflate past a declared size of 0", (done) => {
            const entry = new Zip(bombZip(0)).getEntry("bomb.txt");
            expect(entry.header.size).to.equal(0);
            entry.getDataAsync((data, err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("getDataAsync() does not inflate past a small declared size", (done) => {
            const entry = new Zip(bombZip(1)).getEntry("bomb.txt");
            entry.getDataAsync((data, err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("readFileAsync() does not inflate past a declared size of 0", (done) => {
            const zip = new Zip(bombZip(0));
            zip.readFileAsync("bomb.txt", (data, err) => {
                expect(err).to.be.an("error");
                expect(err.message).to.match(MAX_OUTPUT_EXCEEDED);
                expect(data).to.have.lengthOf(0);
                done();
            });
        });

        it("still reads the entry when the declared size is correct", (done) => {
            const zip = new Zip(bombZip(payload.length));
            expect(zip.getEntry("bomb.txt").getData().equals(payload)).to.be.true;
            zip.getEntry("bomb.txt").getDataAsync((data, err) => {
                expect(err).to.be.undefined;
                expect(data.equals(payload)).to.be.true;
                done();
            });
        });
    });
});
