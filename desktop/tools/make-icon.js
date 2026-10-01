"use strict";

// Generates desktop/build/icon.png (256x256) with no external dependencies.
// The icon is a dark engineering palette with a cyan sentinel diamond.
// Run: node tools/make-icon.js   (from the desktop/ directory)

const fs = require("node:fs");
const path = require("node:path");

const SIZE = 256;

// Minimal DEFLATE "stored" blocks + zlib wrapper.
function crc32(bytes) {
  let c;
  const table = [];
  for (let n = 0; n < 256; n += 1) {
    c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function adler32(bytes) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    a = (a + bytes[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeBuffer = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0);
  return Buffer.concat([length, typeBuffer, data, crc]);
}

function zlibStore(raw) {
  const blocks = [];
  const max = 65535;
  for (let offset = 0; offset < raw.length; offset += max) {
    const slice = raw.subarray(offset, Math.min(offset + max, raw.length));
    const header = Buffer.alloc(5);
    header[0] = offset + max >= raw.length ? 1 : 0;
    header.writeUInt16LE(slice.length, 1);
    header.writeUInt16LE(slice.length ^ 0xffff, 3);
    blocks.push(header, slice);
  }
  if (raw.length === 0) {
    const header = Buffer.alloc(5);
    header[0] = 1;
    blocks.push(header);
  }
  const adler = Buffer.alloc(4);
  adler.writeUInt32BE(adler32(raw), 0);
  return Buffer.concat([Buffer.from([0x78, 0x01]), ...blocks, adler]);
}

function pixel(x, y) {
  // Background: deep navy. Frame: cyan border. Center: sentinel diamond.
  const frame = 10;
  const inner = SIZE - 2 * frame;
  const cx = SIZE / 2;
  const cy = SIZE / 2;
  const inFrame = x >= frame && y >= frame && x < frame + inner && y < frame + inner;
  const dx = Math.abs(x - cx);
  const dy = Math.abs(y - cy);
  const inDiamond = dx + dy <= 84;
  const inCore = dx + dy <= 52;
  if (inCore) return [13, 148, 173, 255];
  if (inDiamond) return [34, 211, 238, 255];
  if (inFrame) return [16, 30, 46, 255];
  return [11, 15, 20, 255];
}

function makeIcon() {
  const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
  let offset = 0;
  for (let y = 0; y < SIZE; y += 1) {
    raw[offset] = 0;
    offset += 1;
    for (let x = 0; x < SIZE; x += 1) {
      const [r, g, b, a] = pixel(x, y);
      raw[offset] = r;
      raw[offset + 1] = g;
      raw[offset + 2] = b;
      raw[offset + 3] = a;
      offset += 4;
    }
  }
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(SIZE, 0);
  ihdr.writeUInt32BE(SIZE, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const idat = zlibStore(raw);
  const png = Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
  const outDir = path.resolve(__dirname, "..", "build");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "icon.png");
  fs.writeFileSync(outPath, png);
  process.stdout.write(`wrote ${outPath} (${png.length} bytes)\n`);
}

makeIcon();
