import { openSync, closeSync, readSync, statSync } from "node:fs";

const maximumHeaderBytes = 1024 * 1024;
export const maximumPreviewDimension = 16_384;
export const maximumPreviewPixels = 100_000_000;

export interface SafeImageDimensions { width: number; height: number; contentType: "image/png" | "image/jpeg" | "image/gif" | "image/webp"; }

export function inspectImageDimensions(path: string, declaredContentType: string): SafeImageDimensions {
  const size = statSync(path).size;
  const buffer = Buffer.alloc(Math.min(size, maximumHeaderBytes));
  const descriptor = openSync(path, "r");
  try { readSync(descriptor, buffer, 0, buffer.length, 0); } finally { closeSync(descriptor); }
  const result = parseImage(buffer);
  if (!result) throw new Error("Image format or dimensions could not be validated.");
  if (result.contentType !== declaredContentType) throw new Error("Image content does not match its declared MIME type.");
  if (result.width < 1 || result.height < 1 || result.width > maximumPreviewDimension || result.height > maximumPreviewDimension || result.width * result.height > maximumPreviewPixels) {
    throw new Error("Image pixel dimensions exceed the preview safety limit.");
  }
  return result;
}

function parseImage(buffer: Buffer): SafeImageDimensions | undefined {
  if (buffer.length >= 24 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) && buffer.toString("ascii", 12, 16) === "IHDR") {
    return { contentType: "image/png", width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
  }
  if (buffer.length >= 10 && (buffer.toString("ascii", 0, 6) === "GIF87a" || buffer.toString("ascii", 0, 6) === "GIF89a")) {
    return { contentType: "image/gif", width: buffer.readUInt16LE(6), height: buffer.readUInt16LE(8) };
  }
  if (buffer.length >= 12 && buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP") return parseWebp(buffer);
  if (buffer.length >= 4 && buffer[0] === 0xff && buffer[1] === 0xd8) return parseJpeg(buffer);
  return undefined;
}

function parseJpeg(buffer: Buffer): SafeImageDimensions | undefined {
  let offset = 2;
  while (offset + 9 < buffer.length) {
    if (buffer[offset] !== 0xff) { offset += 1; continue; }
    const marker = buffer[offset + 1]!;
    offset += 2;
    if (marker === 0xd8 || marker === 0xd9 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > buffer.length) return undefined;
    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) return undefined;
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      return { contentType: "image/jpeg", height: buffer.readUInt16BE(offset + 3), width: buffer.readUInt16BE(offset + 5) };
    }
    offset += length;
  }
  return undefined;
}

function parseWebp(buffer: Buffer): SafeImageDimensions | undefined {
  if (buffer.length < 30) return undefined;
  const chunk = buffer.toString("ascii", 12, 16);
  if (chunk === "VP8X") return { contentType: "image/webp", width: 1 + buffer.readUIntLE(24, 3), height: 1 + buffer.readUIntLE(27, 3) };
  if (chunk === "VP8 " && buffer[23] === 0x9d && buffer[24] === 0x01 && buffer[25] === 0x2a) {
    return { contentType: "image/webp", width: buffer.readUInt16LE(26) & 0x3fff, height: buffer.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === "VP8L" && buffer[20] === 0x2f && buffer.length >= 25) {
    const bits = buffer.readUInt32LE(21);
    return { contentType: "image/webp", width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
  }
  return undefined;
}
