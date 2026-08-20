import { deflateSync } from "node:zlib";

const width = 960;
const height = 540;
const channels = 3;

type Rgb = readonly [red: number, green: number, blue: number];

export function createSyntheticDashboardScreenshot(): Buffer {
  const stride = width * channels + 1;
  const pixels = Buffer.alloc(stride * height);
  fill(pixels, [244, 247, 250]);

  rectangle(pixels, 0, 0, width, 72, [14, 28, 42]);
  rectangle(pixels, 0, 72, 210, height - 72, [26, 47, 65]);
  rectangle(pixels, 242, 104, 686, 70, [255, 255, 255]);
  rectangle(pixels, 242, 198, 210, 132, [255, 255, 255]);
  rectangle(pixels, 476, 198, 210, 132, [255, 255, 255]);
  rectangle(pixels, 710, 198, 218, 132, [255, 255, 255]);
  rectangle(pixels, 242, 354, 686, 150, [255, 255, 255]);

  rectangle(pixels, 28, 24, 142, 18, [240, 248, 255]);
  for (let index = 0; index < 5; index += 1) {
    rectangle(pixels, 28, 110 + index * 52, 146, 13, index === 1 ? [103, 187, 255] : [187, 205, 219]);
  }
  rectangle(pixels, 266, 126, 254, 13, [37, 72, 101]);
  rectangle(pixels, 266, 148, 390, 8, [169, 185, 198]);

  metric(pixels, 266, 220, [28, 105, 164]);
  metric(pixels, 500, 220, [35, 128, 89]);
  metric(pixels, 734, 220, [185, 91, 45]);

  const bars: ReadonlyArray<readonly [number, number, Rgb]> = [
    [278, 78, [28, 105, 164]],
    [336, 112, [35, 128, 89]],
    [394, 62, [185, 91, 45]],
    [452, 104, [28, 105, 164]],
    [510, 86, [35, 128, 89]],
    [568, 122, [185, 91, 45]],
    [626, 96, [28, 105, 164]]
  ];
  for (const [x, barHeight, color] of bars) rectangle(pixels, x, 478 - barHeight, 32, barHeight, color);
  rectangle(pixels, 266, 478, 428, 2, [143, 159, 173]);
  rectangle(pixels, 730, 382, 164, 10, [37, 72, 101]);
  rectangle(pixels, 730, 407, 132, 8, [169, 185, 198]);
  rectangle(pixels, 730, 430, 148, 8, [169, 185, 198]);
  rectangle(pixels, 730, 453, 116, 8, [169, 185, 198]);

  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 2;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", header),
    pngChunk("IDAT", deflateSync(pixels, { level: 9 })),
    pngChunk("IEND", Buffer.alloc(0))
  ]);
}

export const syntheticScreenshotDimensions = Object.freeze({ width, height });

function fill(buffer: Buffer, color: Rgb): void {
  for (let y = 0; y < height; y += 1) {
    const row = y * (width * channels + 1);
    buffer[row] = 0;
    for (let x = 0; x < width; x += 1) setPixel(buffer, x, y, color);
  }
}

function metric(buffer: Buffer, x: number, y: number, color: Rgb): void {
  rectangle(buffer, x, y, 72, 38, color);
  rectangle(buffer, x, y + 56, 142, 9, [169, 185, 198]);
  rectangle(buffer, x, y + 75, 104, 7, [205, 215, 223]);
}

function rectangle(buffer: Buffer, x: number, y: number, rectangleWidth: number, rectangleHeight: number, color: Rgb): void {
  for (let row = y; row < Math.min(height, y + rectangleHeight); row += 1) {
    for (let column = x; column < Math.min(width, x + rectangleWidth); column += 1) setPixel(buffer, column, row, color);
  }
}

function setPixel(buffer: Buffer, x: number, y: number, color: Rgb): void {
  const offset = y * (width * channels + 1) + 1 + x * channels;
  buffer[offset] = color[0];
  buffer[offset + 1] = color[1];
  buffer[offset + 2] = color[2];
}

function pngChunk(type: string, data: Buffer): Buffer {
  const typeBuffer = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  typeBuffer.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 8 + data.length);
  return chunk;
}

function crc32(buffer: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
