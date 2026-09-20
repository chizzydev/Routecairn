import { writeFileSync } from "node:fs";

/** Writes a dependency-free, scriptless PDF 1.7 proof document. The writer
 * intentionally supports text only: remote assets, active content, embedded
 * files, links, and target-controlled fonts are excluded. */
export function writePdfProofPack(path: string, markdown: string): void {
  const lines = markdown.split(/\r?\n/).flatMap((line) => wrap(normalize(line), 92));
  const pages = chunk(lines.length ? lines : ["RouteCairn proof pack"], 48);
  const objects: string[] = [];
  const add = (value: string): number => { objects.push(value); return objects.length; };
  const catalog = add(""); const pagesRoot = add(""); const font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const pageIds: number[] = [];
  for (const pageLines of pages) {
    const stream = pageStream(pageLines);
    const contentId = add(`<< /Length ${Buffer.byteLength(stream, "ascii")} >>\nstream\n${stream}\nendstream`);
    const pageId = add(`<< /Type /Page /Parent ${pagesRoot} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  }
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pagesRoot} 0 R >>`;
  objects[pagesRoot - 1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`;
  let output = "%PDF-1.7\n%RouteCairn\n"; const offsets = [0];
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(output, "ascii")); output += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(output, "ascii"); output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) output += `${String(offset).padStart(10, "0")} 00000 n \n`;
  output += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  writeFileSync(path, Buffer.from(output, "ascii"), { mode: 0o600 });
}

function pageStream(lines: string[]): string { const commands = ["BT", "/F1 10 Tf", "12 TL", "44 750 Td"]; lines.forEach((line, index) => { if (index > 0) commands.push("T*"); commands.push(`(${pdfString(line)}) Tj`); }); commands.push("ET"); return commands.join("\n"); }
function normalize(value: string): string { return value.replace(/^#{1,6}\s+/, "").replace(/`/g, "").replace(/[*~]/g, "").replace(/[^\x20-\x7E]/g, "?").trimEnd(); }
function pdfString(value: string): string { return value.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)"); }
function wrap(value: string, width: number): string[] { if (!value) return [""]; const result: string[] = []; let remaining = value; while (remaining.length > width) { let split = remaining.lastIndexOf(" ", width); if (split < Math.floor(width / 2)) split = width; result.push(remaining.slice(0, split)); remaining = remaining.slice(split).trimStart(); } result.push(remaining); return result; }
function chunk<T>(values: T[], size: number): T[][] { const result: T[][] = []; for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size)); return result; }
