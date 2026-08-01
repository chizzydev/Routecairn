import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";

const sourceMapPattern = /\/\/[#@]\s*sourceMappingURL=([^\s]+)/g;

export class SourceMapDetector {
  public detect(jsSource: string, scriptUrl: string): string[] {
    const sourceMaps = new Set<string>();

    if (scriptUrl.endsWith(".js")) {
      sourceMaps.add(`${scriptUrl}.map`);
    }

    for (const match of jsSource.matchAll(sourceMapPattern)) {
      const raw = match[1]?.trim();

      if (!raw || raw.startsWith("data:")) {
        continue;
      }

      try {
        sourceMaps.add(normalizeUrl(raw, scriptUrl));
      } catch {
        // Ignore malformed source map references.
      }
    }

    return [...sourceMaps];
  }
}
