import * as cheerio from "cheerio";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";

export class ScriptExtractor {
  public extract(html: string, baseUrl: string): string[] {
    const $ = cheerio.load(html);
    const scripts = new Set<string>();

    $("script[src]").each((_index, element) => {
      const src = $(element).attr("src")?.trim();

      if (!src) {
        return;
      }

      try {
        const normalized = normalizeUrl(src, baseUrl);
        if (["http:", "https:"].includes(new URL(normalized).protocol)) scripts.add(normalized);
      } catch {
        // Ignore malformed script URLs; the report should stay focused on actionable evidence.
      }
    });

    return [...scripts];
  }
}
