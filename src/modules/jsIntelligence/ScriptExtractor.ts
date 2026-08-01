import * as cheerio from "cheerio";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";

export class ScriptExtractor {
  public extract(html: string, baseUrl: string): string[] {
    const $ = cheerio.load(html);
    const scripts = new Set<string>();

    $("script[src]").each((_index, element) => {
      const src = $(element).attr("src")?.trim();

      if (!src || src.startsWith("data:") || src.startsWith("javascript:")) {
        return;
      }

      try {
        scripts.add(normalizeUrl(src, baseUrl));
      } catch {
        // Ignore malformed script URLs; the report should stay focused on actionable evidence.
      }
    });

    return [...scripts];
  }
}
