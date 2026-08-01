import type { DetectedTechnology, TechnologyCategory } from "../../reports/ReportTypes.js";

export interface FingerprintRule {
  name: string;
  category: TechnologyCategory;
  confidence: DetectedTechnology["confidence"];
  match: (input: FingerprintInput) => string[];
}

export interface FingerprintInput {
  headersText: string;
  cookiesText: string;
  bodyText: string;
  urlText: string;
}

export const fingerprintRules: FingerprintRule[] = [
  marker("Next.js", "framework", "High", ["/_next/static", "__next_data__", "next-router-state-tree", "x-nextjs"]),
  marker("React SPA", "framework", "Medium", ["id=\"root\"", "id=\"__next\"", "react-refresh", "react-dom"]),
  marker("Vite", "framework", "High", ["/@vite/client", "vite.svg", "type=\"module\" crossorigin"]),
  marker("Laravel", "framework", "High", ["laravel_session", "x-powered-by: php", "/vendor/laravel", "csrf-token"]),
  marker("WordPress", "cms", "High", ["/wp-content/", "/wp-includes/", "wp-json", "wordpress"]),
  marker("Shopify", "commerce", "High", ["x-shopify", "shopify", "/cart.js", "cdn.shopify.com"]),
  marker("Express/Node", "server", "Medium", ["x-powered-by: express", "connect.sid"]),
  marker("Nginx", "server", "Medium", ["server: nginx"]),
  marker("Apache", "server", "Medium", ["server: apache"]),
  marker("Vercel", "platform", "High", ["server: vercel", "x-vercel", ".vercel.app", "__vc"]),
  marker("Netlify", "platform", "High", ["server: netlify", "x-nf-request-id", ".netlify.app"]),
  marker("Cloudflare", "cdn", "High", ["server: cloudflare", "cf-ray", "__cf_bm", "cf-cache-status"]),
  marker("Firebase", "platform", "High", ["firebaseio.com", "firebasestorage.googleapis.com", "firebaseapp.com"]),
  marker("Supabase", "database", "High", ["supabase.co", "supabase.in", "supabaseUrl"]),
  marker("S3/CloudFront", "storage", "High", ["s3.amazonaws.com", "amazonaws.com", "cloudfront.net", "x-amz-"])
];

function marker(
  name: string,
  category: TechnologyCategory,
  confidence: DetectedTechnology["confidence"],
  markers: string[]
): FingerprintRule {
  return {
    name,
    category,
    confidence,
    match(input: FingerprintInput): string[] {
      const haystack = `${input.headersText}\n${input.cookiesText}\n${input.bodyText}\n${input.urlText}`.toLowerCase();
      return markers.filter((markerValue) => haystack.includes(markerValue.toLowerCase()));
    }
  };
}
