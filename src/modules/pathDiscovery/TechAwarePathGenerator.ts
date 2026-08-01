import type { DetectedTechnology } from "../../reports/ReportTypes.js";
import type { WordlistEntry } from "./WordlistLoader.js";

const pathsByTechnology: Record<string, string[]> = {
  "Next.js": ["/_next/static/", "/_next/data/", "/api/", "/api/auth/session", "/api/auth/csrf", "/sitemap.xml", "/robots.txt"],
  Laravel: ["/.env", "/storage/", "/vendor/", "/telescope", "/horizon", "/_debugbar", "/server-status"],
  WordPress: ["/wp-admin/", "/wp-login.php", "/wp-json/", "/xmlrpc.php", "/wp-content/", "/wp-content/debug.log"],
  Shopify: ["/admin", "/cart.js", "/products.json", "/collections.json", "/sitemap.xml"],
  "React SPA": ["/static/js/", "/assets/", "/manifest.json"],
  Vite: ["/assets/", "/src/", "/@vite/client"],
  Firebase: ["/__/firebase/init.json"],
  Supabase: ["/rest/v1/", "/auth/v1/"],
  "S3/CloudFront": ["/index.html", "/robots.txt", "/sitemap.xml"],
  Vercel: ["/_next/static/", "/api/", "/.well-known/vercel"],
  Netlify: ["/.netlify/functions/", "/_redirects", "/_headers"]
};

export class TechAwarePathGenerator {
  public generate(technologies: DetectedTechnology[]): WordlistEntry[] {
    return technologies.flatMap((technology) => {
      const paths = pathsByTechnology[technology.name] ?? [];

      return paths.map((path) => ({
        path,
        source: `tech:${technology.name}`
      }));
    });
  }
}
