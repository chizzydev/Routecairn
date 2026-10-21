/** Bind public locale metadata before interception is released. Chromium/Edge may
 * otherwise add Accept-Language later, breaking exact proxy request matching.
 * Supplied headers retain their original meaning; broker matching is unchanged. */
export function bindBrowserLanguage(headers: Record<string, string>): Record<string, string> {
  return Object.keys(headers).some((name) => name.toLowerCase() === "accept-language")
    ? headers
    : { ...headers, "accept-language": "en-US" };
}
