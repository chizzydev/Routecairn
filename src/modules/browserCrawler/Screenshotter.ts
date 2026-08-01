import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { Page } from "playwright";

export class Screenshotter {
  public async capture(page: Page, outputDir: string, name = "homepage.png"): Promise<string> {
    const screenshotDir = join(outputDir, "screenshots");
    await mkdir(screenshotDir, { recursive: true });
    const screenshotPath = join(screenshotDir, name);
    await page.screenshot({ path: screenshotPath, fullPage: true });
    return screenshotPath;
  }
}
