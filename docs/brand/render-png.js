// PNG fallbacks for the VisCon1 logos. Run after build.py: node docs/brand/render-png.js
const path = require("path");
const fs = require("fs");
const { chromium } = require("playwright");
const OUT = path.join(__dirname, "..", "..", "linkwatch", "server", "static", "brand");

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  for (const family of ["light", "dark", "green"]) {
    const clear = fs.readFileSync(path.join(OUT, `viscon1-${family}-static.svg`), "utf8");
    const apple = path.join(OUT, `.apple-${family}.svg`);
    const opaque = fs.readFileSync(apple, "utf8");
    const jobs = [[clear, 32, `favicon-${family}-32.png`, true], [clear, 192, `icon-${family}-192.png`, true],
                  [clear, 512, `icon-${family}-512.png`, true], [opaque, 180, `apple-touch-icon-${family}.png`, false]];
    for (const [svg, size, name, clearBg] of jobs) {
      await page.setViewportSize({ width: size, height: size });
      const body = svg.replace(/^<\?xml[^>]*>\s*/, "").replace('width="512" height="512"', `width="${size}" height="${size}"`);
      await page.setContent(`<html><body style="margin:0;background:transparent">${body}</body></html>`);
      await page.screenshot({ path: path.join(OUT, name), omitBackground: clearBg, clip: { x: 0, y: 0, width: size, height: size } });
    }
    fs.unlinkSync(apple);
  }
  await browser.close();
  console.log("PNGs written to", OUT);
})();
