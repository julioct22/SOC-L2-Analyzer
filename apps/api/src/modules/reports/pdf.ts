import fs from 'node:fs';
import puppeteer, { type Browser } from 'puppeteer-core';
import { env } from '../../config/env.js';

const CANDIDATES = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable'];

function chromiumPath(): string {
  const found = [env.CHROMIUM_PATH, ...CANDIDATES].find((p) => p && fs.existsSync(p));
  if (!found) throw new Error('No se encontró Chromium. Defina CHROMIUM_PATH o use la imagen Docker de la API.');
  return found;
}

let browserPromise: Promise<Browser> | null = null;

/** Una sola instancia de Chromium reutilizada entre informes */
async function getBrowser(): Promise<Browser> {
  if (browserPromise) {
    const b = await browserPromise.catch(() => null);
    if (b?.connected) return b;
  }
  browserPromise = puppeteer.launch({
    executablePath: chromiumPath(),
    headless: true,
    // --no-sandbox es necesario dentro de contenedores sin privilegios; el HTML es generado por el propio sistema
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--font-render-hinting=none'],
  });
  return browserPromise;
}

export async function htmlToPdf(html: string, footerLabel: string): Promise<Buffer> {
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    // Sin acceso a red: el informe es autocontenido
    await page.setRequestInterception(true);
    page.on('request', (r) => (r.url().startsWith('data:') || r.url() === 'about:blank' ? r.continue() : r.abort()));
    await page.setContent(html, { waitUntil: 'load' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      // Marcadores (panel lateral del lector PDF) generados a partir de los títulos h2/h3
      outline: true,
      tagged: true,
      displayHeaderFooter: true,
      headerTemplate: '<div></div>',
      footerTemplate: `<div style="font-size:7px;width:100%;padding:0 14mm;color:#64748b;display:flex;justify-content:space-between;font-family:Arial,sans-serif">
        <span>${footerLabel.replace(/[<>&]/g, '')} · CONFIDENCIAL</span><span>Página <span class="pageNumber"></span> de <span class="totalPages"></span></span></div>`,
      margin: { top: '14mm', bottom: '16mm', left: '14mm', right: '14mm' },
    });
    return Buffer.from(pdf);
  } finally {
    await page.close();
  }
}

export async function closeBrowser(): Promise<void> {
  const b = await browserPromise?.catch(() => null);
  await b?.close();
}
