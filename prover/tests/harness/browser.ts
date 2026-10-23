// Shared helpers of the headless-Chromium tests: the browser, and the request recorder.
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright-core';

export const launch = (): Promise<Browser> =>
  chromium.launch({ executablePath: process.env.CHROMIUM ?? '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });

export type Contact = { origin: string; url: string; kind: string; method: string; body: boolean };

// Records every request of every page of the context, workers and web sockets included (the
// pattern of the member page's network spec), as origin + url, with the method and whether a
// body went with it.
export function record(context: BrowserContext): Contact[] {
  const contacts: Contact[] = [];
  const origin = (url: string) => {
    const parsed = new URL(url);
    if (['data:', 'blob:', 'about:'].includes(parsed.protocol)) return null;
    return `${parsed.protocol.replace('ws', 'http')}//${parsed.host}`;
  };
  context.on('request', (request) => {
    const o = origin(request.url());
    if (o !== null) contacts.push({ origin: o, url: request.url(), kind: request.resourceType(), method: request.method(), body: request.postDataBuffer() !== null });
  });
  const sockets = (page: Page) =>
    page.on('websocket', (socket) => {
      const o = origin(socket.url());
      if (o !== null) contacts.push({ origin: o, url: socket.url(), kind: 'websocket', method: 'GET', body: false });
    });
  context.pages().forEach(sockets);
  context.on('page', sockets);
  return contacts;
}
