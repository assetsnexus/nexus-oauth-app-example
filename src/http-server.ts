import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JwksCache, type PermissionBatchItem } from '@nexus/commands-client';
import { createIdempotencyStore } from '@nexus/webhooks';
import type { PartnerConfig } from './config.js';
import { mapPartnerError, PartnerService } from './partner-service.js';
import { createPartnerLogger, PartnerState } from './state.js';
import { partnerWebhookHandlers, receiveNexusWebhook } from './webhook-receiver.js';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
const COOKIE = 'nx_partner';

export type PartnerApp = {
  state: PartnerState;
  service: PartnerService;
  handle: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
};

function readBody(req: IncomingMessage, limit = 1_000_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('body_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sessionId(req: IncomingMessage): string {
  const raw = req.headers.cookie || '';
  const match = raw.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE}=`));
  return match ? decodeURIComponent(match.slice(COOKIE.length + 1)) : '';
}

function isLocalDevHost(hostHeader: string | undefined): boolean {
  const host = (hostHeader || '').trim().toLowerCase();
  const hostname = host.startsWith('[')
    ? host.slice(1, host.indexOf(']') === -1 ? undefined : host.indexOf(']'))
    : host.replace(/:\d+$/, '');
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

export function partnerSessionCookie(sessionIdValue: string, hostHeader: string | undefined): string {
  const parts = [
    `${COOKIE}=${encodeURIComponent(sessionIdValue)}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
  ];
  if (!isLocalDevHost(hostHeader)) parts.push('Secure');
  return parts.join('; ');
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

export function createPartnerApp(config: PartnerConfig): PartnerApp {
  const state = new PartnerState();
  const logger = createPartnerLogger();
  // In-process for the demo. A real partner keeps processed eventIds in its database.
  const store = createIdempotencyStore();
  const service = new PartnerService({
    issuer: config.issuer,
    portalOrigin: config.portalOrigin,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    jwks: new JwksCache(config.issuer),
    state,
    logger,
  });
  const handlers = partnerWebhookHandlers(state, logger);

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    try {
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const html = await readFile(path.join(publicDir, 'index.html'));
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/app.js') {
        const js = await readFile(path.join(publicDir, 'app.js'));
        res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' });
        res.end(js);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/webhooks/nexus') {
        const rawBody = await readBody(req);
        const result = await receiveNexusWebhook({
          rawBody,
          headers: req.headers,
          secret: config.webhookSecret,
          handlers,
          idempotency: store,
        });
        sendJson(res, result.status, result.body);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/login') {
        const subjectType = url.searchParams.get('subjectType') === 'org_member' ? 'org_member' : 'user';
        const started = await service.startLogin({
          subjectType,
          orgId: url.searchParams.get('orgId') || undefined,
        });
        res.writeHead(302, {
          Location: started.authorizeUrl,
          'Set-Cookie': partnerSessionCookie(started.sessionId, req.headers.host),
        });
        res.end();
        return;
      }
      if (req.method === 'GET' && url.pathname === '/callback') {
        const sid = sessionId(req);
        await service.completeLogin({
          sessionId: sid,
          code: url.searchParams.get('code') || '',
          state: url.searchParams.get('state') || '',
        });
        res.writeHead(302, { Location: '/' });
        res.end();
        return;
      }
      const sid = sessionId(req);
      if (req.method === 'GET' && url.pathname === '/api/identities') {
        sendJson(res, 200, await service.identities(sid));
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/identities/switch') {
        const body = JSON.parse((await readBody(req)) || '{}') as { subjectType?: 'user' | 'org_member'; orgId?: string };
        const started = await service.startLogin({
          subjectType: body.subjectType || 'org_member',
          orgId: body.orgId,
        });
        sendJson(res, 200, { authorizeUrl: started.authorizeUrl }, {
          'Set-Cookie': partnerSessionCookie(started.sessionId, req.headers.host),
        });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/status') {
        sendJson(res, 200, await service.status(sid));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/fields') {
        sendJson(res, 200, await service.fields(sid));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/subscription') {
        sendJson(res, 200, await service.subscription(sid));
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/fields') {
        const body = JSON.parse((await readBody(req)) || '{}') as { fields?: Array<{ field: string; purpose?: string }> };
        sendJson(res, 200, await service.requestFields(sid, body.fields || []));
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/permissions/batch') {
        const body = JSON.parse((await readBody(req)) || '{}') as { items?: PermissionBatchItem[] };
        sendJson(res, 200, await service.requestBatch(sid, body.items || []));
        return;
      }
      sendJson(res, 404, { error: 'NOT_FOUND' });
    } catch (err) {
      const mapped = mapPartnerError(err, config.portalOrigin);
      logger.warn('request_failed', {
        path: url.pathname,
        error: String(mapped.body.error || ''),
        ...(typeof mapped.body.message === 'string' ? { message: mapped.body.message } : {}),
      });
      sendJson(res, mapped.status, mapped.body);
    }
  }

  return { state, service, handle };
}

export function listen(config: PartnerConfig) {
  const app = createPartnerApp(config);
  const server = createServer((req, res) => {
    void app.handle(req, res);
  });
  return new Promise<ReturnType<typeof createServer>>((resolve) => {
    server.listen(config.port, () => resolve(server));
  });
}
