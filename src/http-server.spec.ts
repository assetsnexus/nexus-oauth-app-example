import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { describe, expect, it } from 'vitest';
import type { PartnerConfig } from './config.js';
import { createPartnerApp, partnerSessionCookie, type PartnerApp } from './http-server.js';

const config: PartnerConfig = {
  issuer: 'https://region.example',
  portalOrigin: 'https://portal.example',
  clientId: 'client-1',
  redirectUri: 'http://127.0.0.1:8787/callback',
  webhookSecret: 'whsec',
  port: 0,
};

function cookieValue(setCookie: string): string {
  const match = /nx_partner=([^;]+)/.exec(setCookie);
  return match ? decodeURIComponent(match[1]) : '';
}

async function call(
  app: PartnerApp,
  init: { method: string; url: string; host?: string; cookie?: string; body?: string },
): Promise<{ status: number; headers: Record<string, string | number | readonly string[]>; body: string }> {
  const req = new EventEmitter() as IncomingMessage;
  req.method = init.method;
  req.url = init.url;
  req.headers = {
    host: init.host || '127.0.0.1:8787',
    ...(init.cookie ? { cookie: init.cookie } : {}),
  };
  let status = 0;
  let headers: Record<string, string | number | readonly string[]> = {};
  let body = '';
  const res = new EventEmitter() as ServerResponse;
  res.writeHead = ((code: number, next?: Record<string, string | number | readonly string[]>) => {
    status = code;
    headers = next || {};
    return res;
  }) as ServerResponse['writeHead'];
  res.end = ((chunk?: string | Buffer) => {
    if (chunk) body += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    return res;
  }) as ServerResponse['end'];

  const pending = app.handle(req, res);
  if (init.body !== undefined) req.emit('data', Buffer.from(init.body));
  req.emit('end');
  await pending;
  return { status, headers, body };
}

describe('partnerSessionCookie', () => {
  it('stays usable on localhost and is Secure elsewhere', () => {
    expect(partnerSessionCookie('abc', 'localhost:8787')).not.toContain('Secure');
    expect(partnerSessionCookie('abc', '127.0.0.1')).not.toContain('Secure');
    expect(partnerSessionCookie('abc', '[::1]:8787')).not.toContain('Secure');
    expect(partnerSessionCookie('abc', 'partner.example')).toContain('Secure');
    expect(partnerSessionCookie('abc', undefined)).toContain('Secure');
  });
});

describe('login session cookie', () => {
  it('mints a server session id and ignores the client cookie', async () => {
    const app = createPartnerApp(config);
    const res = await call(app, {
      method: 'GET',
      url: '/api/login?subjectType=user',
      host: '127.0.0.1:8787',
      cookie: 'nx_partner=client-supplied',
    });
    expect(res.status).toBe(302);
    const setCookie = String(res.headers['Set-Cookie'] || '');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).not.toContain('Secure');
    const id = cookieValue(setCookie);
    expect(id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(id).not.toBe('client-supplied');
    expect(app.state.session('client-supplied')).toBeUndefined();
    expect(app.state.session(id)?.intent?.subjectType).toBe('user');
  });

  it('mints a new session on identity switch', async () => {
    const app = createPartnerApp(config);
    const login = await call(app, {
      method: 'GET',
      url: '/api/login?subjectType=user',
      host: 'partner.example',
    });
    const first = cookieValue(String(login.headers['Set-Cookie'] || ''));
    expect(String(login.headers['Set-Cookie'])).toContain('Secure');

    const switched = await call(app, {
      method: 'POST',
      url: '/api/identities/switch',
      host: 'partner.example',
      cookie: `nx_partner=${first}`,
      body: JSON.stringify({ subjectType: 'org_member', orgId: 'org-1' }),
    });
    expect(switched.status).toBe(200);
    const next = cookieValue(String(switched.headers['Set-Cookie'] || ''));
    expect(next).not.toBe(first);
    expect(String(switched.headers['Set-Cookie'])).toContain('Secure');
    expect(JSON.parse(switched.body).authorizeUrl).toContain('subject_type=org_member');
    expect(app.state.session(next)?.intent?.orgId).toBe('org-1');
    expect(app.state.session(first)?.intent?.subjectType).toBe('user');
  });
});
